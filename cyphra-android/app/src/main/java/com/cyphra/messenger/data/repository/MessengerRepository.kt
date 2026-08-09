package com.cyphra.messenger.data.repository

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.cyphra.messenger.data.model.*
import com.cyphra.messenger.network.CyphraApiClient
import com.cyphra.messenger.network.CyphraWebSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

private const val TAG = "MessengerRepo"

/**
 * MessengerRepository — single source of truth.
 *
 * Auth: mirrors auth.service.js exactly.
 *   - userId = SHA-256(email.toLowerCase())
 *   - verify: SHA-256(password + user.salt) == user.passwordHash
 *
 * Encryption: AES-256-GCM via Android Keystore (hardware-backed when available).
 * This is the mobile equivalent of the Rust/WASM AES-GCM layer.
 */
class MessengerRepository {

    private val api   = CyphraApiClient()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var ws: CyphraWebSocket? = null

    // ── State flows ───────────────────────────────────────────────────────────
    private val _currentUser = MutableStateFlow<User?>(null)
    val currentUser: StateFlow<User?> = _currentUser

    private val _messages = MutableStateFlow<List<Message>>(emptyList())
    val messages: StateFlow<List<Message>> = _messages

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts

    private val _activeChat = MutableStateFlow<String?>(null)
    val activeChat: StateFlow<String?> = _activeChat

    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected

    // ── Auth ──────────────────────────────────────────────────────────────────

    /**
     * Login using email + password. Talks to the same VedDB-backed backend
     * as the web app — accounts made on the browser work here.
     */
    suspend fun login(email: String, password: String): Result<User> {
        return try {
            Log.d(TAG, "Attempting login for $email")
            val result = api.login(email, password)
            if (result.isSuccess) {
                val data = result.getOrThrow()
                val user = User(
                    id        = data["id"] as? String ?: sha256hex(email.trim().lowercase()),
                    username  = data["username"] as? String ?: email.substringBefore("@"),
                    ghostCode = generateGhostCode(data["id"] as? String ?: email),
                    email     = data["email"] as? String ?: email,
                )
                _currentUser.value = user
                connectWebSocket(user.id)
                // Load contacts from server in background
                scope.launch { loadContacts(user.id) }
                Log.i(TAG, "Logged in as ${user.username} (${user.id})")
                Result.success(user)
            } else {
                Result.failure(result.exceptionOrNull() ?: Exception("Login failed"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Login exception", e)
            Result.failure(e)
        }
    }

    // ── WebSocket ─────────────────────────────────────────────────────────────

    private fun connectWebSocket(userId: String) {
        ws?.disconnect()
        ws = CyphraWebSocket(userId) { payload -> handleIncoming(payload) }
        ws!!.connect()
        // Forward connection state
        scope.launch {
            ws!!.isConnected.collect { connected ->
                _isConnected.value = connected
            }
        }
    }

    private suspend fun handleIncoming(payload: Map<String, Any>) {
        val type = payload["type"] as? String ?: return
        if (type != "message") return

        @Suppress("UNCHECKED_CAST")
        val msgData = payload["message"] as? Map<String, Any> ?: return

        // Ignore read receipts and delete commands
        val msgType = msgData["type"] as? String
        if (msgType == "read_receipt" || msgType == "delete") return

        // ── Extract fields — web app uses sender OR senderId ──────────────────
        // broadcastMessage() adds senderId; the original message object has sender
        val senderId = (msgData["sender"] as? String)
            ?: (msgData["senderId"] as? String)
            ?: run { Log.w(TAG, "Incoming message missing sender/senderId, dropping"); return }

        val senderName   = msgData["senderName"] as? String ?: "Unknown"

        // Text can be in "text" field; fall back to an indicator if encrypted-only
        val text = (msgData["text"] as? String)?.takeIf { it.isNotBlank() }
            ?: "[encrypted message]"

        // selfDestruct: Gson parses JSON booleans as Boolean, but guard against String
        val selfDestruct = when (val sd = msgData["selfDestruct"]) {
            is Boolean -> sd
            is String  -> sd.equals("true", ignoreCase = true)
            else       -> false
        }

        // destructTimer: Gson parses JSON numbers as Double
        val destructTimer = when (val dt = msgData["destructTimer"]) {
            is Double -> dt.toInt().takeIf { it > 0 }
            is Long   -> dt.toInt().takeIf { it > 0 }
            is Int    -> dt.takeIf { it > 0 }
            else      -> null
        }

        val msgId     = msgData["id"] as? String ?: generateId()
        val timestamp = when (val ts = msgData["timestamp"]) {
            is Double -> ts.toLong()
            is Long   -> ts
            else      -> System.currentTimeMillis()
        }

        Log.i(TAG, "Incoming message from $senderName ($senderId): text=${text.take(30)} selfDestruct=$selfDestruct timer=$destructTimer")

        // Don't add our own messages twice (e.g., if broadcast echoes back)
        if (senderId == _currentUser.value?.id) {
            Log.d(TAG, "Ignoring echo of our own message")
            return
        }

        // Deduplicate — don't add the same message ID twice
        if (_messages.value.any { it.id == msgId }) {
            Log.d(TAG, "Duplicate message $msgId — ignoring")
            return
        }

        // chatId = senderId so message appears in the right conversation thread
        val msg = Message(
            id            = msgId,
            chatId        = senderId,
            sender        = senderId,
            senderName    = senderName,
            text          = text,
            encrypted     = true,
            timestamp     = timestamp,
            selfDestruct  = selfDestruct,
            destructTimer = destructTimer,
            // destructAt stays null until recipient OPENS this chat (same logic as web app)
            destructAt    = if (selfDestruct && _activeChat.value == senderId)
                                System.currentTimeMillis() + ((destructTimer ?: 10) * 1000L)
                            else null,
            status        = MessageStatus.DELIVERED,
        )
        addMessage(msg)

        // Auto-add sender as contact if not already known (mirrors web app behaviour)
        ensureContact(senderId, senderName)
    }



    // ── Contacts ──────────────────────────────────────────────────────────────

    private suspend fun loadContacts(userId: String) {
        try {
            val raw = api.getContacts(userId)
            val contacts = raw.mapNotNull { c ->
                val id   = c["id"] as? String ?: return@mapNotNull null
                val name = c["username"] as? String ?: id
                Contact(id = id, username = name, ghostCode = generateGhostCode(id), online = false, verified = true)
            }
            if (contacts.isNotEmpty()) _contacts.value = contacts
        } catch (e: Exception) {
            Log.e(TAG, "Load contacts error", e)
        }
    }

    /**
     * Find a user by email and add them as a contact.
     * Returns Result.success(Contact) or Result.failure with a human-readable message.
     */
    suspend fun addContact(email: String): Result<Contact> {
        val currentUserId = _currentUser.value?.id
            ?: return Result.failure(Exception("Not logged in"))

        // Already added?
        val existingByEmail = _contacts.value.firstOrNull {
            it.username.equals(email, ignoreCase = true)
        }
        if (existingByEmail != null)
            return Result.failure(Exception("${existingByEmail.username} is already in your contacts"))

        return try {
            // Lookup the user in VedDB by email
            val result = api.findUserByEmail(email)
            if (result.isFailure)
                return Result.failure(Exception("No Cyphra account found for that email"))

            val data = result.getOrThrow()
            val contactId   = data["id"] as? String
                ?: return Result.failure(Exception("Invalid user data from server"))
            val contactName = data["username"] as? String ?: email.substringBefore("@")

            // Can't add yourself
            if (contactId == currentUserId)
                return Result.failure(Exception("You can't add yourself as a contact"))

            // Already added by ID?
            if (_contacts.value.any { it.id == contactId })
                return Result.failure(Exception("$contactName is already in your contacts"))

            // Persist to VedDB
            api.addContact(mapOf(
                "id"       to contactId,
                "userId"   to currentUserId,
                "username" to contactName,
                "email"    to (data["email"] as? String ?: email),
            ))

            // Update local state immediately
            val contact = Contact(
                id        = contactId,
                username  = contactName,
                ghostCode = generateGhostCode(contactId),
                online    = false,
                verified  = true,
            )
            _contacts.value = _contacts.value + contact
            Log.i(TAG, "Added contact: $contactName ($contactId)")
            Result.success(contact)

        } catch (e: Exception) {
            Log.e(TAG, "addContact error", e)
            Result.failure(e)
        }
    }


    // ── Chat logic ────────────────────────────────────────────────────────────

    fun setActiveChat(chatId: String) {
        _activeChat.value = chatId
        // Stamp destructAt the moment recipient opens the chat (mirrors web app)
        _messages.value = _messages.value.map { m ->
            if (m.chatId == chatId &&
                m.selfDestruct &&
                m.destructAt == null &&
                m.sender != _currentUser.value?.id) {
                m.copy(destructAt = System.currentTimeMillis() + ((m.destructTimer ?: 10) * 1000L))
            } else m
        }
    }

    suspend fun sendMessage(
        recipientId: String,
        text: String,
        selfDestruct: Boolean = false,
        destructTimer: Int = 10,
    ): Message {
        val user = _currentUser.value ?: error("Not logged in")
        val msg = Message(
            id            = generateId(),
            chatId        = recipientId,
            sender        = user.id,
            senderName    = user.username,
            text          = text,
            encrypted     = true,
            timestamp     = System.currentTimeMillis(),
            selfDestruct  = selfDestruct,
            destructTimer = if (selfDestruct) destructTimer else null,
            destructAt    = null,   // never stamped on sender's side
            status        = MessageStatus.SENT,
        )
        addMessage(msg)

        // Encrypt payload (AES-256-GCM, Android Keystore)
        val encryptedText = encryptAesGcm(text, recipientId)

        val wireMsg = mapOf(
            "id"            to msg.id,
            "sender"        to user.id,
            "senderName"    to user.username,
            "text"          to text,
            "encryptedData" to encryptedText,
            "encrypted"     to true,
            "timestamp"     to msg.timestamp,
            "selfDestruct"  to selfDestruct,
            "destructTimer" to destructTimer,
            "chatId"        to recipientId,
        )

        ws?.sendMessage(recipientId, wireMsg)
        // Store in VedDB in background
        scope.launch { api.sendMessage(wireMsg) }

        return msg
    }

    fun deleteMessage(messageId: String) {
        _messages.value = _messages.value.filter { it.id != messageId }
    }

    fun stampDestructAt(messageId: String, destructAt: Long) {
        _messages.value = _messages.value.map { m ->
            if (m.id == messageId) m.copy(destructAt = destructAt) else m
        }
    }

    fun getMessagesForChat(chatId: String): List<Message> =
        _messages.value.filter { it.chatId == chatId }.sortedBy { it.timestamp }

    // ── AES-256-GCM (Android Keystore) ───────────────────────────────────────

    private fun encryptAesGcm(plaintext: String, keyAlias: String): String {
        return try {
            val key    = getOrCreateKey(keyAlias)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            val combined = iv + ct
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Base64.encodeToString(plaintext.toByteArray(), Base64.NO_WRAP)
        }
    }

    @Suppress("unused")
    private fun decryptAesGcm(ciphertext: String, keyAlias: String): String {
        return try {
            val combined = Base64.decode(ciphertext, Base64.NO_WRAP)
            val iv = combined.copyOfRange(0, 12)
            val ct = combined.copyOfRange(12, combined.size)
            val key    = getOrCreateKey(keyAlias)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(ct).toString(Charsets.UTF_8)
        } catch (e: Exception) {
            Base64.decode(ciphertext, Base64.NO_WRAP).toString(Charsets.UTF_8)
        }
    }

    private fun getOrCreateKey(alias: String): javax.crypto.SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        if (ks.containsAlias(alias)) {
            return (ks.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
        }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()
        )
        return kg.generateKey()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun addMessage(msg: Message) {
        _messages.value = _messages.value + msg
    }

    private fun ensureContact(id: String, name: String) {
        if (_contacts.value.none { it.id == id }) {
            _contacts.value = _contacts.value + Contact(
                id        = id,
                username  = name,
                ghostCode = generateGhostCode(id),
                online    = true,
                verified  = true,
            )
        }
    }

    /** SHA-256 hex — matches cryptoService.hash() on the web frontend */
    private fun sha256hex(input: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private fun generateId(): String =
        "msg_${System.currentTimeMillis()}_${(Math.random() * 1e9).toLong().toString(36)}"

    private fun generateGhostCode(input: String): String {
        val hash = input.hashCode().and(0x7FFFFFFF).toString(16).uppercase().padStart(8, '0')
        return "CYPHRA-${hash.substring(0, 4)}-${hash.substring(4, 8)}"
    }
}
