package com.cyphra.messenger.network

import android.util.Log
import com.cyphra.messenger.BuildConfig
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.security.MessageDigest

private const val TAG = "CyphraApi"

/**
 * REST client for the Cyphra backend.
 *
 * Mirrors the web app's auth.service.js + veddb.service.js exactly:
 *  - userId   = SHA-256( email.toLowerCase() )
 *  - passwordHash = SHA-256( password + salt )
 *  - Storage key: user:{userId}  → fetched via GET /api/storage/get/:key
 *
 * This means any account registered on the web app works on the phone
 * without any changes to the backend.
 */
class CyphraApiClient {

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)   // give WiFi time to route
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    private val gson    = Gson()
    private val JSON    = "application/json; charset=utf-8".toMediaType()
    private val base    = BuildConfig.SERVER_URL

    // ── Auth ──────────────────────────────────────────────────────────────────

    /**
     * Login — replicates auth.service.js login() exactly.
     * 1. userId = sha256(email.toLowerCase())
     * 2. Fetch user object from VedDB via GET /api/storage/get/user:{userId}
     * 3. Verify SHA-256(password + user.salt) == user.passwordHash
     */
    suspend fun login(email: String, password: String): Result<Map<String, Any>> =
        withContext(Dispatchers.IO) {
            try {
                // Step 1 — derive userId the same way the web app does
                val userId = sha256(email.trim().lowercase())
                Log.d(TAG, "Logging in userId=$userId")

                // Step 2 — fetch user record from VedDB
                val userResp = get("/api/storage/get/user:$userId")
                    ?: return@withContext Result.failure(Exception("Invalid email or password"))

                @Suppress("UNCHECKED_CAST")
                val outer = userResp as? Map<String, Any>
                    ?: return@withContext Result.failure(Exception("Invalid server response"))

                if (outer["success"] != true)
                    return@withContext Result.failure(Exception("Invalid email or password"))

                @Suppress("UNCHECKED_CAST")
                val user = outer["value"] as? Map<String, Any>
                    ?: return@withContext Result.failure(Exception("Invalid server response"))

                // Step 3 — verify password: sha256(password + salt)
                val salt = user["salt"] as? String
                    ?: return@withContext Result.failure(Exception("Corrupted user record"))
                val computedHash = sha256(password + salt)
                val storedHash   = user["passwordHash"] as? String ?: ""

                if (computedHash != storedHash)
                    return@withContext Result.failure(Exception("Invalid email or password"))

                Log.i(TAG, "Login successful for ${user["username"]}")
                Result.success(user)

            } catch (e: Exception) {
                Log.e(TAG, "Login error", e)
                Result.failure(e)
            }
        }

    // ── Messages ──────────────────────────────────────────────────────────────

    suspend fun sendMessage(message: Map<String, Any>): Result<Unit> =
        withContext(Dispatchers.IO) {
            try {
                post("/api/messages", message)
                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Send message error", e)
                Result.failure(e)
            }
        }

    suspend fun getMessages(chatId: String): List<Map<String, Any>> =
        withContext(Dispatchers.IO) {
            try {
                @Suppress("UNCHECKED_CAST")
                val resp = get("/api/messages/chat/$chatId") as? Map<String, Any>
                @Suppress("UNCHECKED_CAST")
                resp?.get("messages") as? List<Map<String, Any>> ?: emptyList()
            } catch (e: Exception) {
                Log.e(TAG, "Get messages error", e)
                emptyList()
            }
        }

    suspend fun getContacts(userId: String): List<Map<String, Any>> =
        withContext(Dispatchers.IO) {
            try {
                @Suppress("UNCHECKED_CAST")
                val resp = get("/api/contacts/user/$userId") as? Map<String, Any>
                @Suppress("UNCHECKED_CAST")
                resp?.get("contacts") as? List<Map<String, Any>> ?: emptyList()
            } catch (e: Exception) {
                Log.e(TAG, "Get contacts error", e)
                emptyList()
            }
        }

    /**
     * Find a registered user by their email address.
     * Uses the same SHA-256 userId derivation as the web app.
     */
    suspend fun findUserByEmail(email: String): Result<Map<String, Any>> =
        withContext(Dispatchers.IO) {
            try {
                val userId = sha256(email.trim().lowercase())
                Log.d(TAG, "Looking up user by email → userId=$userId")
                val resp = get("/api/storage/get/user:$userId")
                    ?: return@withContext Result.failure(Exception("User not found"))
                @Suppress("UNCHECKED_CAST")
                val outer = resp as? Map<String, Any>
                    ?: return@withContext Result.failure(Exception("User not found"))
                if (outer["success"] != true)
                    return@withContext Result.failure(Exception("User not found"))
                @Suppress("UNCHECKED_CAST")
                val user = outer["value"] as? Map<String, Any>
                    ?: return@withContext Result.failure(Exception("User not found"))
                Result.success(user)
            } catch (e: Exception) {
                Log.e(TAG, "findUserByEmail error", e)
                Result.failure(e)
            }
        }

    /**
     * Persist a contact relationship in VedDB.
     * POST /api/contacts   body: { id, userId, username, email }
     */
    suspend fun addContact(contact: Map<String, Any>): Result<Unit> =
        withContext(Dispatchers.IO) {
            try {
                post("/api/contacts", contact)
                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "addContact error", e)
                Result.failure(e)
            }
        }


    // ── Health ────────────────────────────────────────────────────────────────

    suspend fun ping(): Boolean = withContext(Dispatchers.IO) {
        try {
            get("/api/storage/ping") != null
        } catch (e: Exception) {
            false
        }
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private fun get(path: String): Any? {
        val req = Request.Builder().url("$base$path").get().build()
        val body = client.newCall(req).execute().use { it.body?.string() } ?: return null
        val type = object : TypeToken<Map<String, Any>>() {}.type
        return gson.fromJson<Map<String, Any>>(body, type)
    }

    private fun post(path: String, data: Map<String, Any>): Any? {
        val body = gson.toJson(data).toRequestBody(JSON)
        val req  = Request.Builder().url("$base$path").post(body).build()
        val resp = client.newCall(req).execute().use { it.body?.string() } ?: return null
        val type = object : TypeToken<Map<String, Any>>() {}.type
        return gson.fromJson<Map<String, Any>>(resp, type)
    }

    // ── Crypto helper — matches web app's cryptoService.hash() ────────────────

    private fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
