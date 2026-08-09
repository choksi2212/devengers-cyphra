package com.cyphra.messenger.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.cyphra.messenger.data.model.*
import com.cyphra.messenger.data.repository.MessengerRepository
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

class MessengerViewModel(app: Application) : AndroidViewModel(app) {
    val repo = MessengerRepository()

    val currentUser  = repo.currentUser
    val messages     = repo.messages
    val contacts     = repo.contacts
    val activeChat   = repo.activeChat
    val isConnected  = repo.isConnected

    private val _uiState = MutableStateFlow(UiState())
    val uiState: StateFlow<UiState> = _uiState

    // Separate state for the Add Contact dialog
    private val _addContactState = MutableStateFlow(AddContactState())
    val addContactState: StateFlow<AddContactState> = _addContactState

    data class UiState(
        val isLoading: Boolean = false,
        val error: String? = null,
        val isAuthenticated: Boolean = false,
    )

    data class AddContactState(
        val isLoading: Boolean = false,
        val error: String? = null,
        val success: String? = null,  // set to contact name on success
    )

    fun login(email: String, password: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, error = null) }
            val result = repo.login(email, password)
            if (result.isSuccess) {
                _uiState.update { it.copy(isLoading = false, isAuthenticated = true) }
            } else {
                _uiState.update { it.copy(isLoading = false, error = result.exceptionOrNull()?.message) }
            }
        }
    }

    fun addContact(email: String) {
        viewModelScope.launch {
            _addContactState.value = AddContactState(isLoading = true)
            val result = repo.addContact(email.trim())
            if (result.isSuccess) {
                val contact = result.getOrThrow()
                _addContactState.value = AddContactState(success = contact.username)
            } else {
                _addContactState.value = AddContactState(error = result.exceptionOrNull()?.message ?: "Failed to add contact")
            }
        }
    }

    fun resetAddContactState() {
        _addContactState.value = AddContactState()
    }

    fun setActiveChat(chatId: String) = repo.setActiveChat(chatId)

    fun sendMessage(text: String, selfDestruct: Boolean, destructTimer: Int) {
        val chatId = activeChat.value ?: return
        viewModelScope.launch {
            repo.sendMessage(chatId, text, selfDestruct, destructTimer)
        }
    }

    fun deleteMessage(messageId: String) = repo.deleteMessage(messageId)

    fun stampDestructAt(messageId: String, destructAt: Long) =
        repo.stampDestructAt(messageId, destructAt)

    fun getMessagesForChat(chatId: String) = repo.getMessagesForChat(chatId)

    fun getChatThreads(): List<ChatThread> {
        val msgs = messages.value
        val contactList = contacts.value
        return contactList.map { contact ->
            val chatMsgs = msgs.filter { it.chatId == contact.id }
            val last = chatMsgs.maxByOrNull { it.timestamp }
            ChatThread(
                contactId          = contact.id,
                contactName        = contact.username,
                lastMessage        = last?.text ?: "Tap to start a conversation",
                lastTimestamp      = last?.timestamp ?: 0L,
                unreadCount        = chatMsgs.count { it.status != MessageStatus.READ && it.sender != currentUser.value?.id },
                isOnline           = contact.online,
                hasPendingDestruct = chatMsgs.any { it.selfDestruct && it.destructAt == null },
            )
        }.sortedByDescending { it.lastTimestamp }
    }
}

