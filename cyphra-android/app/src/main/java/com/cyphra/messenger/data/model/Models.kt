package com.cyphra.messenger.data.model

data class User(
    val id: String,
    val username: String,
    val ghostCode: String,
    val email: String = "",
    val token: String? = null,
)

data class Contact(
    val id: String,
    val username: String,
    val ghostCode: String,
    val online: Boolean = false,
    val verified: Boolean = false,
)

data class Message(
    val id: String,
    val chatId: String,
    val sender: String,
    val senderName: String,
    val text: String,
    val encrypted: Boolean = true,
    val timestamp: Long,
    val selfDestruct: Boolean = false,
    val destructTimer: Int? = null,       // duration in seconds
    val destructAt: Long? = null,         // epoch ms when countdown starts — null until chat opened
    val status: MessageStatus = MessageStatus.SENT,
)

enum class MessageStatus { SENT, DELIVERED, READ }

data class ChatThread(
    val contactId: String,
    val contactName: String,
    val lastMessage: String,
    val lastTimestamp: Long,
    val unreadCount: Int = 0,
    val isOnline: Boolean = false,
    val hasPendingDestruct: Boolean = false,
)

data class WsMessage(
    val type: String,
    val recipientId: String? = null,
    val message: Map<String, Any>? = null,
)
