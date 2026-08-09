package com.cyphra.messenger.network

import android.os.Handler
import android.os.Looper
import android.util.Log
import com.cyphra.messenger.BuildConfig
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import okhttp3.*
import java.util.concurrent.TimeUnit

private const val TAG = "CyphraWS"

/**
 * WebSocket client — mirrors the frontend veddb.service.js WebSocket layer.
 *
 * Backend message routing works via subscriptions:
 *   1. Client connects → server responds with { type:"connected" }
 *   2. Client subscribes → sends { type:"subscribe", key:"messages:{userId}" }
 *   3. Sender sends   → { type:"message", recipientId, message:{...} }
 *   4. Recipient gets → { type:"update", key:"messages:{recipientId}", data:{...} }
 *
 * So we MUST subscribe after connect or we never receive anything.
 */
class CyphraWebSocket(
    private val userId: String,
    private val onMessage: suspend (Map<String, Any>) -> Unit,
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)   // 0 = no timeout for WebSocket (it's persistent)
        .writeTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    private val scope          = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val gson           = Gson()
    private val handler        = Handler(Looper.getMainLooper())
    private var ws             : WebSocket? = null
    private var reconnectDelay = 1000L

    /** The subscription key the backend uses to find this client */
    private val mySubscriptionKey = "messages:$userId"

    val isConnected = MutableStateFlow(false)

    fun connect() {
        val request = Request.Builder()
            .url(BuildConfig.WS_URL)
            .addHeader("X-User-Id", userId)
            .build()

        ws = client.newWebSocket(request, object : WebSocketListener() {

            override fun onOpen(webSocket: WebSocket, response: Response) {
                Log.i(TAG, "WebSocket connected for user=$userId")
                reconnectDelay = 1000L
                isConnected.tryEmit(true)

                // 1. Tell server we are online
                sendJson(mapOf("type" to "presence", "userId" to userId, "status" to "online"))

                // 2. Subscribe to OUR messages key — REQUIRED for receiving messages
                //    Without this the backend never delivers any messages to us
                sendJson(mapOf("type" to "subscribe", "key" to mySubscriptionKey))
                Log.i(TAG, "Subscribed to key: $mySubscriptionKey")
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                Log.d(TAG, "<<< RAW: $text")
                try {
                    val type = object : TypeToken<Map<String, Any>>() {}.type
                    val payload: Map<String, Any> = gson.fromJson(text, type)

                    when (payload["type"] as? String) {
                        "connected" -> {
                            Log.i(TAG, "Server confirmed connection, clientId=${payload["clientId"]}")
                            // Re-subscribe in case server restarted
                            sendJson(mapOf("type" to "subscribe", "key" to mySubscriptionKey))
                        }
                        "subscribed" -> {
                            Log.i(TAG, "Subscribed confirmed: key=${payload["key"]}")
                        }
                        "update" -> {
                            // This is the shape of an incoming message from another user:
                            // { type:"update", key:"messages:{ourId}", data: {messagePayload} }
                            val key = payload["key"] as? String ?: ""
                            if (key == mySubscriptionKey) {
                                @Suppress("UNCHECKED_CAST")
                                val data = payload["data"] as? Map<String, Any> ?: return
                                Log.i(TAG, "Incoming message from ${data["sender"]}")
                                // Wrap in the shape handleIncoming() expects
                                scope.launch {
                                    onMessage(mapOf("type" to "message", "message" to data))
                                }
                            }
                        }
                        "delivered" -> {
                            Log.d(TAG, "Delivery confirmed for msgId=${payload["messageId"]}")
                        }
                        "pong" -> { /* keepalive */ }
                        "error" -> {
                            Log.w(TAG, "Server error: ${payload["message"]}")
                        }
                        else -> {
                            Log.d(TAG, "Unhandled WS type: ${payload["type"]}")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "WS parse error for text=$text", e)
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "WS failure (${t.message}), retrying in ${reconnectDelay}ms")
                isConnected.tryEmit(false)
                scheduleReconnect()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "WS closed: $reason")
                isConnected.tryEmit(false)
            }
        })
    }

    fun sendMessage(recipientId: String, message: Map<String, Any>) {
        val payload = mapOf(
            "type"        to "message",
            "recipientId" to recipientId,
            "message"     to message,
        )
        Log.d(TAG, ">>> SEND to $recipientId")
        sendJson(payload)
    }

    fun sendReadReceipt(senderId: String, messageId: String) {
        sendJson(mapOf(
            "type"        to "message",
            "recipientId" to senderId,
            "message"     to mapOf("type" to "read_receipt", "messageId" to messageId),
        ))
    }

    private fun sendJson(data: Map<String, Any>) {
        val json = gson.toJson(data)
        val sent = ws?.send(json) ?: false
        if (!sent) Log.w(TAG, "WS send failed — not connected?")
    }

    private fun scheduleReconnect() {
        val delay = reconnectDelay
        reconnectDelay = minOf(reconnectDelay * 2, 30_000L)
        handler.postDelayed({ connect() }, delay)
    }

    fun disconnect() {
        ws?.close(1000, "User logged out")
        scope.cancel()
        handler.removeCallbacksAndMessages(null)
    }
}
