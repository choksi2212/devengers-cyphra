package com.cyphra.messenger.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import com.cyphra.messenger.data.model.Message
import com.cyphra.messenger.data.model.MessageStatus
import com.cyphra.messenger.ui.MessengerViewModel
import com.cyphra.messenger.ui.theme.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    vm: MessengerViewModel,
    contactId: String,
    onBack: () -> Unit,
) {
    val currentUser  by vm.currentUser.collectAsState()
    val allMessages  by vm.messages.collectAsState()
    val chatMessages = remember(allMessages) { vm.getMessagesForChat(contactId) }
    val contact      = vm.contacts.collectAsState().value.firstOrNull { it.id == contactId }

    var messageText  by remember { mutableStateOf("") }
    var selfDestruct by remember { mutableStateOf(false) }
    val listState    = rememberLazyListState()
    val scope        = rememberCoroutineScope()

    // ── CRITICAL: Set active chat when screen opens ───────────────────────────
    // This triggers stampDestructAt for any pending self-destruct messages
    // in this conversation — exactly mirrors the web app's useEffect on activeChat.
    LaunchedEffect(contactId) {
        vm.setActiveChat(contactId)
    }

    // Scroll to bottom on new message
    LaunchedEffect(chatMessages.size) {
        if (chatMessages.isNotEmpty()) listState.animateScrollToItem(chatMessages.size - 1)
    }


    Scaffold(
        containerColor = CyphraBg,
        topBar = {
            Column(
                modifier = Modifier
                    .background(CyphraBg)
                    .statusBarsPadding()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = CyphraTextSecondary)
                    }
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(
                                Brush.linearGradient(listOf(CyphraAccent, CyphraTeal)),
                                CircleShape,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            (contact?.username ?: contact?.id ?: "?").take(2).uppercase(),
                            style = MaterialTheme.typography.titleMedium.copy(color = Color(0xFF001E2F), fontWeight = FontWeight.Bold),
                        )
                    }
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            contact?.username ?: contactId,
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
                        )
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            Icon(Icons.Default.Lock, null, tint = CyphraAccent, modifier = Modifier.size(11.dp))
                            Text(
                                "ENCRYPTED · ${if (contact?.online == true) "ONLINE" else "OFFLINE"}",
                                style = MaterialTheme.typography.labelSmall.copy(color = CyphraAccent, letterSpacing = 1.sp),
                            )
                        }
                    }
                    IconButton(onClick = {}) {
                        Icon(Icons.Default.MoreVert, null, tint = CyphraTextSecondary)
                    }
                }
                Divider(color = CyphraBorder, thickness = 0.5.dp)
            }
        },
        bottomBar = {
            ChatInputBar(
                text         = messageText,
                onTextChange = { messageText = it },
                selfDestruct = selfDestruct,
                onSelfDestructToggle = { selfDestruct = !selfDestruct },
                onSend       = {
                    if (messageText.isNotBlank()) {
                        vm.sendMessage(messageText, selfDestruct, 10)
                        messageText = ""
                        scope.launch { delay(100); if (chatMessages.isNotEmpty()) listState.animateScrollToItem(chatMessages.size - 1) }
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            state   = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
            contentPadding = PaddingValues(vertical = 12.dp),
        ) {
            items(chatMessages, key = { it.id }) { msg ->
                val isMine = msg.sender == currentUser?.id
                MessageBubble(
                    message = msg,
                    isMine  = isMine,
                    onExpire = { vm.deleteMessage(msg.id) },
                )
            }
        }
    }
}

// ── Message Bubble ─────────────────────────────────────────────────────────

@Composable
fun MessageBubble(message: Message, isMine: Boolean, onExpire: () -> Unit) {
    val timeFmt = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = if (isMine) Alignment.End else Alignment.Start,
    ) {
        Box(
            modifier = Modifier
                .widthIn(max = 280.dp)
                .background(
                    if (isMine) CyphraAccent else CyphraSurface,
                    RoundedCornerShape(
                        topStart = 16.dp, topEnd = 16.dp,
                        bottomStart = if (isMine) 16.dp else 4.dp,
                        bottomEnd   = if (isMine) 4.dp   else 16.dp,
                    )
                )
                .padding(horizontal = 14.dp, vertical = 10.dp),
        ) {
            Column {
                if (!isMine) {
                    Text(
                        message.senderName,
                        style = MaterialTheme.typography.labelSmall.copy(
                            color = CyphraAccent, fontWeight = FontWeight.SemiBold,
                        ),
                    )
                    Spacer(Modifier.height(2.dp))
                }
                Text(
                    message.text,
                    style = MaterialTheme.typography.bodyMedium.copy(
                        color = if (isMine) Color(0xFF001E2F) else CyphraTextPrimary,
                    ),
                )
                Spacer(Modifier.height(4.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.End),
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    // Self-destruct countdown
                    if (message.selfDestruct && message.destructAt != null) {
                        CountdownTimer(
                            destructAt = message.destructAt,
                            onExpire   = onExpire,
                            accent     = if (isMine) Color(0x80003751) else CyphraWarning,
                        )
                    }
                    // Lock icon
                    Icon(
                        Icons.Default.Lock, null,
                        tint = if (isMine) Color(0x80003751) else CyphraTextMuted,
                        modifier = Modifier.size(10.dp),
                    )
                    // Timestamp
                    Text(
                        timeFmt.format(Date(message.timestamp)),
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                            color      = if (isMine) Color(0x80003751) else CyphraTextMuted,
                        ),
                    )
                    // Read status (mine only)
                    if (isMine) {
                        Icon(
                            when (message.status) {
                                MessageStatus.READ      -> Icons.Default.DoneAll
                                MessageStatus.DELIVERED -> Icons.Default.DoneAll
                                MessageStatus.SENT      -> Icons.Default.Done
                            },
                            null,
                            modifier = Modifier.size(13.dp),
                            tint = when (message.status) {
                                MessageStatus.READ      -> Color(0xFF00BFFF)
                                else                    -> Color(0x80003751)
                            },
                        )
                    }
                }
            }
        }
    }
}

// ── Countdown Timer ────────────────────────────────────────────────────────

@Composable
fun CountdownTimer(destructAt: Long, onExpire: () -> Unit, accent: Color) {
    var secondsLeft by remember { mutableStateOf(
        maxOf(0, ((destructAt - System.currentTimeMillis()) / 1000).toInt())
    )}

    LaunchedEffect(destructAt) {
        while (secondsLeft > 0) {
            delay(1000L)
            secondsLeft = maxOf(0, ((destructAt - System.currentTimeMillis()) / 1000).toInt())
        }
        onExpire()
    }

    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(3.dp)) {
        Icon(Icons.Default.Timer, null, tint = CyphraWarning, modifier = Modifier.size(11.dp))
        Text("${secondsLeft}s", style = MaterialTheme.typography.labelSmall.copy(
            color = CyphraWarning, fontFamily = FontFamily.Monospace,
        ))
    }
}

// ── Input Bar ─────────────────────────────────────────────────────────────

@Composable
fun ChatInputBar(
    text: String,
    onTextChange: (String) -> Unit,
    selfDestruct: Boolean,
    onSelfDestructToggle: () -> Unit,
    onSend: () -> Unit,
) {
    Column(
        modifier = Modifier
            .background(CyphraBg)
            .navigationBarsPadding()
            .imePadding(),
    ) {
        // Self-destruct banner
        AnimatedVisibility(visible = selfDestruct) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(CyphraWarning.copy(0.1f))
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Icon(Icons.Default.Timer, null, tint = CyphraWarning, modifier = Modifier.size(14.dp))
                    Text("Self-destruct: 10s after read", style = MaterialTheme.typography.bodySmall.copy(color = CyphraWarning))
                }
                TextButton(onClick = onSelfDestructToggle) {
                    Text("CANCEL", style = MaterialTheme.typography.labelSmall.copy(color = CyphraWarning))
                }
            }
        }

        Divider(color = CyphraBorder, thickness = 0.5.dp)

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            // Self-destruct toggle
            IconButton(
                onClick = onSelfDestructToggle,
                modifier = Modifier.size(40.dp),
            ) {
                Icon(
                    Icons.Default.Timer,
                    null,
                    tint   = if (selfDestruct) CyphraWarning else CyphraTextMuted,
                    modifier = Modifier.size(20.dp),
                )
            }

            // Text field
            OutlinedTextField(
                value         = text,
                onValueChange = onTextChange,
                modifier      = Modifier.weight(1f),
                placeholder   = { Text("Encrypted message...", style = MaterialTheme.typography.bodySmall.copy(color = CyphraTextMuted)) },
                maxLines      = 4,
                shape         = RoundedCornerShape(20.dp),
                colors        = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor   = CyphraAccent,
                    unfocusedBorderColor = CyphraBorder,
                    focusedTextColor     = CyphraTextPrimary,
                    unfocusedTextColor   = CyphraTextPrimary,
                    cursorColor          = CyphraAccent,
                    focusedContainerColor   = CyphraSurface,
                    unfocusedContainerColor = CyphraSurface,
                ),
            )

            // Send button
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(
                        if (text.isNotBlank()) CyphraAccent else CyphraSurface,
                        CircleShape,
                    )
                    .clickable(enabled = text.isNotBlank(), onClick = onSend),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    Icons.Default.Send, "Send",
                    tint     = if (text.isNotBlank()) Color(0xFF001E2F) else CyphraTextMuted,
                    modifier = Modifier.size(20.dp),
                )
            }
        }
    }
}
