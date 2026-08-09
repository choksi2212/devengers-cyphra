package com.cyphra.messenger.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.cyphra.messenger.data.model.ChatThread
import com.cyphra.messenger.ui.MessengerViewModel
import com.cyphra.messenger.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatListScreen(
    vm: MessengerViewModel,
    onChatOpen: (contactId: String, contactName: String) -> Unit,
    onSettingsClick: () -> Unit,
) {
    val currentUser      by vm.currentUser.collectAsState()
    val contacts         by vm.contacts.collectAsState()
    val messages         by vm.messages.collectAsState()
    val isConnected      by vm.isConnected.collectAsState()
    val addContactState  by vm.addContactState.collectAsState()

    // Derive chat threads fresh on every recomposition
    val threads = remember(contacts, messages) { vm.getChatThreads() }

    // Show add-contact dialog
    var showAddDialog by remember { mutableStateOf(false) }

    // Auto-close dialog on success
    LaunchedEffect(addContactState.success) {
        if (addContactState.success != null) {
            kotlinx.coroutines.delay(1200)
            showAddDialog = false
            vm.resetAddContactState()
        }
    }

    Scaffold(
        containerColor = CyphraBg,
        topBar = {
            CyphraTopBar(
                currentUser    = currentUser?.username ?: "Cyphra",
                isConnected    = isConnected,
                onPencilClick  = {
                    vm.resetAddContactState()
                    showAddDialog = true
                },
                onSettingsClick = onSettingsClick,
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    vm.resetAddContactState()
                    showAddDialog = true
                },
                containerColor = CyphraAccent,
                contentColor   = Color(0xFF00344D),
                shape          = CircleShape,
                modifier       = Modifier.size(56.dp),
            ) {
                Icon(Icons.Default.PersonAdd, contentDescription = "Add Contact", modifier = Modifier.size(24.dp))
            }
        },
    ) { padding ->

        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when {
                contacts.isEmpty() -> EmptyState()
                else -> {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = 80.dp),
                    ) {
                        item {
                            // Header row
                            Row(
                                modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    "CONVERSATIONS",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        letterSpacing = 2.sp,
                                        color = CyphraTextMuted,
                                    ),
                                )
                                Spacer(Modifier.weight(1f))
                                Text(
                                    "${threads.size} chats",
                                    style = MaterialTheme.typography.labelSmall.copy(color = CyphraTextMuted),
                                )
                            }
                        }
                        items(threads, key = { it.contactId }) { thread ->
                            ChatThreadRow(thread = thread, onClick = {
                                vm.setActiveChat(thread.contactId)
                                onChatOpen(thread.contactId, thread.contactName)
                            })
                        }
                    }
                }
            }
        }
    }

    // ── Add Contact Dialog ────────────────────────────────────────────────────
    if (showAddDialog) {
        AddContactDialog(
            state      = addContactState,
            onAdd      = { email -> vm.addContact(email) },
            onDismiss  = {
                showAddDialog = false
                vm.resetAddContactState()
            },
        )
    }
}

// ── Top App Bar ───────────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CyphraTopBar(
    currentUser: String,
    isConnected: Boolean,
    onPencilClick: () -> Unit,
    onSettingsClick: () -> Unit,
) {
    TopAppBar(
        colors = TopAppBarDefaults.topAppBarColors(containerColor = CyphraSurface),
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Logo
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .background(
                            Brush.radialGradient(listOf(CyphraAccent.copy(0.2f), Color.Transparent)),
                            CircleShape,
                        )
                        .border(1.dp, CyphraAccent.copy(0.4f), CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Default.Shield, null, tint = CyphraAccent, modifier = Modifier.size(16.dp))
                }
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(
                        "CYPHRA",
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontWeight   = FontWeight.ExtraBold,
                            letterSpacing = 2.sp,
                            color        = CyphraTextPrimary,
                        ),
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(6.dp)
                                .background(
                                    if (isConnected) CyphraSuccess else CyphraTextMuted,
                                    CircleShape,
                                )
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            if (isConnected) "Encrypted · Online" else "Offline",
                            style = MaterialTheme.typography.labelSmall.copy(color = CyphraTextMuted, fontSize = 10.sp),
                        )
                    }
                }
            }
        },
        actions = {
            // Pencil / compose button — opens Add Contact dialog
            IconButton(onClick = onPencilClick) {
                Icon(
                    Icons.Default.Edit,
                    contentDescription = "New Chat",
                    tint = CyphraAccent,
                )
            }
            IconButton(onClick = onSettingsClick) {
                Icon(Icons.Default.Settings, contentDescription = "Settings", tint = CyphraTextMuted)
            }
        },
    )
}

// ── Chat Thread Row ───────────────────────────────────────────────────────────

@Composable
private fun ChatThreadRow(thread: ChatThread, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(CyphraSurface)
            .padding(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Avatar
        Box(
            modifier = Modifier
                .size(48.dp)
                .background(
                    Brush.radialGradient(listOf(CyphraAccent.copy(0.25f), CyphraBorder)),
                    CircleShape,
                )
                .border(1.5.dp, if (thread.isOnline) CyphraSuccess else CyphraBorder, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                thread.contactName.take(1).uppercase(),
                style = MaterialTheme.typography.titleMedium.copy(
                    fontWeight = FontWeight.Bold,
                    color      = CyphraAccent,
                ),
            )
        }

        Spacer(Modifier.width(12.dp))

        // Message info
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    thread.contactName,
                    style   = MaterialTheme.typography.bodyMedium.copy(
                        fontWeight = FontWeight.SemiBold,
                        color      = CyphraTextPrimary,
                    ),
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (thread.lastTimestamp > 0L) {
                    Text(
                        formatTime(thread.lastTimestamp),
                        style = MaterialTheme.typography.labelSmall.copy(color = CyphraTextMuted, fontSize = 10.sp),
                    )
                }
            }
            Spacer(Modifier.height(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (thread.hasPendingDestruct) {
                    Icon(Icons.Default.Timer, null, tint = CyphraDanger, modifier = Modifier.size(12.dp))
                    Spacer(Modifier.width(3.dp))
                }
                Text(
                    thread.lastMessage,
                    style   = MaterialTheme.typography.bodySmall.copy(
                        color = if (thread.unreadCount > 0) CyphraTextPrimary else CyphraTextMuted,
                    ),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (thread.unreadCount > 0) {
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier = Modifier
                            .size(20.dp)
                            .background(CyphraAccent, CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            thread.unreadCount.coerceAtMost(99).toString(),
                            style = MaterialTheme.typography.labelSmall.copy(
                                color = Color(0xFF00344D),
                                fontWeight = FontWeight.Bold,
                                fontSize = 9.sp,
                            ),
                        )
                    }
                }
            }
        }
    }
    Spacer(Modifier.height(2.dp))
}

// ── Add Contact Dialog ────────────────────────────────────────────────────────

@Composable
private fun AddContactDialog(
    state: MessengerViewModel.AddContactState,
    onAdd: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var emailInput by remember { mutableStateOf("") }
    val focusMgr = LocalFocusManager.current

    Dialog(onDismissRequest = { if (!state.isLoading) onDismiss() }) {
        Surface(
            shape          = RoundedCornerShape(16.dp),
            color          = CyphraSurface,
            tonalElevation = 8.dp,
            modifier       = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                // Header
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(CyphraAccent.copy(0.15f), CircleShape)
                            .border(1.dp, CyphraAccent.copy(0.4f), CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(Icons.Default.PersonAdd, null, tint = CyphraAccent, modifier = Modifier.size(20.dp))
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(
                            "ADD CONTACT",
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight    = FontWeight.ExtraBold,
                                letterSpacing = 2.sp,
                                color         = CyphraTextPrimary,
                            ),
                        )
                        Text(
                            "Enter their Cyphra email address",
                            style = MaterialTheme.typography.bodySmall.copy(color = CyphraTextMuted),
                        )
                    }
                }

                HorizontalDivider(color = CyphraBorder, thickness = 0.5.dp)

                // Email input
                OutlinedTextField(
                    value         = emailInput,
                    onValueChange = { emailInput = it },
                    label         = { Text("EMAIL ADDRESS", style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 1.sp)) },
                    leadingIcon   = { Icon(Icons.Default.AlternateEmail, null, tint = CyphraTextMuted, modifier = Modifier.size(18.dp)) },
                    singleLine    = true,
                    enabled       = !state.isLoading && state.success == null,
                    modifier      = Modifier.fillMaxWidth(),
                    shape         = RoundedCornerShape(8.dp),
                    keyboardOptions = KeyboardOptions(
                        imeAction    = ImeAction.Done,
                        keyboardType = KeyboardType.Email,
                    ),
                    keyboardActions = KeyboardActions(onDone = {
                        focusMgr.clearFocus()
                        if (emailInput.isNotBlank() && '@' in emailInput) onAdd(emailInput)
                    }),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor    = CyphraAccent,
                        unfocusedBorderColor  = CyphraBorder,
                        focusedLabelColor     = CyphraAccent,
                        unfocusedLabelColor   = CyphraTextMuted,
                        focusedTextColor      = CyphraTextPrimary,
                        unfocusedTextColor    = CyphraTextPrimary,
                        cursorColor           = CyphraAccent,
                        focusedContainerColor    = CyphraBg,
                        unfocusedContainerColor  = CyphraBg,
                    ),
                )

                // Success / Error feedback
                AnimatedVisibility(visible = state.success != null) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(CyphraSuccess.copy(0.1f), RoundedCornerShape(8.dp))
                            .padding(12.dp),
                    ) {
                        Icon(Icons.Default.CheckCircle, null, tint = CyphraSuccess, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "${state.success} added successfully!",
                            style = MaterialTheme.typography.bodySmall.copy(color = CyphraSuccess),
                        )
                    }
                }
                AnimatedVisibility(visible = state.error != null && state.success == null) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(CyphraDanger.copy(0.1f), RoundedCornerShape(8.dp))
                            .padding(12.dp),
                    ) {
                        Icon(Icons.Default.Error, null, tint = CyphraDanger, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(
                            state.error ?: "",
                            style = MaterialTheme.typography.bodySmall.copy(color = CyphraDanger),
                        )
                    }
                }

                // Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedButton(
                        onClick  = onDismiss,
                        enabled  = !state.isLoading,
                        modifier = Modifier.weight(1f),
                        shape    = RoundedCornerShape(8.dp),
                        border   = BorderStroke(1.dp, CyphraBorder),
                    ) {
                        Text("CANCEL", color = CyphraTextMuted, letterSpacing = 1.sp)
                    }
                    Button(
                        onClick  = {
                            focusMgr.clearFocus()
                            if (emailInput.isNotBlank() && '@' in emailInput) onAdd(emailInput)
                        },
                        enabled  = emailInput.isNotBlank() && '@' in emailInput && !state.isLoading && state.success == null,
                        modifier = Modifier.weight(1f),
                        shape    = RoundedCornerShape(8.dp),
                        colors   = ButtonDefaults.buttonColors(containerColor = CyphraAccent),
                    ) {
                        if (state.isLoading) {
                            CircularProgressIndicator(
                                color       = Color(0xFF00344D),
                                modifier    = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                            )
                        } else {
                            Text("ADD", color = Color(0xFF00344D), fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                        }
                    }
                }
            }
        }
    }
}

// ── Empty State ───────────────────────────────────────────────────────────────

@Composable
private fun EmptyState() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            modifier = Modifier
                .size(80.dp)
                .background(CyphraAccent.copy(0.1f), CircleShape)
                .border(1.dp, CyphraAccent.copy(0.3f), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Default.Forum, null, tint = CyphraAccent, modifier = Modifier.size(36.dp))
        }
        Spacer(Modifier.height(24.dp))
        Text(
            "NO CONTACTS YET",
            style = MaterialTheme.typography.titleSmall.copy(
                fontWeight    = FontWeight.ExtraBold,
                letterSpacing = 2.sp,
                color         = CyphraTextPrimary,
            ),
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "Tap the ✏ button or + button\nto add a contact by email",
            style     = MaterialTheme.typography.bodySmall.copy(color = CyphraTextMuted),
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

private fun formatTime(timestamp: Long): String {
    val now = System.currentTimeMillis()
    val diff = now - timestamp
    return when {
        diff < 60_000           -> "now"
        diff < 3_600_000        -> "${diff / 60_000}m"
        diff < 86_400_000       -> SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(timestamp))
        else                    -> SimpleDateFormat("dd/MM", Locale.getDefault()).format(Date(timestamp))
    }
}
