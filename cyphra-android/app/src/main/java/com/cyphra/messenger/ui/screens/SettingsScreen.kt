package com.cyphra.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import com.cyphra.messenger.ui.MessengerViewModel
import com.cyphra.messenger.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: MessengerViewModel, onBack: () -> Unit) {
    val currentUser by vm.currentUser.collectAsState()
    val isConnected by vm.isConnected.collectAsState()

    Scaffold(
        containerColor = CyphraBg,
        topBar = {
            Column(
                modifier = Modifier
                    .background(CyphraBg)
                    .statusBarsPadding()
            ) {
                Row(
                    modifier  = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 4.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = CyphraTextSecondary)
                    }
                    Text(
                        "SETTINGS",
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontWeight = FontWeight.Bold, letterSpacing = 3.sp,
                        ),
                    )
                }
                Divider(color = CyphraBorder, thickness = 0.5.dp)
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(vertical = 16.dp),
        ) {
            // ── Profile card ─────────────────────────────────────────────
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(CyphraSurface, RoundedCornerShape(12.dp))
                        .border(1.dp, CyphraAccent.copy(0.2f), RoundedCornerShape(12.dp))
                        .padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .background(
                                Brush.linearGradient(listOf(CyphraAccent, CyphraTeal)),
                                CircleShape,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            (currentUser?.username ?: "?").take(2).uppercase(),
                            style = MaterialTheme.typography.headlineMedium.copy(
                                color = Color(0xFF001E2F), fontWeight = FontWeight.ExtraBold,
                            ),
                        )
                    }
                    Text(
                        currentUser?.username ?: "Anonymous",
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    )
                    // Ghost Code
                    Box(
                        modifier = Modifier
                            .background(CyphraAccent.copy(0.1f), RoundedCornerShape(8.dp))
                            .border(1.dp, CyphraAccent.copy(0.3f), RoundedCornerShape(8.dp))
                            .padding(horizontal = 14.dp, vertical = 6.dp),
                    ) {
                        Text(
                            currentUser?.ghostCode ?: "CYPHRA-????-????",
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontFamily = FontFamily.Monospace,
                                color      = CyphraAccent,
                                fontWeight = FontWeight.Medium,
                            ),
                        )
                    }
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Box(Modifier.size(6.dp).background(CyphraSuccess, CircleShape))
                        Text("Secure Identity Active", style = MaterialTheme.typography.bodySmall.copy(color = CyphraSuccess))
                    }
                }
            }

            // ── Security section ─────────────────────────────────────────
            item { SectionHeader("SECURITY") }
            item {
                SettingsGroup {
                    SettingsRow(
                        icon   = Icons.Default.Lock,
                        label  = "Encryption",
                        value  = "AES-256-GCM",
                        valueColor = CyphraSuccess,
                    )
                    SettingsDivider()
                    var destructToggle by remember { mutableStateOf(true) }
                    SettingsToggleRow(
                        icon    = Icons.Default.Timer,
                        label   = "Self-Destruct Messages",
                        checked = destructToggle,
                        onCheckedChange = { destructToggle = it },
                    )
                    SettingsDivider()
                    var biometricToggle by remember { mutableStateOf(true) }
                    SettingsToggleRow(
                        icon    = Icons.Default.Fingerprint,
                        label   = "Biometric Lock",
                        checked = biometricToggle,
                        onCheckedChange = { biometricToggle = it },
                    )
                }
            }

            // ── Connection section ────────────────────────────────────────
            item { SectionHeader("CONNECTION") }
            item {
                SettingsGroup {
                    SettingsRow(
                        icon   = Icons.Default.Wifi,
                        label  = "Server Status",
                        value  = if (isConnected) "Connected" else "Disconnected",
                        valueColor = if (isConnected) CyphraSuccess else CyphraDanger,
                    )
                    SettingsDivider()
                    SettingsRow(
                        icon  = Icons.Default.Shield,
                        label = "Protocol",
                        value = "WebSocket + TLS",
                    )
                }
            }

            // ── App section ───────────────────────────────────────────────
            item { SectionHeader("APPLICATION") }
            item {
                SettingsGroup {
                    SettingsRow(icon = Icons.Default.Palette,   label = "Theme",   value = "Dark Military")
                    SettingsDivider()
                    SettingsRow(icon = Icons.Default.Info,      label = "Version", value = "1.0.0")
                    SettingsDivider()
                    SettingsRow(icon = Icons.Default.Security,  label = "Build",   value = "CYPHRA-SECURE")
                }
            }

            item { Spacer(Modifier.height(40.dp)) }
        }
    }
}

@Composable fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.labelSmall.copy(
            color = CyphraTextMuted, letterSpacing = 2.sp,
        ),
        modifier = Modifier.padding(start = 4.dp, top = 8.dp, bottom = 4.dp),
    )
}

@Composable fun SettingsGroup(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(CyphraSurface, RoundedCornerShape(12.dp)),
        content = content,
    )
}

@Composable fun SettingsDivider() = Divider(
    modifier = Modifier.padding(start = 52.dp),
    color    = CyphraBorder, thickness = 0.5.dp
)

@Composable fun SettingsRow(
    icon: ImageVector,
    label: String,
    value: String? = null,
    valueColor: Color = CyphraTextMuted,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(icon, null, tint = CyphraAccent, modifier = Modifier.size(20.dp))
            Text(label, style = MaterialTheme.typography.bodyMedium)
        }
        if (value != null) {
            Text(value, style = MaterialTheme.typography.bodySmall.copy(color = valueColor))
        } else {
            Icon(Icons.Default.ChevronRight, null, tint = CyphraTextMuted, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable fun SettingsToggleRow(
    icon: ImageVector,
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(icon, null, tint = CyphraAccent, modifier = Modifier.size(20.dp))
            Text(label, style = MaterialTheme.typography.bodyMedium)
        }
        Switch(
            checked  = checked,
            onCheckedChange = onCheckedChange,
            colors   = SwitchDefaults.colors(
                checkedThumbColor   = Color.White,
                checkedTrackColor   = CyphraAccent,
                uncheckedTrackColor = CyphraBorder,
            ),
        )
    }
}
