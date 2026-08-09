package com.cyphra.messenger.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.*
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.*
import com.cyphra.messenger.ui.MessengerViewModel
import com.cyphra.messenger.ui.theme.*

@Composable
fun LoginScreen(vm: MessengerViewModel, onLoginSuccess: () -> Unit) {
    val uiState by vm.uiState.collectAsState()
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    val passwordFocus = remember { FocusRequester() }
    val focusMgr = LocalFocusManager.current

    // Navigate on successful auth
    LaunchedEffect(uiState.isAuthenticated) {
        if (uiState.isAuthenticated) onLoginSuccess()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(CyphraBg),
        contentAlignment = Alignment.Center,
    ) {
        // Background glow orb
        Box(
            modifier = Modifier
                .size(300.dp)
                .offset(y = (-80).dp)
                .background(
                    brush = Brush.radialGradient(listOf(CyphraAccent.copy(alpha = 0.06f), Color.Transparent)),
                    shape = RoundedCornerShape(50),
                )
                .blur(60.dp)
        )

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(0.dp),
        ) {
            // ── Logo ──────────────────────────────────────────────────────
            Spacer(Modifier.height(40.dp))
            Box(
                modifier = Modifier
                    .size(72.dp)
                    .background(
                        brush = Brush.radialGradient(listOf(CyphraAccent.copy(0.15f), Color.Transparent)),
                        shape = RoundedCornerShape(16.dp),
                    )
                    .border(1.dp, CyphraAccent.copy(0.3f), RoundedCornerShape(16.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = "Cyphra Logo",
                    tint   = CyphraAccent,
                    modifier = Modifier.size(36.dp),
                )
            }

            Spacer(Modifier.height(20.dp))
            Text(
                text  = "CYPHRA",
                style = MaterialTheme.typography.displayLarge.copy(
                    fontSize     = 34.sp,
                    fontWeight   = FontWeight.ExtraBold,
                    letterSpacing= 6.sp,
                    color        = CyphraTextPrimary,
                ),
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text  = "Military-Grade Encrypted Messenger",
                style = MaterialTheme.typography.bodySmall.copy(color = CyphraTextMuted),
                textAlign = TextAlign.Center,
            )

            Spacer(Modifier.height(48.dp))

            // ── Username ──────────────────────────────────────────────────
            CyphraTextField(
                value        = email,
                onValueChange= { email = it },
                label        = "EMAIL",
                leadingIcon  = { Icon(Icons.Default.Person, null, tint = CyphraTextMuted, modifier = Modifier.size(18.dp)) },
                keyboardOptions = KeyboardOptions(
                    imeAction = ImeAction.Next,
                    keyboardType = KeyboardType.Email,
                ),
                keyboardActions = KeyboardActions(onNext = { passwordFocus.requestFocus() }),
            )

            Spacer(Modifier.height(12.dp))

            // ── Password ──────────────────────────────────────────────────
            CyphraTextField(
                value         = password,
                onValueChange = { password = it },
                label         = "PASSWORD",
                modifier      = Modifier.focusRequester(passwordFocus),
                leadingIcon   = { Icon(Icons.Default.Lock, null, tint = CyphraTextMuted, modifier = Modifier.size(18.dp)) },
                trailingIcon  = {
                    IconButton(onClick = { showPassword = !showPassword }) {
                        Icon(
                            if (showPassword) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            null, tint = CyphraTextMuted, modifier = Modifier.size(18.dp),
                        )
                    }
                },
                visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done, keyboardType = KeyboardType.Password),
                    keyboardActions = KeyboardActions(onDone = {
                        focusMgr.clearFocus()
                        if (email.isNotBlank() && password.isNotBlank()) vm.login(email, password)
                    }),
            )

            // Error
            AnimatedVisibility(visible = uiState.error != null) {
                Text(
                    text   = uiState.error ?: "",
                    color  = CyphraDanger,
                    style  = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            Spacer(Modifier.height(28.dp))

            // ── Authenticate button ───────────────────────────────────────
            Button(
                onClick = {
                    focusMgr.clearFocus()
                    vm.login(email.trim(), password)

                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape  = RoundedCornerShape(8.dp),
                colors = ButtonDefaults.buttonColors(containerColor = CyphraAccent),
                enabled = !uiState.isLoading,
            ) {
                if (uiState.isLoading) {
                    CircularProgressIndicator(color = Color.White, modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(
                        "AUTHENTICATE",
                        fontWeight   = FontWeight.Bold,
                        letterSpacing= 2.sp,
                        color        = Color(0xFF00344D),
                    )
                }
            }

            Spacer(Modifier.height(24.dp))

            // ── Footer ────────────────────────────────────────────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center,
            ) {
                Box(Modifier.size(6.dp).background(CyphraSuccess, androidx.compose.foundation.shape.CircleShape))
                Spacer(Modifier.width(6.dp))
                Text("End-to-end encrypted · Zero knowledge", style = MaterialTheme.typography.labelSmall)
            }
            Spacer(Modifier.height(40.dp))
        }
    }
}

@Composable
fun CyphraTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    leadingIcon: @Composable (() -> Unit)? = null,
    trailingIcon: @Composable (() -> Unit)? = null,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
) {
    OutlinedTextField(
        value              = value,
        onValueChange      = onValueChange,
        modifier           = modifier.fillMaxWidth(),
        label              = {
            Text(label, style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 1.sp))
        },
        leadingIcon        = leadingIcon,
        trailingIcon       = trailingIcon,
        visualTransformation = visualTransformation,
        keyboardOptions    = keyboardOptions,
        keyboardActions    = keyboardActions,
        singleLine         = true,
        shape              = RoundedCornerShape(8.dp),
        colors             = OutlinedTextFieldDefaults.colors(
            focusedBorderColor   = CyphraAccent,
            unfocusedBorderColor = CyphraBorder,
            focusedLabelColor    = CyphraAccent,
            unfocusedLabelColor  = CyphraTextMuted,
            focusedTextColor     = CyphraTextPrimary,
            unfocusedTextColor   = CyphraTextPrimary,
            cursorColor          = CyphraAccent,
            focusedContainerColor   = CyphraSurface,
            unfocusedContainerColor = CyphraBg,
        ),
    )
}
