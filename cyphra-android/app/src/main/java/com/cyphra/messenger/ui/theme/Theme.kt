package com.cyphra.messenger.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ── Cyphra Colour System ──────────────────────────────────────────────────
// Exact match with the web app's tailwind.config.js tokens

val CyphraBg         = Color(0xFF0A0F1A)   // deepest background
val CyphraSurface    = Color(0xFF111827)   // card / panel surface
val CyphraSurfaceHigh= Color(0xFF1B1F2B)  // elevated surface
val CyphraAccent     = Color(0xFF0EA5E9)   // sky-blue primary
val CyphraAccentHover= Color(0xFF0284C7)
val CyphraBorder     = Color(0xFF1E293B)
val CyphraBorderLight= Color(0xFF334155)
val CyphraTextPrimary   = Color(0xFFDEE2F2)
val CyphraTextSecondary = Color(0xFF94A3B8)
val CyphraTextMuted     = Color(0xFF64748B)
val CyphraSuccess    = Color(0xFF10B981)
val CyphraWarning    = Color(0xFFF59E0B)
val CyphraDanger     = Color(0xFFEF4444)
val CyphraTeal       = Color(0xFF14B8A6)
val CyphraCyan       = Color(0xFF06B6D4)

private val DarkColorScheme = darkColorScheme(
    primary             = CyphraAccent,
    onPrimary           = Color(0xFF00344D),
    primaryContainer    = CyphraAccent,
    onPrimaryContainer  = CyphraTextPrimary,
    secondary           = CyphraTextSecondary,
    onSecondary         = CyphraBg,
    secondaryContainer  = CyphraSurface,
    onSecondaryContainer= CyphraTextSecondary,
    background          = CyphraBg,
    onBackground        = CyphraTextPrimary,
    surface             = CyphraSurface,
    onSurface           = CyphraTextPrimary,
    surfaceVariant      = CyphraSurfaceHigh,
    onSurfaceVariant    = CyphraTextSecondary,
    outline             = CyphraBorder,
    outlineVariant      = CyphraBorderLight,
    error               = CyphraDanger,
    onError             = Color.White,
    tertiary            = CyphraWarning,
)

@Composable
fun CyphraTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography  = CyphraTypography,
        content     = content,
    )
}
