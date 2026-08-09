package com.cyphra.messenger.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Use system default sans-serif (matches Inter closely on Android)
// For exact Inter: download Inter .ttf files to res/font/ and reference here
val InterFamily = FontFamily.Default
val MonoFamily  = FontFamily.Monospace

val CyphraTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = InterFamily,
        fontWeight = FontWeight.Bold,
        fontSize   = 32.sp,
        letterSpacing = (-0.5).sp,
        color = CyphraTextPrimary,
    ),
    headlineMedium = TextStyle(
        fontFamily = InterFamily,
        fontWeight = FontWeight.SemiBold,
        fontSize   = 18.sp,
        color = CyphraTextPrimary,
    ),
    titleMedium = TextStyle(
        fontFamily = InterFamily,
        fontWeight = FontWeight.Medium,
        fontSize   = 15.sp,
        color = CyphraTextPrimary,
    ),
    bodyMedium = TextStyle(
        fontFamily = InterFamily,
        fontWeight = FontWeight.Normal,
        fontSize   = 14.sp,
        lineHeight = 20.sp,
        color = CyphraTextPrimary,
    ),
    bodySmall = TextStyle(
        fontFamily = InterFamily,
        fontWeight = FontWeight.Normal,
        fontSize   = 12.sp,
        color = CyphraTextSecondary,
    ),
    labelSmall = TextStyle(
        fontFamily = MonoFamily,
        fontWeight = FontWeight.Normal,
        fontSize   = 10.sp,
        letterSpacing = 0.5.sp,
        color = CyphraTextMuted,
    ),
)
