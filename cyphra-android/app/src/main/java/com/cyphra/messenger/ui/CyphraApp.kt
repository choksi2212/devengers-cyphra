package com.cyphra.messenger.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.cyphra.messenger.ui.screens.*

sealed class Screen(val route: String) {
    object Login    : Screen("login")
    object ChatList : Screen("chats")
    object Chat     : Screen("chat/{contactId}") {
        fun withId(id: String) = "chat/$id"
    }
    object Settings : Screen("settings")
}

@Composable
fun CyphraApp(vm: MessengerViewModel = viewModel()) {
    val uiState by vm.uiState.collectAsState()
    val nav = rememberNavController()

    val start = if (uiState.isAuthenticated) Screen.ChatList.route else Screen.Login.route

    NavHost(navController = nav, startDestination = start) {

        composable(Screen.Login.route) {
            LoginScreen(
                vm = vm,
                onLoginSuccess = {
                    nav.navigate(Screen.ChatList.route) {
                        popUpTo(Screen.Login.route) { inclusive = true }
                    }
                }
            )
        }

        composable(Screen.ChatList.route) {
            ChatListScreen(
                vm = vm,
                onChatOpen = { contactId, contactName ->
                    vm.setActiveChat(contactId)
                    nav.navigate(Screen.Chat.withId(contactId))
                },
                onSettingsClick = { nav.navigate(Screen.Settings.route) }
            )
        }

        composable(
            Screen.Chat.route,
            arguments = listOf(navArgument("contactId") { type = NavType.StringType })
        ) { back ->
            val contactId = back.arguments?.getString("contactId") ?: return@composable
            ChatScreen(
                vm        = vm,
                contactId = contactId,
                onBack    = { nav.popBackStack() },
            )
        }

        composable(Screen.Settings.route) {
            SettingsScreen(
                vm     = vm,
                onBack = { nav.popBackStack() }
            )
        }
    }
}
