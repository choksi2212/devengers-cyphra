/**
 * app.js — Cyphra PWA Main Application
 * All screen logic, state management, and UI orchestration.
 * Feature-complete mirror of the Android app.
 */

// ── State ──────────────────────────────────────────────────────────────────
const State = {
  currentUser: null,
  contacts: [],       // [{ id, username, online }]
  messages: [],       // [{ id, chatId, sender, senderName, text, timestamp, selfDestruct, destructTimer, destructAt, status }]
  activeChat: null,   // contactId string
  selfDestruct: false,
  ws: null,
};

// ── Helpers ────────────────────────────────────────────────────────────────
function $(id) { return document.getElementById(id); }

function showToast(msg, duration = 2500) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), duration);
}

function formatTime(ts) {
  const d = new Date(ts);
  return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
}

function initials(name) {
  return (name || '??').substring(0, 2).toUpperCase();
}

// ── Screen Navigation ──────────────────────────────────────────────────────
const SCREENS = ['login', 'chatlist', 'chat', 'settings'];

function showScreen(name, direction = 'forward') {
  SCREENS.forEach(s => {
    const el = $(`screen-${s}`);
    if (s === name) {
      el.classList.remove('hidden', 'slide-left');
    } else {
      if (direction === 'forward') {
        el.classList.add('hidden');
        el.classList.remove('slide-left');
      } else {
        el.classList.add('slide-left');
        el.classList.remove('hidden');
        setTimeout(() => el.classList.add('hidden'), 310);
      }
    }
  });
}

// ── Overlay helpers ────────────────────────────────────────────────────────
function showOverlay(id) { $(id).classList.remove('hidden'); }
function hideOverlay(id) { $(id).classList.add('hidden'); }

// ── Chat List ──────────────────────────────────────────────────────────────
function renderChatList() {
  const empty = $('chatlist-empty');
  const list  = $('chatlist-items');

  if (State.contacts.length === 0) {
    empty.style.display = 'flex';
    list.style.display = 'none';
    return;
  }

  empty.style.display = 'none';
  list.style.display = 'block';
  list.innerHTML = '';

  State.contacts.forEach(contact => {
    // Find last message
    const msgs = State.messages
      .filter(m => m.chatId === contact.id || (m.sender === contact.id))
      .sort((a, b) => b.timestamp - a.timestamp);
    const lastMsg = msgs[0];

    const item = document.createElement('div');
    item.className = 'chat-item';
    item.innerHTML = `
      <div class="avatar">${initials(contact.username)}</div>
      <div class="chat-item-info">
        <div class="chat-item-name">${contact.username || contact.id.substring(0, 10)}</div>
        <div class="chat-item-preview">${lastMsg ? escapeHtml(lastMsg.text.substring(0, 40)) : 'Tap to start chatting'}</div>
      </div>
      <div class="chat-item-time">${lastMsg ? formatTime(lastMsg.timestamp) : ''}</div>
    `;
    item.addEventListener('click', () => openChat(contact));
    list.appendChild(item);
  });
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str || ''));
  return d.innerHTML;
}

// ── Open Chat ──────────────────────────────────────────────────────────────
function openChat(contact) {
  State.activeChat = contact.id;

  // Update header
  $('chat-contact-name').textContent = contact.username || contact.id;
  $('chat-avatar').textContent = initials(contact.username || contact.id);

  // CRITICAL: Stamp destructAt on pending self-destruct messages
  // (same as Android's setActiveChat / stampDestructAt)
  State.messages = State.messages.map(m => {
    if (m.chatId === contact.id &&
        m.selfDestruct &&
        m.destructAt === null &&
        m.sender !== State.currentUser.id) {
      return { ...m, destructAt: Date.now() + ((m.destructTimer || 10) * 1000) };
    }
    return m;
  });

  // Send read receipts for unread incoming messages
  State.messages
    .filter(m => m.chatId === contact.id && m.sender === contact.id && m.status !== 'read')
    .forEach(m => {
      if (State.ws) State.ws.sendReadReceipt(contact.id, m.id);
      m.status = 'read';
    });

  renderMessages();
  showScreen('chat');

  // Scroll to bottom
  setTimeout(() => {
    const area = $('messages-area');
    area.scrollTop = area.scrollHeight;
  }, 50);
}

// ── Render Messages ────────────────────────────────────────────────────────
function renderMessages() {
  const area = $('messages-area');
  const chatMsgs = State.messages
    .filter(m => m.chatId === State.activeChat || (m.sender === State.activeChat && m.chatId === State.activeChat))
    .sort((a, b) => a.timestamp - b.timestamp);

  area.innerHTML = '';
  chatMsgs.forEach(msg => appendMessageBubble(msg));
}

function appendMessageBubble(msg) {
  const area = $('messages-area');
  const isMine = msg.sender === State.currentUser?.id;

  const row = document.createElement('div');
  row.className = `msg-row ${isMine ? 'mine' : 'theirs'}`;
  row.id = `msg-${msg.id}`;

  const statusHtml = isMine ? `
    <span class="status-icon ${msg.status === 'read' ? 'read' : 'sent'}">
      <svg viewBox="0 0 24 24" fill="currentColor">
        ${msg.status === 'read' || msg.status === 'delivered'
          ? '<path d="M18 7l-1.41-1.41-6.34 6.34 1.41 1.41L18 7zm4.24-1.41L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.41zM.41 13.41L6 19l1.41-1.41L1.83 12 .41 13.41z"/>'
          : '<path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>'}
      </svg>
    </span>` : '';

  const countdownHtml = (msg.selfDestruct && msg.destructAt)
    ? `<span class="countdown" id="countdown-${msg.id}">
         <svg viewBox="0 0 24 24"><path d="M15 1H9v2h6V1zm-4 13h2V8h-2v6zm8.03-6.61l1.42-1.42c-.43-.51-.9-.99-1.41-1.41l-1.42 1.42C16.07 4.74 14.12 4 12 4c-4.97 0-9 4.03-9 9s4.02 9 9 9 9-4.03 9-9c0-2.12-.74-4.07-1.97-5.61zM12 20c-3.87 0-7-3.13-7-7s3.13-7 7-7 7 3.13 7 7-3.13 7-7 7z"/></svg>
         <span>${Math.max(0, Math.ceil((msg.destructAt - Date.now()) / 1000))}s</span>
       </span>` : '';

  const senderLabel = !isMine ? `<div class="bubble-sender">${escapeHtml(msg.senderName || '')}</div>` : '';

  row.innerHTML = `
    <div class="bubble">
      ${senderLabel}
      <div class="bubble-text">${escapeHtml(msg.text)}</div>
      <div class="bubble-meta">
        ${countdownHtml}
        <span class="bubble-lock">
          <svg viewBox="0 0 24 24" fill="currentColor" style="width:9px;height:9px;opacity:0.5"><path d="M12 1C8.676 1 6 3.676 6 7v1H4v15h16V8h-2V7c0-3.324-2.676-6-6-6zm0 2c2.276 0 4 1.724 4 4v1H8V7c0-2.276 1.724-4 4-4z"/></svg>
        </span>
        <span class="bubble-time">${formatTime(msg.timestamp)}</span>
        ${statusHtml}
      </div>
    </div>`;

  area.appendChild(row);

  // Start countdown if needed
  if (msg.selfDestruct && msg.destructAt) {
    startCountdown(msg.id, msg.destructAt);
  }

  return row;
}

// ── Countdown Timers ───────────────────────────────────────────────────────
const _countdownIntervals = {};

function startCountdown(msgId, destructAt) {
  if (_countdownIntervals[msgId]) return;

  _countdownIntervals[msgId] = setInterval(() => {
    const remaining = Math.max(0, Math.ceil((destructAt - Date.now()) / 1000));
    const el = document.querySelector(`#countdown-${msgId} span:last-child`);
    if (el) el.textContent = `${remaining}s`;

    if (remaining <= 0) {
      clearInterval(_countdownIntervals[msgId]);
      delete _countdownIntervals[msgId];
      deleteMessage(msgId);
    }
  }, 500);
}

function deleteMessage(msgId) {
  State.messages = State.messages.filter(m => m.id !== msgId);
  const el = $(`msg-${msgId}`);
  if (el) {
    el.style.transition = 'opacity 0.3s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }
}

// ── Send Message ───────────────────────────────────────────────────────────
async function sendMessage() {
  const input = $('chat-input');
  const text = input.value.trim();
  if (!text || !State.activeChat || !State.currentUser) return;

  const contact = State.contacts.find(c => c.id === State.activeChat);
  const msg = {
    id: CryptoUtils.generateId(),
    chatId: State.activeChat,
    sender: State.currentUser.id,
    senderName: State.currentUser.username,
    text,
    timestamp: Date.now(),
    selfDestruct: State.selfDestruct,
    destructTimer: State.selfDestruct ? 10 : null,
    destructAt: null,   // null on sender side — only recipient stamps it
    status: 'sent',
    encrypted: true,
  };

  // Add to local state
  State.messages.push(msg);
  input.value = '';
  input.style.height = '';

  // Update send button
  $('btn-send').className = 'send-btn inactive';

  // Render
  const area = $('messages-area');
  appendMessageBubble(msg);
  setTimeout(() => { area.scrollTop = area.scrollHeight; }, 50);

  // Broadcast via WebSocket (same as web app's broadcastMessage)
  if (State.ws) {
    const recipientMsg = {
      ...msg,
      senderId: State.currentUser.id,
      recipientId: State.activeChat,
      status: 'sent',
    };
    State.ws.sendMessage(State.activeChat, recipientMsg);
  }

  // Update chat list preview
  renderChatList();
}

// ── Handle Incoming Message ────────────────────────────────────────────────
function handleIncoming(payload) {
  if (payload.type !== 'message') return;
  const data = payload.message;
  if (!data || data.type === 'read_receipt' || data.type === 'delete') return;

  // Extract fields (web app uses both sender and senderId)
  const senderId   = data.sender || data.senderId;
  const senderName = data.senderName || 'Unknown';
  if (!senderId) return;

  // Ignore own echoes
  if (senderId === State.currentUser?.id) return;

  // Deduplicate
  if (State.messages.some(m => m.id === data.id)) return;

  const selfDestruct  = data.selfDestruct === true || data.selfDestruct === 'true';
  const destructTimer = typeof data.destructTimer === 'number' ? data.destructTimer : null;

  const msg = {
    id:           data.id || CryptoUtils.generateId(),
    chatId:       senderId,       // route into sender's thread
    sender:       senderId,
    senderName,
    text:         data.text || '[encrypted]',
    timestamp:    data.timestamp || Date.now(),
    selfDestruct,
    destructTimer,
    // Stamp destructAt if chat is currently open (same as Android)
    destructAt: (selfDestruct && State.activeChat === senderId)
      ? Date.now() + ((destructTimer || 10) * 1000)
      : null,
    status:       'delivered',
    encrypted:    true,
  };

  State.messages.push(msg);

  // Auto-add as contact if not known
  ensureContact(senderId, senderName);

  // If currently in this chat → append bubble immediately
  if (State.activeChat === senderId) {
    const area = $('messages-area');
    appendMessageBubble(msg);
    setTimeout(() => { area.scrollTop = area.scrollHeight; }, 50);
  }

  // Update chat list
  renderChatList();
}

// ── Ensure Contact ─────────────────────────────────────────────────────────
function ensureContact(userId, username) {
  if (State.contacts.some(c => c.id === userId)) return;
  State.contacts.push({ id: userId, username, online: true });
  renderChatList();
}

// ── Add Contact Flow ───────────────────────────────────────────────────────
async function addContact() {
  const emailInput = $('input-contact-email');
  const email = emailInput.value.trim();
  const errEl = $('dialog-error');
  const successEl = $('dialog-success');
  const addBtn = $('btn-dialog-add');

  errEl.textContent = '';
  successEl.style.display = 'none';

  if (!email) { errEl.textContent = 'Please enter an email address'; return; }

  // Check not adding self
  const selfId = await CryptoUtils.deriveUserId(email);
  if (selfId === State.currentUser?.id) {
    errEl.textContent = 'You cannot add yourself as a contact';
    return;
  }

  // Check not already a contact
  if (State.contacts.some(c => c.id === selfId)) {
    errEl.textContent = 'This person is already in your contacts';
    return;
  }

  addBtn.disabled = true;
  addBtn.textContent = 'Finding...';

  try {
    const user = await CyphraApi.findUserByEmail(email);
    if (!user) {
      errEl.textContent = 'No Cyphra account found for that email';
      return;
    }

    // Persist on server
    await CyphraApi.addContactRecord(State.currentUser.id, selfId, user.username);

    // Add locally
    State.contacts.push({ id: selfId, username: user.username, online: false });
    renderChatList();

    // Show success
    $('dialog-success-text').textContent = `${user.username} added successfully!`;
    successEl.style.display = 'flex';

    // Auto-close after 1.2s
    setTimeout(() => {
      hideOverlay('overlay-add-contact');
      emailInput.value = '';
      errEl.textContent = '';
      successEl.style.display = 'none';
    }, 1200);

  } catch (e) {
    errEl.textContent = e.message || 'Failed to add contact';
  } finally {
    addBtn.disabled = false;
    addBtn.textContent = 'ADD';
  }
}

// ── Login Flow ─────────────────────────────────────────────────────────────
async function doLogin() {
  const email    = $('input-email').value.trim();
  const password = $('input-password').value;
  const errEl    = $('login-error');
  const btn      = $('btn-login');

  errEl.textContent = '';

  if (!email || !password) {
    errEl.textContent = 'Please fill in all fields';
    return;
  }

  btn.disabled = true;
  btn.classList.add('loading');
  btn.textContent = 'AUTHENTICATING';

  try {
    const user = await CyphraApi.login(email, password);
    State.currentUser = user;
    localStorage.setItem('cyphra_session', JSON.stringify({
      id: user.id, username: user.username, email: user.email || email
    }));

    // Load contacts
    const contacts = await CyphraApi.getContacts(user.id);
    State.contacts = contacts.map(c => ({
      id: c.contactId || c.id,
      username: c.username,
      online: false
    }));

    // Connect WebSocket
    connectWS(user.id);

    // Update settings screen
    updateSettingsScreen();
    renderChatList();
    showScreen('chatlist');

  } catch (e) {
    errEl.textContent = e.message || 'Authentication failed';
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
    btn.textContent = 'AUTHENTICATE';
  }
}

// ── WebSocket Connect ──────────────────────────────────────────────────────
function connectWS(userId) {
  if (State.ws) State.ws.disconnect();
  State.ws = new CyphraWebSocket(userId, handleIncoming);
  State.ws.onStatusChange(connected => {
    console.log('[App] WS connected:', connected);
  });
  State.ws.connect();
}

// ── Settings Screen ────────────────────────────────────────────────────────
function updateSettingsScreen() {
  const u = State.currentUser;
  if (!u) return;
  $('settings-avatar').textContent = initials(u.username);
  $('settings-username').textContent = u.username || 'Unknown';
  $('settings-email').textContent = u.email || '';
  $('settings-server-url-display').textContent =
    localStorage.getItem('cyphra_server_url') || '192.168.1.6:3001';
}

// ── Logout ─────────────────────────────────────────────────────────────────
function doLogout() {
  if (State.ws) State.ws.disconnect();
  State.currentUser = null;
  State.contacts = [];
  State.messages = [];
  State.activeChat = null;
  localStorage.removeItem('cyphra_session');
  showScreen('login', 'back');
  showToast('Signed out');
}

// ── Auto-resize textarea ───────────────────────────────────────────────────
function autoResize(el) {
  el.style.height = '';
  el.style.height = Math.min(el.scrollHeight, 96) + 'px';
}

// ── PWA Install Banner ─────────────────────────────────────────────────────
let deferredInstall = null;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstall = e;
  // Show install banner after a short delay
  setTimeout(() => $('install-banner').classList.remove('hidden'), 3000);
});

// ── Event Wiring ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

  // ── LOGIN ──
  $('btn-login').addEventListener('click', doLogin);
  $('input-email').addEventListener('keydown', e => { if (e.key === 'Enter') $('input-password').focus(); });
  $('input-password').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

  // ── CHAT LIST ──
  $('btn-add-contact').addEventListener('click', () => {
    $('input-contact-email').value = '';
    $('dialog-error').textContent = '';
    $('dialog-success').style.display = 'none';
    showOverlay('overlay-add-contact');
    setTimeout(() => $('input-contact-email').focus(), 300);
  });
  $('btn-fab').addEventListener('click', () => {
    $('input-contact-email').value = '';
    $('dialog-error').textContent = '';
    $('dialog-success').style.display = 'none';
    showOverlay('overlay-add-contact');
    setTimeout(() => $('input-contact-email').focus(), 300);
  });
  $('btn-settings').addEventListener('click', () => {
    updateSettingsScreen();
    showScreen('settings');
  });

  // ── ADD CONTACT DIALOG ──
  $('btn-dialog-cancel').addEventListener('click', () => hideOverlay('overlay-add-contact'));
  $('overlay-add-contact').addEventListener('click', e => {
    if (e.target === $('overlay-add-contact')) hideOverlay('overlay-add-contact');
  });
  $('btn-dialog-add').addEventListener('click', addContact);
  $('input-contact-email').addEventListener('keydown', e => { if (e.key === 'Enter') addContact(); });

  // ── CHAT ──
  $('btn-back').addEventListener('click', () => {
    State.activeChat = null;
    showScreen('chatlist', 'back');
  });

  const chatInputEl = $('chat-input');
  const sendBtn     = $('btn-send');

  chatInputEl.addEventListener('input', () => {
    autoResize(chatInputEl);
    const hasText = chatInputEl.value.trim().length > 0;
    sendBtn.className = `send-btn ${hasText ? 'active' : 'inactive'}`;
  });

  chatInputEl.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  sendBtn.addEventListener('click', sendMessage);

  // Self-destruct toggle
  $('btn-timer').addEventListener('click', () => {
    State.selfDestruct = !State.selfDestruct;
    $('btn-timer').classList.toggle('active', State.selfDestruct);
    $('sd-banner').classList.toggle('hidden', !State.selfDestruct);
  });
  $('btn-sd-cancel').addEventListener('click', () => {
    State.selfDestruct = false;
    $('btn-timer').classList.remove('active');
    $('sd-banner').classList.add('hidden');
  });

  // ── SETTINGS ──
  $('btn-settings-back').addEventListener('click', () => showScreen('chatlist', 'back'));
  $('btn-logout').addEventListener('click', doLogout);

  $('row-server-config').addEventListener('click', () => {
    $('input-server-url').value = localStorage.getItem('cyphra_server_url') || '192.168.1.6:3001';
    showOverlay('overlay-server');
    setTimeout(() => $('input-server-url').focus(), 300);
  });

  // ── SERVER CONFIG DIALOG ──
  $('btn-server-cancel').addEventListener('click', () => hideOverlay('overlay-server'));
  $('btn-server-save').addEventListener('click', () => {
    const val = $('input-server-url').value.trim();
    if (val) {
      localStorage.setItem('cyphra_server_url', val);
      updateSettingsScreen();
      showToast('Server address saved. Reconnecting...');
      if (State.currentUser) connectWS(State.currentUser.id);
    }
    hideOverlay('overlay-server');
  });
  $('overlay-server').addEventListener('click', e => {
    if (e.target === $('overlay-server')) hideOverlay('overlay-server');
  });

  // ── INSTALL BANNER ──
  $('btn-install').addEventListener('click', async () => {
    if (deferredInstall) {
      deferredInstall.prompt();
      const result = await deferredInstall.userChoice;
      deferredInstall = null;
      $('install-banner').classList.add('hidden');
    } else {
      showToast('On iOS: tap Share → "Add to Home Screen"');
    }
  });

  // ── Resume session ──
  const saved = localStorage.getItem('cyphra_session');
  if (saved) {
    try {
      const user = JSON.parse(saved);
      State.currentUser = user;
      // Reload contacts from server
      CyphraApi.getContacts(user.id).then(contacts => {
        State.contacts = contacts.map(c => ({
          id: c.contactId || c.id,
          username: c.username,
          online: false
        }));
        renderChatList();
      }).catch(() => {});
      connectWS(user.id);
      updateSettingsScreen();
      renderChatList();
      showScreen('chatlist');
    } catch {
      localStorage.removeItem('cyphra_session');
    }
  }

  // ── iOS: Keyboard handling ──
  // Prevent the viewport from bouncing on iOS
  document.addEventListener('touchmove', (e) => {
    if (!e.target.closest('.messages-area, .chat-list-scroll, .settings-scroll')) {
      e.preventDefault();
    }
  }, { passive: false });
});
