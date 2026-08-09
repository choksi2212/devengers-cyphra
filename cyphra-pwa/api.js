/**
 * api.js — Cyphra PWA REST API Client
 * Mirrors CyphraApiClient.kt exactly — same endpoints, same auth flow.
 */

const CyphraApi = (() => {

  function getBase() {
    const stored = localStorage.getItem('cyphra_server_url') || '192.168.162.129:3001';
    return `http://${stored}`;
  }

  async function request(method, path, body = null) {
    const res = await fetch(`${getBase()}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30000),
    });
    const text = await res.text();
    try { return { ok: res.ok, status: res.status, data: JSON.parse(text) }; }
    catch { return { ok: res.ok, status: res.status, data: { error: text } }; }
  }

  /**
   * Login — mirrors CyphraApiClient.login()
   * 1. Derive userId = SHA-256(email)
   * 2. GET /api/storage/get/user:{userId}
   * 3. Verify passwordHash matches
   */
  async function login(email, password) {
    const userId = await CryptoUtils.deriveUserId(email);
    const resp = await request('GET', `/api/storage/get/user:${userId}`);

    if (!resp.ok || !resp.data?.value) {
      if (resp.status === 404) throw new Error('No account found for this email');
      throw new Error(resp.data?.error || 'Connection failed');
    }

    const user = resp.data.value;

    // Verify password
    const salt = user.salt || '';
    const expectedHash = await CryptoUtils.hashPassword(password, salt);
    if (user.passwordHash !== expectedHash) {
      throw new Error('Incorrect password');
    }

    return user;
  }

  /**
   * Find user by email — mirrors findUserByEmail()
   * Used when adding a contact.
   */
  async function findUserByEmail(email) {
    const userId = await CryptoUtils.deriveUserId(email);
    const resp = await request('GET', `/api/storage/get/user:${userId}`);
    if (!resp.ok || !resp.data?.value) return null;
    return resp.data.value;
  }

  /**
   * Get contacts for a user
   */
  async function getContacts(userId) {
    const resp = await request('GET', `/api/contacts/user/${userId}`);
    if (!resp.ok) return [];
    return resp.data?.contacts || [];
  }

  /**
   * Store a contact relationship
   */
  async function addContactRecord(ownerUserId, contactUserId, contactName) {
    const resp = await request('POST', '/api/contacts', {
      userId: ownerUserId,
      contactId: contactUserId,
      username: contactName,
    });
    return resp.ok;
  }

  /**
   * Ping — health check used before login
   */
  async function ping() {
    const resp = await request('GET', '/api/storage/ping');
    return resp.ok;
  }

  /**
   * Store message in VedDB (for persistence)
   */
  async function storeMessage(message) {
    await request('POST', '/api/messages', message);
  }

  /**
   * Get messages for a chat
   */
  async function getMessages(chatId) {
    const resp = await request('GET', `/api/messages/chat/${chatId}`);
    if (!resp.ok) return [];
    return resp.data?.messages || [];
  }

  return { login, findUserByEmail, getContacts, addContactRecord, ping, storeMessage, getMessages, getBase };
})();
