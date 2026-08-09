/**
 * websocket.js — Cyphra PWA WebSocket Client
 * Mirrors CyphraWebSocket.kt exactly:
 *   - Subscribes to "messages:{userId}" after connect (CRITICAL)
 *   - Handles { type:"update", data:{...} } incoming shape from backend
 *   - Re-wraps for app handler as { type:"message", message:{...} }
 *   - Exponential backoff reconnect
 */

class CyphraWebSocket {
  constructor(userId, onMessage) {
    this.userId = userId;
    this.onMessage = onMessage;
    this.ws = null;
    this.reconnectDelay = 1000;
    this.reconnectTimer = null;
    this.intentionalClose = false;
    this._connected = false;
    this.myKey = `messages:${userId}`;
    this._onStatusChange = null;
  }

  get connected() { return this._connected; }

  connect() {
    this.intentionalClose = false;
    const stored = localStorage.getItem('cyphra_server_url') || '192.168.162.129:3001';
    const url = `ws://${stored}/ws`;

    console.log('[WS] Connecting to', url);
    try { this.ws = new WebSocket(url); }
    catch (e) { console.error('[WS] Failed to create socket:', e); this._scheduleReconnect(); return; }

    this.ws.onopen = () => {
      console.log('[WS] Connected, subscribing to', this.myKey);
      this.reconnectDelay = 1000;
      this._connected = true;
      if (this._onStatusChange) this._onStatusChange(true);

      // 1. Announce presence
      this._send({ type: 'presence', userId: this.userId, status: 'online' });
      // 2. Subscribe — REQUIRED to receive any messages
      this._send({ type: 'subscribe', key: this.myKey });
    };

    this.ws.onmessage = (event) => {
      console.log('[WS] <<<', event.data);
      let payload;
      try { payload = JSON.parse(event.data); } catch { return; }

      switch (payload.type) {
        case 'connected':
          // Re-subscribe in case server restarted
          this._send({ type: 'subscribe', key: this.myKey });
          break;

        case 'subscribed':
          console.log('[WS] Subscribed confirmed:', payload.key);
          break;

        case 'update':
          // This is an incoming message from another user:
          // { type:"update", key:"messages:{ourId}", data: { messagePayload } }
          if (payload.key === this.myKey && payload.data) {
            const data = payload.data;
            // Ignore read receipts
            if (data.type === 'read_receipt' || data.type === 'delete') return;
            // Re-wrap to match Android's handleIncoming shape
            this.onMessage({ type: 'message', message: data });
          }
          break;

        case 'delivered':
          console.log('[WS] Delivery confirmed for', payload.messageId);
          break;

        case 'error':
          console.warn('[WS] Server error:', payload.message);
          break;
      }
    };

    this.ws.onclose = () => {
      this._connected = false;
      if (this._onStatusChange) this._onStatusChange(false);
      if (!this.intentionalClose) this._scheduleReconnect();
    };

    this.ws.onerror = (e) => {
      console.warn('[WS] Error:', e);
      this._connected = false;
    };
  }

  sendMessage(recipientId, message) {
    this._send({
      type: 'message',
      recipientId,
      message,
    });
  }

  sendReadReceipt(senderId, messageId) {
    this._send({
      type: 'message',
      recipientId: senderId,
      message: { type: 'read_receipt', messageId },
    });
  }

  _send(data) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  _scheduleReconnect() {
    const delay = this.reconnectDelay;
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000);
    console.log(`[WS] Reconnecting in ${delay}ms`);
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  disconnect() {
    this.intentionalClose = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) this.ws.close(1000, 'User logged out');
  }

  onStatusChange(cb) { this._onStatusChange = cb; }
}
