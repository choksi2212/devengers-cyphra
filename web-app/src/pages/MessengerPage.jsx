import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Send, Lock, Shield, Clock, Trash2, Users, Plus, CheckCircle, Timer, Activity, X, Search, Copy, Check, CheckCheck } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import useStore from '../store/useStore'
import cryptoService from '../services/crypto.service'
import veddbService from '../services/veddb.service'
import mlSimulationService from '../services/ml-intelligence.service'
import MLDashboard from '../components/MLDashboard'

function CountdownTimer({ destructAt, messageId, onExpire, hidden }) {
  const [timeLeft, setTimeLeft] = useState(0)

  useEffect(() => {
    const updateTimer = () => {
      const now = Date.now()
      const remaining = Math.max(0, Math.ceil((destructAt - now) / 1000))
      setTimeLeft(remaining)
      if (remaining === 0 && onExpire) onExpire(messageId)
    }
    updateTimer()
    const interval = setInterval(updateTimer, 1000)
    return () => clearInterval(interval)
  }, [destructAt, messageId, onExpire])

  // Hidden mode: timer still runs but nothing visible to receiver
  if (hidden) return null

  return (
    <div className="flex items-center gap-1 text-cyphra-warning">
      <Timer className="w-3 h-3" strokeWidth={1.5} />
      <span className="font-mono text-[11px]">{timeLeft}s</span>
    </div>
  )
}

export default function MessengerPage() {
  const navigate = useNavigate()
  const messagesEndRef = useRef(null)

  const { currentUser, messages, addMessage, deleteMessage, updateMessageStatus, stampDestructAt, activeChat, setActiveChat, contacts, addContact } = useStore()
  const [messageText, setMessageText] = useState('')
  const [selfDestruct, setSelfDestruct] = useState(false)
  const DESTRUCT_TIMER = 10
  const [sending, setSending] = useState(false)
  const [showAddContact, setShowAddContact] = useState(false)
  const [ghostCode, setGhostCode] = useState('')
  const [myGhostCode, setMyGhostCode] = useState('')
  const [showMLDashboard, setShowMLDashboard] = useState(false)
  const [mlAnalysis, setMlAnalysis] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')

  // Mock contacts if none exist
  const mockContacts = contacts.length > 0 ? contacts : [
    { id: 'contact_1', username: 'Alpha Team', publicKey: null, verified: true, online: true },
    { id: 'contact_2', username: 'Bravo Squad', publicKey: null, verified: true, online: false },
    { id: 'contact_3', username: 'Command Center', publicKey: null, verified: true, online: true },
  ]

  const currentChat = activeChat || mockContacts[0]?.id

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  // ── Self-destruct: stamp destructAt the moment the recipient opens the chat ──
  // The sender never sets destructAt. The receiver gets destructAt:null on arrival.
  // Only here — when activeChat changes and the chat is opened — do we start the clock.
  useEffect(() => {
    if (!currentChat) return
    const pending = messages.filter(
      m =>
        m.chatId === currentChat &&     // message is in this chat
        m.selfDestruct &&               // it IS a self-destruct message
        m.destructAt === null &&        // countdown not yet started
        m.sender !== currentUser?.id    // it's NOT our own outgoing message
    )
    pending.forEach(m => {
      const timer = m.destructTimer || 10
      stampDestructAt(m.id, Date.now() + timer * 1000)
    })
  }, [activeChat, currentChat])  // runs every time user switches chat

  useEffect(() => {
    // Set active chat if none
    if (!activeChat && mockContacts.length > 0) {
      setActiveChat(mockContacts[0].id)
    }
    
    // Generate user's unique Ghost Code
    if (currentUser) {
      const code = generateGhostCode(currentUser.id, currentUser.username)
      setMyGhostCode(code)
      
      // Subscribe to real-time messages for this user
      subscribeToMessages()
    }
    
    // DEMO MODE: Keyboard shortcuts for attack simulation
    const handleKeyPress = (e) => {
      // Ctrl + Shift + P = Port Scan
      if (e.ctrlKey && e.shiftKey && e.key === 'P') {
        e.preventDefault()
        console.log('DEMO: Triggering Port Scan attack')
        mlSimulationService.triggerAttackScenario('portscan')
        // Silent trigger - no alert
      }
      // Ctrl + Shift + D = DDoS
      else if (e.ctrlKey && e.shiftKey && e.key === 'D') {
        e.preventDefault()
        console.log('DEMO: Triggering DDoS attack')
        mlSimulationService.triggerAttackScenario('ddos')
        // Silent trigger - no alert
      }
      // Ctrl + Shift + B = Brute Force
      else if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault()
        console.log('DEMO: Triggering Brute Force attack')
        mlSimulationService.triggerAttackScenario('bruteforce')
        // Silent trigger - no alert
      }
      // Ctrl + Shift + X = Stop Attack
      else if (e.ctrlKey && e.shiftKey && e.key === 'X') {
        e.preventDefault()
        console.log('DEMO: Stopping attack')
        mlSimulationService.stopAttackScenario()
        // Silent trigger - no alert
      }
    }

    window.addEventListener('keydown', handleKeyPress)
    
    return () => {
      // Cleanup: unsubscribe when component unmounts
      if (currentUser) {
        veddbService.unsubscribe(`messages:${currentUser.id}`)
      }
      window.removeEventListener('keydown', handleKeyPress)
    }
  }, [])

  // Subscribe to real-time incoming messages
  const subscribeToMessages = async () => {
    if (!currentUser) return

    const messagesKey = `messages:${currentUser.id}`
    
    // Register delivery/read status callback
    veddbService.onStatusUpdate = (messageId, status) => {
      console.log(`Message ${messageId} status: ${status}`)
      useStore.getState().updateMessageStatus(messageId, status)
    }
    
    await veddbService.subscribe(messagesKey, (incomingMessage) => {
      console.log('New message received:', incomingMessage)
      
      // Handle delete commands from other device
      if (incomingMessage.type === 'delete') {
        console.log(`Remote delete for message: ${incomingMessage.messageId}`)
        deleteMessage(incomingMessage.messageId)
        return
      }
      
      // Handle read receipts from recipient
      if (incomingMessage.type === 'read_receipt') {
        console.log(`Read receipt for message: ${incomingMessage.messageId}`)
        useStore.getState().updateMessageStatus(incomingMessage.messageId, 'read')
        return
      }
      
      const senderId = incomingMessage.senderId || incomingMessage.sender
      const senderName = incomingMessage.senderName
      
      // Auto-add sender as contact if not already in contacts list
      // This ensures they appear in the sidebar with their username
      const currentContacts = useStore.getState().contacts
      const alreadyExists = currentContacts.some(c => c.id === senderId)
      if (!alreadyExists && senderId && senderId !== currentUser.id) {
        addContact({
          id: senderId,
          username: senderName || `User-${senderId.substring(0, 8)}`,
          publicKey: null,
          verified: true,
          online: true,
        })
        console.log(`Auto-added contact: ${senderName} (${senderId})`)
      }
      
      // chatId = sender's ID so message lands in the right conversation
      const messageWithChatId = {
        ...incomingMessage,
        chatId: senderId,
        // destructAt is intentionally null here.
        // The countdown starts ONLY when the recipient opens this chat
        // (see the activeChat useEffect above).
        destructAt: null,
      }
      
      console.log('Message with chatId:', messageWithChatId)
      
      // Add message to state
      addMessage(messageWithChatId)

      // Edge case: if this chat is ALREADY open, start the countdown immediately.
      // (The activeChat useEffect only fires on chat-switch, not on message arrival.)
      if (
        messageWithChatId.selfDestruct &&
        messageWithChatId.destructAt === null &&
        useStore.getState().activeChat === senderId
      ) {
        const timer = messageWithChatId.destructTimer || 10
        stampDestructAt(messageWithChatId.id, Date.now() + timer * 1000)
      }
      
      // Send read receipt back to sender via WebSocket
      if (senderId && veddbService.ws && veddbService.ws.readyState === WebSocket.OPEN) {
        veddbService.ws.send(JSON.stringify({
          type: 'message',
          recipientId: senderId,
          message: { type: 'read_receipt', messageId: messageWithChatId.id }
        }))
      }
      
      // Show browser notification
      showNotification(messageWithChatId)
      
      // Auto-set active chat to sender
      setActiveChat(messageWithChatId.chatId)
    })
  }

  // Show browser notification for new message
  const showNotification = (message) => {
    // Request notification permission if not granted
    if (Notification.permission === 'default') {
      Notification.requestPermission()
    }

    if (Notification.permission === 'granted') {
      const senderName = getContactName(message.senderId)
      const notification = new Notification(`New message from ${senderName}`, {
        body: message.encrypted ? 'Encrypted message' : message.content,
        icon: '/manifest.json',
        badge: '/manifest.json',
        tag: message.id,
      })

      notification.onclick = () => {
        window.focus()
        setActiveChat(message.senderId)
        notification.close()
      }
    }
  }

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  // Broadcast message to recipient via WebSocket
  const broadcastMessage = async (message, recipientId) => {
    try {
      console.log('Broadcasting message...')
      console.log(`   Recipient ID: ${recipientId}`)
      console.log(`   Sender ID: ${currentUser.id}`)
      console.log(`   Message ID: ${message.id}`)
      
      // Send message to recipient's message queue
      const recipientMessagesKey = `messages:${recipientId}`
      
      // Create message for recipient
      const recipientMessage = {
        ...message,
        senderId: currentUser.id,
        recipientId: recipientId,
        status: 'sent'
      }

      // Store message for recipient in VedDB
      console.log(`Storing message for recipient: ${recipientMessagesKey}:${message.id}`)
      await veddbService.set(`${recipientMessagesKey}:${message.id}`, recipientMessage)
      console.log('Message stored in VedDB')

      // Broadcast via WebSocket if connected
      if (veddbService.ws && veddbService.ws.readyState === WebSocket.OPEN) {
        const wsMessage = {
          type: 'message',
          recipientId: recipientId,
          message: recipientMessage
        }
        console.log('Sending via WebSocket:', wsMessage)
        veddbService.ws.send(JSON.stringify(wsMessage))
        console.log(`Message broadcasted to ${recipientId}`)
      } else {
        console.error(`WebSocket not connected. State: ${veddbService.ws?.readyState}`)
      }
    } catch (error) {
      console.error('Failed to broadcast message:', error)
    }
  }

  const handleSendMessage = async () => {
    if (!messageText.trim() || sending) return

    setSending(true)

    try {
      // Encrypt message
      const encrypted = await cryptoService.encryptMessage(messageText, currentChat)

      // Create message object
      const message = {
        id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        chatId: currentChat,
        sender: currentUser.id,
        senderName: currentUser.username,
        text: messageText,
        encrypted: true,
        encryptedData: encrypted,
        timestamp: Date.now(),
        selfDestruct: selfDestruct,
        destructTimer: selfDestruct ? DESTRUCT_TIMER : null,
        // Sender's copy: destructAt stays null.
        // The sender sees no countdown — only the recipient triggers it on chat open.
        destructAt: null,
        delivered: true,
        read: false,
        status: 'sent',
      }

      // ML Analysis: Analyze message for threats
      const analysis = await mlSimulationService.analyzeMessage(message)
      console.log('ML Analysis:', analysis)
      setMlAnalysis(analysis)

      // Add to state (for sender)
      addMessage(message)

      // Store in VedDB (for sender)
      await veddbService.storeMessage(message)

      // Broadcast message to recipient via WebSocket
      await broadcastMessage(message, currentChat)

      // Clear input
      setMessageText('')

      // Self-destruct logging (actual deletion handled by CountdownTimer component)
      if (selfDestruct) {
        console.log(`Message will self-destruct in ${DESTRUCT_TIMER} seconds`)
        console.log(`Countdown started for message: ${message.id}`)
      }

    } catch (error) {
      console.error('Failed to send message:', error)
    } finally {
      setSending(false)
    }
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSendMessage()
    }
  }

  const getMessagesForChat = () => {
    return messages.filter(m => m.chatId === currentChat).sort((a, b) => a.timestamp - b.timestamp)
  }

  const formatTime = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  }

  const getContactName = (contactId) => {
    const contact = mockContacts.find(c => c.id === contactId)
    return contact?.username || 'Unknown'
  }

  const handleMessageExpire = async (messageId) => {
    console.log(`Message expired: ${messageId}`)
    
    // Find the message before deleting (to get recipient/sender info)
    const expiredMsg = messages.find(m => m.id === messageId)
    
    // Delete from local state
    deleteMessage(messageId)
    
    // Delete from VedDB (try both key formats)
    try {
      // Delete sender's stored copy
      await veddbService.delete(`messages:${currentUser.id}:${messageId}`)
      // Delete recipient's stored copy
      if (expiredMsg) {
        const otherId = expiredMsg.sender === currentUser.id
          ? expiredMsg.chatId
          : expiredMsg.sender || expiredMsg.senderId
        if (otherId) {
          await veddbService.delete(`messages:${otherId}:${messageId}`)
        }
      }
      console.log(`Expired message ${messageId} destroyed from database`)
    } catch (error) {
      console.error('Failed to destroy expired message from DB:', error)
    }
    
    // Broadcast delete to the other device via WebSocket
    if (expiredMsg && veddbService.ws && veddbService.ws.readyState === WebSocket.OPEN) {
      const otherId = expiredMsg.sender === currentUser.id
        ? expiredMsg.chatId
        : expiredMsg.sender || expiredMsg.senderId
      if (otherId) {
        veddbService.ws.send(JSON.stringify({
          type: 'message',
          recipientId: otherId,
          message: { type: 'delete', messageId: messageId }
        }))
        console.log(`Delete broadcast sent to ${otherId}`)
      }
    }
  }

  // Generate unique Ghost Code for user
  // Format: GHOST-{shortId} where shortId is derived from full userId
  const generateGhostCode = (userId, username) => {
    // Create a unique short code from the full user ID
    // Use first 4 and last 4 chars to ensure uniqueness
    const part1 = userId.substring(0, 4).toUpperCase()
    const part2 = userId.substring(userId.length - 4).toUpperCase()
    const ghostCode = `GHOST-${part1}-${part2}`
    
    // Store mapping in VedDB for reverse lookup (async, fire-and-forget)
    veddbService.set(`ghostcode:${ghostCode}`, {
      userId: userId,
      username: username,
      createdAt: Date.now()
    }).then(() => {
      console.log(`Ghost Code stored: ${ghostCode} -> ${userId}`)
    }).catch(err => console.error('Failed to store ghost code mapping:', err))
    
    return ghostCode
  }

  // Decode Ghost Code to get ACTUAL user ID from VedDB
  const decodeGhostCode = async (ghostCode) => {
    try {
      // Query VedDB for the mapping
      const mapping = await veddbService.get(`ghostcode:${ghostCode}`)
      
      if (mapping && mapping.userId) {
        console.log(`Decoded Ghost Code: ${ghostCode} -> User ID: ${mapping.userId}`)
        return mapping.userId  // Return actual user ID!
      }
      
      console.error(`Ghost Code not found: ${ghostCode}`)
      return null
    } catch (error) {
      console.error('Failed to decode ghost code:', error)
      return null
    }
  }

  // Add contact by Ghost Code
  const handleAddContact = async () => {
    if (!ghostCode.trim()) return

    try {
      // Decode Ghost Code to get actual user ID (ASYNC - queries VedDB)
      const userId = await decodeGhostCode(ghostCode)
      
      if (!userId) {
        alert('Invalid Ghost Code or user not found.')
        return
      }

      // Query VedDB for user details
      const userMapping = await veddbService.get(`ghostcode:${ghostCode}`)
      const username = userMapping?.username || `User-${ghostCode.split('-')[1]}`
      
      const newContact = {
        id: userId, // ACTUAL user ID from VedDB mapping
        userId: currentUser.id, // Owner of this contact record
        username: username,
        ghostCode: ghostCode,
        publicKey: null,
        verified: true,  // Verified since we found them in VedDB
        online: false,
        addedAt: Date.now()
      }

      // Store in VedDB
      await veddbService.storeContact(newContact)
      
      // Add to state
      addContact(newContact)

      // Success
      console.log(`Contact added: ${newContact.username} (ID: ${userId})`)
      console.log('Contact details:', newContact)
      alert(`Contact added: ${username}. You can now chat in real-time.`)
      
      setGhostCode('')
      setShowAddContact(false)
    } catch (error) {
      console.error('Failed to add contact:', error)
      alert('Failed to add contact. Please check the Ghost Code and try again.')
    }
  }

  // Copy Ghost Code to clipboard
  const copyGhostCode = () => {
    navigator.clipboard.writeText(myGhostCode)
  }

  return (
    <div className="h-full flex bg-cyphra-bg">
      {/* Contacts Panel */}
      <div className="w-72 bg-cyphra-surface border-r border-cyphra-border flex flex-col flex-shrink-0">
        <div className="p-4 border-b border-cyphra-border">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-cyphra-text-primary">Secure Chats</h2>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setShowAddContact(true)}
                className="p-1.5 rounded text-cyphra-text-muted hover:text-cyphra-accent hover:bg-cyphra-accent-muted transition-colors"
                title="Add Contact"
              >
                <Plus className="w-4 h-4" strokeWidth={1.5} />
              </button>
              <button
                onClick={() => setShowMLDashboard(!showMLDashboard)}
                className={`p-1.5 rounded transition-colors ${
                  showMLDashboard
                    ? 'bg-cyphra-accent-muted text-cyphra-accent'
                    : 'text-cyphra-text-muted hover:text-cyphra-accent hover:bg-cyphra-accent-muted'
                }`}
                title="AI/ML Dashboard"
              >
                <Activity className="w-4 h-4" strokeWidth={1.5} />
              </button>
            </div>
          </div>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyphra-text-muted" strokeWidth={1.5} />
            <input
              type="text"
              placeholder="Search contacts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input-primary pl-9 py-2 text-xs"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {mockContacts.filter(c => !searchQuery || c.username?.toLowerCase().includes(searchQuery.toLowerCase()) || c.ghostCode?.toLowerCase().includes(searchQuery.toLowerCase())).map((contact) => (
            <button
              key={contact.id}
              onClick={() => setActiveChat(contact.id)}
              className={`w-full px-4 py-3 flex items-center gap-3 hover:bg-cyphra-bg transition-colors ${
                currentChat === contact.id ? 'bg-cyphra-bg border-l-2 border-cyphra-accent' : 'border-l-2 border-transparent'
              }`}
            >
              <div className="relative flex-shrink-0">
                <div className="w-9 h-9 bg-cyphra-border rounded-full flex items-center justify-center">
                  <span className="text-xs font-medium text-cyphra-text-secondary">
                    {contact.username.charAt(0).toUpperCase()}
                  </span>
                </div>
                {contact.online && (
                  <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-cyphra-success rounded-full border-2 border-cyphra-surface" />
                )}
              </div>
              <div className="flex-1 text-left min-w-0">
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-medium text-cyphra-text-primary truncate">{contact.username}</p>
                  {contact.verified && (
                    <CheckCircle className="w-3 h-3 text-cyphra-accent flex-shrink-0" strokeWidth={1.5} />
                  )}
                </div>
                <p className="text-[11px] text-cyphra-text-muted mt-0.5">
                  {contact.online ? 'Online' : 'Offline'}
                </p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Chat Header */}
        <div className="border-b border-cyphra-border px-6 py-3.5 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-cyphra-border rounded-full flex items-center justify-center">
              <span className="text-xs font-medium text-cyphra-text-secondary">
                {getContactName(currentChat).charAt(0).toUpperCase()}
              </span>
            </div>
            <div>
              <h3 className="text-sm font-medium text-cyphra-text-primary">{getContactName(currentChat)}</h3>
              <div className="flex items-center gap-1.5 mt-0.5">
                <div className="status-dot-active" />
                <span className="text-[11px] text-cyphra-text-muted">Encrypted channel</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="badge-success text-[11px]">
              <Lock className="w-3 h-3" strokeWidth={1.5} />
              AES-256-GCM
            </span>
            <span className="badge-info text-[11px]">
              <Shield className="w-3 h-3" strokeWidth={1.5} />
              Kyber-1024
            </span>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-3">
          <AnimatePresence>
            {getMessagesForChat().length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <Lock className="w-10 h-10 text-cyphra-text-muted mx-auto mb-3" strokeWidth={1} />
                  <p className="text-sm text-cyphra-text-muted mb-1">No messages yet</p>
                  <p className="text-xs text-cyphra-text-muted">Send your first encrypted message</p>
                </div>
              </div>
            ) : (
              getMessagesForChat().map((message) => {
                const isMine = message.sender === currentUser.id
                return (
                  <motion.div
                    key={message.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.2 }}
                    className={`flex ${isMine ? 'justify-end' : 'justify-start'}`}
                  >
                    <div className={`max-w-[420px] rounded px-3.5 py-2.5 ${
                      isMine ? 'bg-cyphra-accent text-white' : 'bg-cyphra-surface border border-cyphra-border text-cyphra-text-primary'
                    }`}>
                      {!isMine && (
                        <p className="text-[11px] font-medium text-cyphra-accent mb-1">{message.senderName}</p>
                      )}
                      <p className="text-sm leading-relaxed">{message.text}</p>
                      <div className={`flex items-center gap-2 mt-1.5 text-[11px] ${isMine ? 'text-white/60' : 'text-cyphra-text-muted'}`}>
                        <span>{formatTime(message.timestamp)}</span>
                        {message.encrypted && <Lock className="w-2.5 h-2.5" strokeWidth={1.5} />}
                        {message.selfDestruct && message.destructAt && (
                          <CountdownTimer
                            destructAt={message.destructAt}
                            messageId={message.id}
                            onExpire={handleMessageExpire}
                            hidden={!isMine}
                          />
                        )}
                        {isMine && (
                          <span className="flex items-center" title={message.status === 'read' ? 'Read' : message.status === 'delivered' ? 'Delivered' : 'Sent'}>
                            {message.status === 'read' ? (
                              <CheckCheck className="w-3.5 h-3.5 text-cyan-400" strokeWidth={2} />
                            ) : message.status === 'delivered' ? (
                              <CheckCheck className="w-3.5 h-3.5" strokeWidth={2} />
                            ) : (
                              <Check className="w-3.5 h-3.5" strokeWidth={2} />
                            )}
                          </span>
                        )}
                      </div>
                    </div>
                  </motion.div>
                )
              })
            )}
          </AnimatePresence>
          <div ref={messagesEndRef} />
        </div>

        {/* Self-Destruct Banner */}
        {selfDestruct && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="mx-6 mb-2"
          >
            <div className="flex items-center justify-between px-3 py-2 rounded border border-cyphra-warning/20 bg-cyphra-warning-muted">
              <div className="flex items-center gap-2">
                <Timer className="w-3.5 h-3.5 text-cyphra-warning" strokeWidth={1.5} />
                <span className="text-xs text-cyphra-warning">Self-destruct: {DESTRUCT_TIMER}s</span>
              </div>
              <button
                onClick={() => setSelfDestruct(false)}
                className="text-[11px] text-cyphra-text-muted hover:text-cyphra-text-secondary"
              >
                Cancel
              </button>
            </div>
          </motion.div>
        )}

        {/* Message Input */}
        <div className="border-t border-cyphra-border px-6 py-3.5 flex-shrink-0">
          <div className="flex items-end gap-3">
            <button
              onClick={() => setSelfDestruct(!selfDestruct)}
              className={`p-2.5 rounded transition-colors flex-shrink-0 ${
                selfDestruct
                  ? 'bg-cyphra-warning-muted text-cyphra-warning'
                  : 'text-cyphra-text-muted hover:text-cyphra-text-secondary hover:bg-cyphra-surface'
              }`}
              title="Self-destruct message"
            >
              <Trash2 className="w-4 h-4" strokeWidth={1.5} />
            </button>

            <div className="flex-1">
              <textarea
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Type a message..."
                className="input-primary resize-none text-sm py-2.5"
                rows="1"
              />
            </div>

            <button
              onClick={handleSendMessage}
              disabled={!messageText.trim() || sending}
              className={`p-2.5 rounded transition-colors flex-shrink-0 ${
                messageText.trim() && !sending
                  ? 'bg-cyphra-accent hover:bg-cyphra-accent-hover text-white'
                  : 'bg-cyphra-border text-cyphra-text-muted cursor-not-allowed'
              }`}
            >
              <Send className={`w-4 h-4 ${sending ? 'animate-pulse' : ''}`} strokeWidth={1.5} />
            </button>
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-cyphra-text-muted">
            <Lock className="w-3 h-3" strokeWidth={1.5} />
            <span>Messages are end-to-end encrypted</span>
          </div>
        </div>
      </div>

      {/* Add Contact Modal */}
      <AnimatePresence>
        {showAddContact && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
            onClick={() => setShowAddContact(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-cyphra-surface rounded border border-cyphra-border p-6 max-w-sm w-full"
            >
              <div className="flex items-center justify-between mb-5">
                <h3 className="text-sm font-semibold text-cyphra-text-primary">Add Contact</h3>
                <button onClick={() => setShowAddContact(false)} className="text-cyphra-text-muted hover:text-cyphra-text-secondary">
                  <X className="w-4 h-4" strokeWidth={1.5} />
                </button>
              </div>

              <div className="mb-5 p-3 rounded border border-cyphra-accent/20 bg-cyphra-accent-muted">
                <p className="text-[11px] text-cyphra-text-muted mb-1.5">Your Ghost Code</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-2.5 py-1.5 bg-cyphra-bg rounded font-mono text-xs text-cyphra-accent border border-cyphra-border">
                    {myGhostCode}
                  </code>
                  <button onClick={copyGhostCode} className="btn-ghost text-xs px-2 py-1.5">
                    <Copy className="w-3.5 h-3.5" strokeWidth={1.5} />
                  </button>
                </div>
                <p className="text-[11px] text-cyphra-text-muted mt-1.5">Share this code so others can add you.</p>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs text-cyphra-text-secondary mb-1.5">Enter Ghost Code</label>
                  <input
                    type="text"
                    value={ghostCode}
                    onChange={(e) => setGhostCode(e.target.value.toUpperCase())}
                    placeholder="GHOST-XXXX-XXXX"
                    className="input-primary font-mono text-xs"
                    maxLength={20}
                  />
                </div>
                <button
                  onClick={handleAddContact}
                  disabled={!ghostCode.trim() || !ghostCode.startsWith('GHOST-')}
                  className="btn-primary w-full text-xs py-2.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Plus className="w-3.5 h-3.5" strokeWidth={1.5} />
                  Add Contact
                </button>
              </div>

              <div className="mt-4 pt-4 border-t border-cyphra-border">
                <p className="text-[11px] text-cyphra-text-muted leading-relaxed">
                  <span className="text-cyphra-text-secondary font-medium">How it works:</span> Exchange Ghost Codes securely with your contact. Once added, all messages are end-to-end encrypted via Kyber-1024 + AES-256-GCM.
                </p>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ML Dashboard Modal */}
      <AnimatePresence>
        {showMLDashboard && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-6"
            style={{ zIndex: 9999 }}
            onClick={() => setShowMLDashboard(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-5xl max-h-[85vh] overflow-y-auto bg-cyphra-surface rounded border border-cyphra-border"
            >
              <div className="sticky top-0 bg-cyphra-surface border-b border-cyphra-border px-6 py-4 flex items-center justify-between z-10">
                <div>
                  <h2 className="text-sm font-semibold text-cyphra-text-primary">AI/ML Threat Detection</h2>
                  <p className="text-[11px] text-cyphra-text-muted mt-0.5">Real-time network traffic analysis</p>
                </div>
                <button
                  onClick={() => setShowMLDashboard(false)}
                  className="p-1.5 rounded text-cyphra-text-muted hover:text-cyphra-text-secondary hover:bg-cyphra-bg transition-colors"
                >
                  <X className="w-4 h-4" strokeWidth={1.5} />
                </button>
              </div>

              <div className="p-6">
                <MLDashboard />

                {mlAnalysis && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mt-6 p-5 rounded border border-cyphra-border"
                  >
                    <h3 className="text-xs font-semibold text-cyphra-text-primary mb-4 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyphra-accent" strokeWidth={1.5} />
                      Latest Analysis
                    </h3>

                    <div className="grid grid-cols-3 gap-4 mb-4">
                      <div>
                        <div className="text-[11px] text-cyphra-text-muted mb-1">Threat Score</div>
                        <div className="text-lg font-semibold font-mono text-cyphra-text-primary">
                          {(mlAnalysis.threatScore * 100).toFixed(2)}%
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-cyphra-text-muted mb-1">Classification</div>
                        <div className="text-lg font-semibold text-cyphra-success">{mlAnalysis.attackType}</div>
                      </div>
                      <div>
                        <div className="text-[11px] text-cyphra-text-muted mb-1">Confidence</div>
                        <div className="text-lg font-semibold font-mono text-cyphra-text-primary">
                          {(mlAnalysis.confidence * 100).toFixed(2)}%
                        </div>
                      </div>
                    </div>

                    <div className="pt-4 border-t border-cyphra-border grid grid-cols-3 gap-4 text-xs">
                      <div>
                        <span className="text-cyphra-text-muted">LightGBM:</span>
                        <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{(mlAnalysis.ensembleScores.lightgbm * 100).toFixed(2)}%</span>
                      </div>
                      <div>
                        <span className="text-cyphra-text-muted">XGBoost:</span>
                        <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{(mlAnalysis.ensembleScores.xgboost * 100).toFixed(2)}%</span>
                      </div>
                      <div>
                        <span className="text-cyphra-text-muted">Neural Net:</span>
                        <span className="text-cyphra-text-primary font-mono font-medium ml-1.5">{(mlAnalysis.ensembleScores.neuralnet * 100).toFixed(2)}%</span>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-cyphra-border flex justify-between text-[11px] text-cyphra-text-muted font-mono">
                      <span>Inference: {mlAnalysis.inferenceTime}ms</span>
                      <span>GPU: {mlAnalysis.gpuUtilization}%</span>
                      <span>Model: {mlAnalysis.modelVersion}</span>
                    </div>
                  </motion.div>
                )}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

