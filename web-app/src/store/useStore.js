import { create } from 'zustand'

const useStore = create((set, get) => ({
  // User state
  currentUser: null,
  isAuthenticated: false,
  
  // Messages state
  messages: [],
  activeChat: null,
  contacts: [],
  
  // Security state
  threatLevel: 'low', // low, medium, high, critical
  encryptionStatus: 'active',
  metadataProtection: true,
  
  // UI state
  sidebarOpen: true,
  settingsOpen: false,
  missionPreset: 'balanced', // silent, balanced, secure, compromised
  
  // Notifications
  notifications: [],
  
  // Actions
  setCurrentUser: (user) => set({ currentUser: user, isAuthenticated: !!user }),
  
  logout: () => set({
    currentUser: null,
    isAuthenticated: false,
    messages: [],
    activeChat: null,
  }),
  
  addMessage: (message) => set((state) => ({
    messages: [...state.messages, {
      ...message,
      id: message.id || `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: message.timestamp || Date.now(),
      encrypted: message.encrypted !== undefined ? message.encrypted : true,
      selfDestruct: message.selfDestruct || false,
      destructTimer: message.destructTimer || null,
      destructAt: message.destructAt || null,
    }]
  })),
  
  deleteMessage: (messageId) => set((state) => ({
    messages: state.messages.filter(m => m.id !== messageId)
  })),
  
  updateMessageStatus: (messageId, status) => set((state) => ({
    messages: state.messages.map(m => 
      m.id === messageId ? { ...m, status } : m
    )
  })),

  // Start the self-destruct countdown — called only when recipient opens the chat.
  stampDestructAt: (messageId, destructAt) => set((state) => ({
    messages: state.messages.map(m =>
      m.id === messageId ? { ...m, destructAt } : m
    )
  })),

  setActiveChat: (chatId) => set({ activeChat: chatId }),
  
  addContact: (contact) => set((state) => ({
    contacts: [...state.contacts, {
      ...contact,
      // DON'T override the ID if already provided (contains actual user ID!)
      id: contact.id || `contact_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      lastSeen: Date.now(),
      publicKey: contact.publicKey || null,
      verified: contact.verified || false,
    }]
  })),
  
  setThreatLevel: (level) => set({ threatLevel: level }),
  
  setMissionPreset: (preset) => {
    const presets = {
      silent: {
        threatLevel: 'high',
        encryptionCadence: 60,
        paddingRate: 0.8,
        mixPathLength: 4,
      },
      balanced: {
        threatLevel: 'medium',
        encryptionCadence: 300,
        paddingRate: 0.3,
        mixPathLength: 2,
      },
      secure: {
        threatLevel: 'low',
        encryptionCadence: 3600,
        paddingRate: 0.1,
        mixPathLength: 1,
      },
      compromised: {
        threatLevel: 'critical',
        encryptionCadence: 30,
        paddingRate: 0.95,
        mixPathLength: 5,
      }
    }
    
    const config = presets[preset]
    set({
      missionPreset: preset,
      threatLevel: config.threatLevel,
    })
  },
  
  addNotification: (notification) => set((state) => ({
    notifications: [...state.notifications, {
      ...notification,
      id: `notif_${Date.now()}`,
      timestamp: Date.now(),
    }]
  })),
  
  removeNotification: (notifId) => set((state) => ({
    notifications: state.notifications.filter(n => n.id !== notifId)
  })),
  
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  toggleSettings: () => set((state) => ({ settingsOpen: !state.settingsOpen })),
}))

export default useStore

