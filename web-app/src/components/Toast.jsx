import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle, AlertTriangle, X, Info } from 'lucide-react'
import useStore from '../store/useStore'

const icons = {
  success: CheckCircle,
  error: AlertTriangle,
  warning: AlertTriangle,
  info: Info,
}

const styles = {
  success: 'border-cyphra-success/30 bg-cyphra-success-muted text-cyphra-success',
  error: 'border-cyphra-danger/30 bg-cyphra-danger-muted text-cyphra-danger',
  warning: 'border-cyphra-warning/30 bg-cyphra-warning-muted text-cyphra-warning',
  info: 'border-cyphra-accent/30 bg-cyphra-accent-muted text-cyphra-accent',
}

function ToastItem({ notification, onDismiss }) {
  const Icon = icons[notification.type] || icons.info
  const style = styles[notification.type] || styles.info

  useEffect(() => {
    const timer = setTimeout(() => {
      onDismiss(notification.id)
    }, 4000)
    return () => clearTimeout(timer)
  }, [notification.id, onDismiss])

  return (
    <motion.div
      initial={{ opacity: 0, x: 40 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 40 }}
      transition={{ duration: 0.2 }}
      className={`flex items-start gap-3 px-4 py-3 rounded border ${style} max-w-sm`}
    >
      <Icon className="w-4 h-4 mt-0.5 flex-shrink-0" strokeWidth={1.5} />
      <p className="text-sm flex-1">{notification.message}</p>
      <button
        onClick={() => onDismiss(notification.id)}
        className="opacity-60 hover:opacity-100 transition-opacity"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </motion.div>
  )
}

export default function ToastContainer() {
  const { notifications, removeNotification } = useStore()

  return (
    <div className="fixed top-4 right-4 z-[9999] flex flex-col gap-2">
      <AnimatePresence>
        {notifications.slice(-5).map((notif) => (
          <ToastItem
            key={notif.id}
            notification={notif}
            onDismiss={removeNotification}
          />
        ))}
      </AnimatePresence>
    </div>
  )
}
