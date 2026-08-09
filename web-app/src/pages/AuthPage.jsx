import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Lock, ArrowRight, CheckCircle, AlertTriangle } from 'lucide-react'
import useStore from '../store/useStore'
import authService from '../services/auth.service'

export default function AuthPage() {
  const [isLogin, setIsLogin] = useState(true)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const navigate = useNavigate()
  const setCurrentUser = useStore(state => state.setCurrentUser)
  const addNotification = useStore(state => state.addNotification)

  useEffect(() => {
    authService.init()
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    setSuccess('')

    try {
      if (isLogin) {
        const result = await authService.login(email, password)
        if (!result.success) throw new Error('Login failed')
        setCurrentUser(result.user)
        addNotification({ type: 'success', message: `Welcome back, ${result.user.username}` })
        setSuccess('Authenticated. Redirecting...')
        setTimeout(() => navigate('/dashboard'), 1000)
      } else {
        const result = await authService.register(username, email, password)
        if (!result.success) throw new Error('Registration failed')
        setCurrentUser(result.user)
        addNotification({ type: 'success', message: `Account created. Welcome, ${result.user.username}` })
        setSuccess('Account created. Redirecting...')
        setTimeout(() => navigate('/dashboard'), 1000)
      }
    } catch (err) {
      console.error('Authentication error:', err)
      setError(err.message || 'Authentication failed')
      addNotification({ type: 'error', message: err.message || 'Authentication failed' })
    } finally {
      setLoading(false)
    }
  }

  const switchMode = () => {
    setIsLogin(!isLogin)
    setError('')
    setSuccess('')
  }

  return (
    <div className="min-h-screen bg-cyphra-bg flex">
      {/* Left Panel - Branding */}
      <div className="hidden lg:flex lg:w-[45%] flex-col justify-between p-12 border-r border-cyphra-border">
        <div>
          <div className="flex items-center mb-16">
            <img src="/cyphra-logo.png" alt="CYPHRA" className="h-20 object-contain" />
          </div>

          <h1 className="text-4xl font-bold text-cyphra-text-primary leading-tight mb-4">
            Guarding the Unseen<br />Layer of Defense
          </h1>
          <p className="text-cyphra-text-secondary text-sm leading-relaxed max-w-sm">
            Military-grade secure messaging with post-quantum encryption and AI-powered threat detection.
          </p>
        </div>

        <div className="space-y-3">
          <div className="flex items-center gap-3 text-xs text-cyphra-text-muted">
            <Lock className="w-3.5 h-3.5 text-cyphra-accent" strokeWidth={1.5} />
            <span className="font-mono">AES-256-GCM + Kyber-1024 + Dilithium3</span>
          </div>
          <div className="flex items-center gap-3 text-xs text-cyphra-text-muted">
            <Lock className="w-3.5 h-3.5 text-cyphra-accent" strokeWidth={1.5} />
            <span className="font-mono">PBKDF2 100,000 iterations</span>
          </div>
          <div className="flex items-center gap-3 text-xs text-cyphra-text-muted">
            <Lock className="w-3.5 h-3.5 text-cyphra-accent" strokeWidth={1.5} />
            <span className="font-mono">Zero-Knowledge Architecture</span>
          </div>
        </div>
      </div>

      {/* Right Panel - Auth Form */}
      <div className="flex-1 flex items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="w-full max-w-sm"
        >
          {/* Mobile Logo */}
          <div className="lg:hidden flex items-center mb-10">
            <img src="/cyphra-logo.png" alt="CYPHRA" className="h-12 object-contain" />
          </div>

          <h2 className="text-xl font-semibold text-cyphra-text-primary mb-1">
            {isLogin ? 'Sign in' : 'Create account'}
          </h2>
          <p className="text-sm text-cyphra-text-muted mb-8">
            {isLogin ? 'Access your secure workspace' : 'Set up your secure identity'}
          </p>

          {/* Tab Toggle */}
          <div className="flex gap-1 p-1 bg-cyphra-surface rounded border border-cyphra-border mb-6">
            <button
              onClick={() => { setIsLogin(true); setError(''); setSuccess('') }}
              className={`flex-1 py-2 text-sm font-medium rounded transition-colors duration-150 ${isLogin ? 'bg-cyphra-accent text-white' : 'text-cyphra-text-muted hover:text-cyphra-text-secondary'
                }`}
            >
              Sign In
            </button>
            <button
              onClick={() => { setIsLogin(false); setError(''); setSuccess('') }}
              className={`flex-1 py-2 text-sm font-medium rounded transition-colors duration-150 ${!isLogin ? 'bg-cyphra-accent text-white' : 'text-cyphra-text-muted hover:text-cyphra-text-secondary'
                }`}
            >
              Register
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <AnimatePresence mode="wait">
              {!isLogin && (
                <motion.div
                  key="username"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <label className="block text-xs font-medium text-cyphra-text-secondary mb-1.5">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="input-primary"
                    placeholder="Choose a username"
                    required
                    autoComplete="off"
                    minLength={3}
                  />
                </motion.div>
              )}
            </AnimatePresence>

            <div>
              <label className="block text-xs font-medium text-cyphra-text-secondary mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input-primary"
                placeholder="you@example.com"
                required
                autoComplete="off"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-cyphra-text-secondary mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-primary"
                placeholder="Minimum 8 characters"
                required
                autoComplete="off"
                minLength={8}
              />
            </div>

            {/* Status Messages */}
            <AnimatePresence mode="wait">
              {success && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2.5 px-3 py-2.5 rounded border border-cyphra-success/20 bg-cyphra-success-muted"
                >
                  <CheckCircle className="w-4 h-4 text-cyphra-success flex-shrink-0" strokeWidth={1.5} />
                  <span className="text-xs text-cyphra-success">{success}</span>
                </motion.div>
              )}
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2.5 px-3 py-2.5 rounded border border-cyphra-danger/20 bg-cyphra-danger-muted"
                >
                  <AlertTriangle className="w-4 h-4 text-cyphra-danger flex-shrink-0" strokeWidth={1.5} />
                  <span className="text-xs text-cyphra-danger">{error}</span>
                </motion.div>
              )}
            </AnimatePresence>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full py-2.5"
            >
              {loading ? (
                <span className="text-sm">Authenticating...</span>
              ) : (
                <>
                  <span className="text-sm">{isLogin ? 'Sign In' : 'Create Account'}</span>
                  <ArrowRight className="w-4 h-4" strokeWidth={1.5} />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button onClick={switchMode} className="text-xs text-cyphra-text-muted hover:text-cyphra-accent transition-colors">
              {isLogin ? "Don't have an account? Register" : 'Already have an account? Sign in'}
            </button>
          </div>

          {/* Security footer */}
          <div className="mt-10 pt-6 border-t border-cyphra-border">
            <div className="flex items-center justify-center gap-2 text-[11px] text-cyphra-text-muted">
              <Lock className="w-3 h-3" strokeWidth={1.5} />
              <span>End-to-end encrypted. Zero-knowledge proof.</span>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
