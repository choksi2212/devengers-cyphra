import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { lazy, Suspense, useEffect } from 'react'
import useStore from './store/useStore'
import Layout from './components/Layout'
import ToastContainer from './components/Toast'

import cryptoService from './services/crypto.service'
import threatService from './services/threat.service'
import { isWasmAvailable, getVersion as getWasmVersion } from './services/wasm-bridge.service'

const LandingPage = lazy(() => import('./pages/LandingPage'))
const AuthPage = lazy(() => import('./pages/AuthPage'))
const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const MessengerPage = lazy(() => import('./pages/MessengerPage'))
const SecurityDashboard = lazy(() => import('./pages/SecurityDashboard'))
const DefenseOpsPage = lazy(() => import('./pages/DefenseOpsPage'))

function LoadingFallback() {
  return (
    <div className="h-screen flex items-center justify-center bg-cyphra-bg">
      <div className="flex flex-col items-center gap-3">
        <div className="w-8 h-8 rounded bg-cyphra-accent/10 flex items-center justify-center">
          <span className="text-cyphra-accent font-bold text-sm">C</span>
        </div>
        <p className="text-xs text-cyphra-text-muted">Loading...</p>
      </div>
    </div>
  )
}

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useStore()
  if (!isAuthenticated) return <Navigate to="/auth" />
  return <Layout>{children}</Layout>
}

function App() {
  const { isAuthenticated } = useStore()

  useEffect(() => {
    const initServices = async () => {
      try {
        // Pre-warm WASM in parallel with other service inits
        const [wasmOk] = await Promise.all([
          isWasmAvailable(),
          cryptoService.init(),
          threatService.init(),
        ])
        const ver = await getWasmVersion()
        console.log(`[App] 🦀 WASM: ${wasmOk ? ver : 'fallback (Web Crypto)'}`)
        console.log('[App] All services initialized')
      } catch (error) {
        console.error('[App] Service initialization failed:', error)
      }
    }
    initServices()
  }, [])

  return (
    <BrowserRouter>
      <ToastContainer />
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/auth" element={
            isAuthenticated ? <Navigate to="/dashboard" /> : <AuthPage />
          } />

          <Route path="/dashboard" element={
            <ProtectedRoute><DashboardPage /></ProtectedRoute>
          } />
          <Route path="/messenger" element={
            <ProtectedRoute><MessengerPage /></ProtectedRoute>
          } />
          <Route path="/security" element={
            <ProtectedRoute><SecurityDashboard /></ProtectedRoute>
          } />
          <Route path="/defense" element={
            <ProtectedRoute><DefenseOpsPage /></ProtectedRoute>
          } />

          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}

export default App

