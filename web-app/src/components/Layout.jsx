import { useNavigate, useLocation } from 'react-router-dom'
import { LayoutDashboard, MessageSquare, ShieldAlert, Settings, LogOut, Radio } from 'lucide-react'
import useStore from '../store/useStore'

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/messenger', label: 'Messenger', icon: MessageSquare },
  { path: '/security',  label: 'Security',  icon: ShieldAlert },
  { path: '/defense',   label: 'Defence',   icon: Radio },
]

export default function Layout({ children }) {
  const navigate = useNavigate()
  const location = useLocation()
  const { logout, currentUser } = useStore()

  const handleLogout = () => {
    logout()
    navigate('/auth')
  }

  return (
    <div className="h-screen flex overflow-hidden">
      {/* Sidebar */}
      <aside className="w-[72px] bg-cyphra-surface border-r border-cyphra-border flex flex-col items-center py-4 flex-shrink-0">
        {/* Logo */}
        <button
          onClick={() => navigate('/dashboard')}
          className="mb-6 p-1"
        >
          <img src="/cyphra-logo.png" alt="CYPHRA" className="h-20 object-contain" />
        </button>

        {/* Nav Items */}
        <nav className="flex-1 flex flex-col items-center gap-2 w-full px-2">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path
            const Icon = item.icon
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={`relative w-full flex flex-col items-center justify-center gap-1 py-2.5 rounded transition-colors duration-150 ${isActive
                  ? 'bg-cyphra-accent/10 text-cyphra-accent'
                  : 'text-cyphra-text-muted hover:text-cyphra-text-secondary hover:bg-cyphra-bg'
                  }`}
                title={item.label}
              >
                <Icon className="w-[18px] h-[18px]" strokeWidth={1.5} />
                <span className="text-[9px] font-medium leading-none">{item.label}</span>
                {isActive && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-cyphra-accent rounded-r" />
                )}
              </button>
            )
          })}
        </nav>

        {/* Bottom Actions */}
        <div className="w-full px-2">
          <button
            onClick={handleLogout}
            className="w-full flex flex-col items-center justify-center gap-1 py-2.5 rounded text-cyphra-text-muted hover:text-cyphra-danger hover:bg-cyphra-danger-muted transition-colors duration-150"
            title="Logout"
          >
            <LogOut className="w-[18px] h-[18px]" strokeWidth={1.5} />
            <span className="text-[9px] font-medium leading-none">Logout</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-hidden">
        {children}
      </main>
    </div>
  )
}
