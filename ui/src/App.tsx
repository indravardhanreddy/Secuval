import { useEffect, useState } from 'react'
import { Menu, Settings, Home, AlertCircle, Sun, Moon, Shield } from 'lucide-react'
import { Dashboard } from './components/Dashboard'
import { RequestTracker } from './components/RequestTracker'
import { Alerts } from './components/Alerts'
import { SettingsPanel } from './components/Settings'
import { SecuritySettings } from './components/SecuritySettings'
import BlockedRequests from './components/BlockedRequests'
import { useAppStore } from './store'

type View = 'dashboard' | 'requests' | 'blocked' | 'alerts' | 'settings' | 'security'

function App() {
  const [currentView, setCurrentView] = useState<View>('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const settings = useAppStore((state) => state.settings)
  const updateSettings = useAppStore((state) => state.updateSettings)
  const alerts = useAppStore((state) => state.alerts)

  const toggleTheme = () => {
    updateSettings({ theme: settings.theme === 'dark' ? 'light' : 'dark' })
  }

  useEffect(() => {
    if (settings.theme === 'light') {
      document.body.classList.add('light-theme')
    } else {
      document.body.classList.remove('light-theme')
    }
  }, [settings.theme])

  const hasAlerts = alerts && alerts.summary.total > 0
  const hasCriticalAlerts =
    alerts && (alerts.summary.critical > 0 || alerts.summary.requires_attention)

  return (
    <div
      className={`min-h-screen gradient-bg flex ${settings.theme === 'dark' ? 'dark' : ''}`}
    >
      {/* Sidebar */}
      <div
        className={`${
          sidebarOpen ? 'w-72' : 'w-20'
        } ${settings.theme === 'dark' ? 'glass-card' : 'bg-white/90 backdrop-blur-xl border-slate-200/50'} border-r transition-all duration-300 flex flex-col m-4 rounded-3xl overflow-hidden`}
      >
        {/* Logo/Header */}
        <div className={`h-20 flex items-center justify-between px-6 ${settings.theme === 'dark' ? 'border-b border-slate-700/50 bg-gradient-to-r from-cyan-500/10 to-green-500/10' : 'border-b border-slate-200/50 bg-gradient-to-r from-blue-50/80 to-indigo-50/80'} transition-all duration-300`}>
          {sidebarOpen && (
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-green-400 rounded-2xl flex items-center justify-center shadow-lg animate-float">
                <span className="text-slate-900 font-bold text-lg">S</span>
              </div>
              <div>
                <span className={`font-bold text-xl ${settings.theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>Secuval</span>
              </div>
            </div>
          )}
          <div className="flex items-center gap-2">
            <button
              onClick={toggleTheme}
              className={`p-3 hover:bg-white/10 rounded-2xl ${settings.theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'} transition-all duration-200 hover:scale-105`}
              title={`Switch to ${settings.theme === 'dark' ? 'light' : 'dark'} theme`}
            >
              {settings.theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
            </button>
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className={`p-3 hover:bg-white/10 rounded-2xl ${settings.theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'} transition-all duration-200 hover:scale-105`}
            >
              <Menu size={20} />
            </button>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-6 space-y-3">
          <NavItem
            icon={<Home size={20} />}
            label="Dashboard"
            active={currentView === 'dashboard'}
            onClick={() => setCurrentView('dashboard')}
            sidebarOpen={sidebarOpen}
            theme={settings.theme}
          />
          <NavItem
            icon={<AlertCircle size={20} />}
            label="Alerts"
            active={currentView === 'alerts'}
            onClick={() => setCurrentView('alerts')}
            badge={hasAlerts ? alerts?.summary.total : undefined}
            badgeColor={hasCriticalAlerts ? 'red' : 'yellow'}
            sidebarOpen={sidebarOpen}
            theme={settings.theme}
          />
          <NavItem
            icon={<AlertCircle size={20} />}
            label="Requests"
            active={currentView === 'requests'}
            onClick={() => setCurrentView('requests')}
            sidebarOpen={sidebarOpen}
            theme={settings.theme}
          />
          <NavItem
            icon={<Shield size={20} />}
            label="Blocked"
            active={currentView === 'blocked'}
            onClick={() => setCurrentView('blocked')}
            sidebarOpen={sidebarOpen}
            theme={settings.theme}
          />
          <NavItem
            icon={<Settings size={20} />}
            label="Settings"
            active={currentView === 'settings'}
            onClick={() => setCurrentView('settings')}
            sidebarOpen={sidebarOpen}
            theme={settings.theme}
          />
          <NavItem
            icon={<AlertCircle size={20} />}
            label="Security"
            active={currentView === 'security'}
            onClick={() => setCurrentView('security')}
            sidebarOpen={sidebarOpen}
            theme={settings.theme}
          />
        </nav>

        {/* Footer */}
        {sidebarOpen && (
          <div className={`px-6 py-6 border-t ${settings.theme === 'dark' ? 'border-slate-700/50 bg-gradient-to-r from-slate-800/50 to-slate-900/50' : 'border-slate-200/50 bg-gradient-to-r from-slate-100/50 to-slate-200/50'} transition-all duration-300`}>
            <div className="flex items-center gap-3 mb-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
              <p className={`text-sm ${settings.theme === 'dark' ? 'text-gray-400' : 'text-slate-600'}`}>System Online</p>
            </div>
            <p className={`text-xs ${settings.theme === 'dark' ? 'text-gray-500' : 'text-slate-500'}`}>Dashboard v2.0</p>
            <p className={`text-xs ${settings.theme === 'dark' ? 'text-gray-500' : 'text-slate-500'}`}>React + Rust + Security</p>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="animate-slide-up">
          {currentView === 'dashboard' && <Dashboard />}
          {currentView === 'requests' && <RequestTracker />}
          {currentView === 'blocked' && <BlockedRequests />}
          {currentView === 'alerts' && <Alerts />}
          {currentView === 'settings' && <SettingsPanel />}
          {currentView === 'security' && <SecuritySettings />}
        </div>
      </div>
    </div>
  )
}

interface NavItemProps {
  icon: React.ReactNode
  label: string
  active: boolean
  onClick: () => void
  badge?: number
  badgeColor?: 'red' | 'yellow' | 'green'
  sidebarOpen: boolean
  theme: 'dark' | 'light'
}

function NavItem({
  icon,
  label,
  active,
  onClick,
  badge,
  badgeColor = 'yellow',
  sidebarOpen,
  theme,
}: NavItemProps) {
  const badgeColorClass = {
    red: 'bg-red-500',
    yellow: 'bg-yellow-500',
    green: 'bg-green-500',
  }[badgeColor]

  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-4 px-4 py-4 rounded-2xl transition-all duration-200 relative group ${
        active
          ? `${theme === 'dark' ? 'bg-gradient-to-r from-cyan-500/20 to-green-500/20 text-cyan-400 border border-cyan-500/30' : 'bg-gradient-to-r from-blue-500/20 to-indigo-500/20 text-blue-600 border border-blue-500/30'} shadow-lg`
          : `${theme === 'dark' ? 'text-gray-400 hover:bg-white/5 hover:text-white' : 'text-slate-600 hover:bg-slate-100/50 hover:text-slate-900'}`
      }`}
    >
      <div className="flex-shrink-0">{icon}</div>
      {sidebarOpen && (
        <>
          <span className="flex-1 text-left text-sm">{label}</span>
          {badge && badge > 0 && (
            <span
              className={`${badgeColorClass} text-white text-xs font-bold rounded-full w-6 h-6 flex items-center justify-center shadow-lg animate-pulse`}
            >
              {badge > 9 ? '9+' : badge}
            </span>
          )}
        </>
      )}
    </button>
  )
}

export default App
