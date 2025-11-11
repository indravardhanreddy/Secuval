import { useEffect, useState } from 'react'
import { Menu, Settings, Home, AlertCircle } from 'lucide-react'
import { Dashboard } from './components/Dashboard'
import { RequestTracker } from './components/RequestTracker'
import { Alerts } from './components/Alerts'
import { SettingsPanel } from './components/Settings'
import { SecuritySettings } from './components/SecuritySettings'
import { useAppStore } from './store'

type View = 'dashboard' | 'requests' | 'alerts' | 'settings' | 'security'

function App() {
  const [currentView, setCurrentView] = useState<View>('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const settings = useAppStore((state) => state.settings)
  const alerts = useAppStore((state) => state.alerts)

  const hasAlerts = alerts && alerts.summary.total > 0
  const hasCriticalAlerts =
    alerts && (alerts.summary.critical > 0 || alerts.summary.requires_attention)

  return (
    <div
      className={`min-h-screen bg-slate-950 flex ${settings.theme === 'dark' ? 'dark' : ''}`}
    >
      {/* Sidebar */}
      <div
        className={`${
          sidebarOpen ? 'w-64' : 'w-20'
        } bg-slate-900 border-r border-slate-700 transition-all duration-300 flex flex-col`}
      >
        {/* Logo/Header */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-slate-700">
          {sidebarOpen && (
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-gradient-to-br from-cyan-400 to-green-400 rounded flex items-center justify-center">
                <span className="text-slate-900 font-bold text-sm">S</span>
              </div>
              <span className="font-bold text-cyan-400">SecureAPIs</span>
            </div>
          )}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 hover:bg-slate-800 rounded text-cyan-400"
          >
            <Menu size={20} />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-2">
          <NavItem
            icon={<Home size={20} />}
            label="Dashboard"
            active={currentView === 'dashboard'}
            onClick={() => setCurrentView('dashboard')}
            sidebarOpen={sidebarOpen}
          />
          <NavItem
            icon={<AlertCircle size={20} />}
            label="Alerts"
            active={currentView === 'alerts'}
            onClick={() => setCurrentView('alerts')}
            badge={hasAlerts ? alerts?.summary.total : undefined}
            badgeColor={hasCriticalAlerts ? 'red' : 'yellow'}
            sidebarOpen={sidebarOpen}
          />
          <NavItem
            icon={<AlertCircle size={20} />}
            label="Requests"
            active={currentView === 'requests'}
            onClick={() => setCurrentView('requests')}
            sidebarOpen={sidebarOpen}
          />
          <NavItem
            icon={<Settings size={20} />}
            label="Settings"
            active={currentView === 'settings'}
            onClick={() => setCurrentView('settings')}
            sidebarOpen={sidebarOpen}
          />
          <NavItem
            icon={<AlertCircle size={20} />}
            label="Security"
            active={currentView === 'security'}
            onClick={() => setCurrentView('security')}
            sidebarOpen={sidebarOpen}
          />
        </nav>

        {/* Footer */}
        {sidebarOpen && (
          <div className="px-3 py-4 border-t border-slate-700 text-xs text-gray-400">
            <p>Dashboard v1.0</p>
            <p>React + Rust</p>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="p-6">
          {currentView === 'dashboard' && <Dashboard />}
          {currentView === 'requests' && <RequestTracker />}
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
}

function NavItem({
  icon,
  label,
  active,
  onClick,
  badge,
  badgeColor = 'yellow',
  sidebarOpen,
}: NavItemProps) {
  const badgeColorClass = {
    red: 'bg-red-500',
    yellow: 'bg-yellow-500',
    green: 'bg-green-500',
  }[badgeColor]

  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-3 px-3 py-2 rounded transition-colors relative ${
        active
          ? 'bg-cyan-900 text-cyan-400 border border-cyan-700'
          : 'text-gray-400 hover:bg-slate-800'
      }`}
    >
      <div className="flex-shrink-0">{icon}</div>
      {sidebarOpen && (
        <>
          <span className="flex-1 text-left text-sm">{label}</span>
          {badge && badge > 0 && (
            <span
              className={`${badgeColorClass} text-white text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center`}
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
