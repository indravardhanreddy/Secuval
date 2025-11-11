import { useEffect } from 'react'
import { Settings as SettingsIcon, Moon, Sun, Save, RotateCcw } from 'lucide-react'
import { useAppStore } from '../store'

export function SettingsPanel() {
  const settings = useAppStore((state) => state.settings)
  const updateSettings = useAppStore((state) => state.updateSettings)

  const handleAutoRefreshChange = (enabled: boolean) => {
    updateSettings({ autoRefresh: enabled })
  }

  const handleRefreshIntervalChange = (interval: number) => {
    updateSettings({ refreshInterval: interval })
  }

  const handleThemeChange = (theme: 'dark' | 'light') => {
    updateSettings({ theme })
  }

  const handleAlertLevelChange = (level: string) => {
    updateSettings({ threatAlertLevel: level })
  }

  const handleReset = () => {
    if (confirm('Are you sure you want to reset all settings to defaults?')) {
      updateSettings({
        autoRefresh: true,
        refreshInterval: 3000,
        theme: 'dark',
        threatAlertLevel: 'warning',
      })
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-3xl font-bold mb-2">Settings</h1>
        <p className="text-gray-400">Customize your dashboard experience</p>
      </div>

      {/* Display Settings */}
      <Section icon={<SettingsIcon />} title="Display Settings">
        {/* Theme */}
        <SettingItem label="Theme" description="Choose between dark and light mode">
          <div className="flex gap-4">
            <button
              onClick={() => handleThemeChange('dark')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                settings.theme === 'dark'
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-800 text-gray-400 hover:bg-slate-700'
              }`}
            >
              <Moon size={18} />
              Dark Mode
            </button>
            <button
              onClick={() => handleThemeChange('light')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                settings.theme === 'light'
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-800 text-gray-400 hover:bg-slate-700'
              }`}
            >
              <Sun size={18} />
              Light Mode
            </button>
          </div>
        </SettingItem>
      </Section>

      {/* Refresh Settings */}
      <Section icon={<SettingsIcon />} title="Auto Refresh Settings">
        {/* Auto Refresh Toggle */}
        <SettingItem
          label="Auto Refresh"
          description="Automatically refresh dashboard data"
        >
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={settings.autoRefresh}
              onChange={(e) => handleAutoRefreshChange(e.target.checked)}
              className="w-5 h-5 rounded border-slate-500 bg-slate-800"
            />
            <span className="text-gray-300">
              {settings.autoRefresh ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        {/* Refresh Interval */}
        {settings.autoRefresh && (
          <SettingItem
            label="Refresh Interval"
            description="How often to refresh the dashboard (in seconds)"
          >
            <div className="space-y-3">
              <input
                type="range"
                min="1000"
                max="30000"
                step="1000"
                value={settings.refreshInterval}
                onChange={(e) => handleRefreshIntervalChange(parseInt(e.target.value))}
                className="w-full"
              />
              <div className="flex justify-between text-sm text-gray-400">
                <span>1s</span>
                <span className="text-cyan-400 font-semibold">
                  {(settings.refreshInterval / 1000).toFixed(1)}s
                </span>
                <span>30s</span>
              </div>
            </div>
          </SettingItem>
        )}
      </Section>

      {/* Alert Settings */}
      <Section icon={<SettingsIcon />} title="Alert Settings">
        {/* Alert Level */}
        <SettingItem
          label="Threat Alert Level"
          description="Minimum threat level to trigger alerts"
        >
          <select
            value={settings.threatAlertLevel}
            onChange={(e) => handleAlertLevelChange(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500 w-full max-w-xs"
          >
            <option value="critical">Critical Only</option>
            <option value="high">High and Above</option>
            <option value="warning">Warnings and Above</option>
            <option value="info">All Alerts</option>
          </select>
        </SettingItem>
      </Section>

      {/* System Information */}
      <Section icon={<SettingsIcon />} title="System Information">
        <SettingItem label="Dashboard Version" description="">
          <span className="text-cyan-400 font-mono">1.0.0</span>
        </SettingItem>
        <SettingItem label="API Endpoint" description="">
          <span className="text-cyan-400 font-mono">http://localhost:3000</span>
        </SettingItem>
        <SettingItem label="Frontend Framework" description="">
          <span className="text-cyan-400 font-mono">React 18 + TypeScript</span>
        </SettingItem>
        <SettingItem label="Backend Framework" description="">
          <span className="text-cyan-400 font-mono">Rust + Axum</span>
        </SettingItem>
      </Section>

      {/* Actions */}
      <div className="flex gap-4 pt-6 border-t border-slate-700">
        <button className="flex items-center gap-2 px-6 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors font-semibold">
          <Save size={18} />
          Save Settings
        </button>
        <button
          onClick={handleReset}
          className="flex items-center gap-2 px-6 py-2 bg-slate-800 border border-slate-700 text-gray-300 rounded-lg hover:bg-slate-700 transition-colors font-semibold"
        >
          <RotateCcw size={18} />
          Reset to Defaults
        </button>
      </div>
    </div>
  )
}

interface SectionProps {
  icon: React.ReactNode
  title: string
  children: React.ReactNode
}

function Section({ icon, title, children }: SectionProps) {
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="text-cyan-400">{icon}</div>
        <h2 className="text-xl font-semibold">{title}</h2>
      </div>
      <div className="space-y-6">{children}</div>
    </div>
  )
}

interface SettingItemProps {
  label: string
  description: string
  children: React.ReactNode
}

function SettingItem({ label, description, children }: SettingItemProps) {
  return (
    <div className="flex items-start justify-between py-4 border-b border-slate-800 last:border-b-0">
      <div className="flex-1">
        <p className="font-semibold text-white mb-1">{label}</p>
        {description && <p className="text-sm text-gray-400">{description}</p>}
      </div>
      <div className="flex-1 flex justify-end">{children}</div>
    </div>
  )
}
