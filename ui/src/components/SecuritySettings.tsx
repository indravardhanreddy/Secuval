import { useEffect, useState } from 'react'
import { Lock, Shield, AlertTriangle, CheckCircle } from 'lucide-react'

interface SecurityConfig {
  rate_limit: {
    enabled: boolean
    requests_per_window: number
    window_secs: number
    burst_size: number
    adaptive: boolean
  }
  validation: {
    enabled: boolean
    sql_injection_check: boolean
    xss_check: boolean
    command_injection_check: boolean
    path_traversal_check: boolean
    sanitize_input: boolean
    max_payload_size: number
  }
  auth: {
    enabled: boolean
    require_auth: boolean
    token_expiry_secs: number
    mfa_enabled: boolean
  }
  threat_detection: {
    enabled: boolean
    anomaly_detection: boolean
    bot_detection: boolean
    known_patterns: boolean
  }
}

export function SecuritySettings() {
  const [config, setConfig] = useState<SecurityConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(
    null
  )

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/ui/settings')
      const data = await response.json()
      if (data.success && data.data) {
        setConfig({
          rate_limit: {
            enabled: data.data.security?.rate_limit_enabled ?? true,
            requests_per_window:
              data.data.security?.rate_limit_requests ?? 100_000,
            window_secs: data.data.security?.rate_limit_window_secs ?? 60,
            burst_size:
              Math.floor((data.data.security?.rate_limit_requests ?? 100_000) / 10),
            adaptive: true,
          },
          validation: {
            enabled: data.data.security?.validation_enabled ?? true,
            sql_injection_check: true,
            xss_check: true,
            command_injection_check: true,
            path_traversal_check: true,
            sanitize_input: true,
            max_payload_size: 10 * 1024 * 1024,
          },
          auth: {
            enabled: data.data.security?.auth_enabled ?? false,
            require_auth: false,
            token_expiry_secs: 3600,
            mfa_enabled: false,
          },
          threat_detection: {
            enabled: true,
            anomaly_detection: true,
            bot_detection: true,
            known_patterns: true,
          },
        })
      }
    } catch (error) {
      console.error('Error fetching settings:', error)
      setMessage({ type: 'error', text: 'Failed to load security settings' })
    } finally {
      setLoading(false)
    }
  }

  const saveSettings = async () => {
    if (!config) return

    try {
      setSaving(true)
      const response = await fetch('/api/ui/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          security: config,
        }),
      })
      const data = await response.json()
      if (data.success) {
        setMessage({ type: 'success', text: 'Security settings updated successfully' })
        setTimeout(() => setMessage(null), 3000)
      } else {
        setMessage({ type: 'error', text: 'Failed to save settings' })
      }
    } catch (error) {
      console.error('Error saving settings:', error)
      setMessage({ type: 'error', text: 'Error saving settings' })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <p className="text-gray-400">Loading security settings...</p>
      </div>
    )
  }

  if (!config) {
    return (
      <div className="flex items-center justify-center h-screen">
        <p className="text-red-400">Failed to load security settings</p>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
          <Shield className="text-cyan-400" />
          Security Settings
        </h1>
        <p className="text-gray-400">Manage API security and threat detection</p>
      </div>

      {message && (
        <div
          className={`p-4 rounded-lg flex items-center gap-2 ${
            message.type === 'success'
              ? 'bg-green-900/20 border border-green-700 text-green-300'
              : 'bg-red-900/20 border border-red-700 text-red-300'
          }`}
        >
          {message.type === 'success' ? (
            <CheckCircle size={20} />
          ) : (
            <AlertTriangle size={20} />
          )}
          {message.text}
        </div>
      )}

      {/* Rate Limiting */}
      <Section icon={<Lock />} title="Rate Limiting" enabled={config.rate_limit.enabled}>
        <SettingItem
          label="Requests Per Minute"
          description="Maximum number of requests allowed per IP address per 60 seconds"
        >
          <div className="space-y-3 w-full">
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="100"
                max="1000000"
                step="10000"
                value={config.rate_limit.requests_per_window}
                onChange={(e) =>
                  setConfig({
                    ...config,
                    rate_limit: {
                      ...config.rate_limit,
                      requests_per_window: Number(e.target.value),
                      burst_size: Math.floor(Number(e.target.value) / 10),
                    },
                  })
                }
                className="flex-1"
              />
              <span className="text-cyan-400 font-mono font-bold min-w-[140px] text-right">
                {config.rate_limit.requests_per_window.toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between text-xs text-gray-400">
              <span>100</span>
              <span>100K (Recommended)</span>
              <span>1M+</span>
            </div>
          </div>
        </SettingItem>

        <SettingItem
          label="Burst Size"
          description="Number of tokens available immediately before rate limiting kicks in"
        >
          <span className="text-cyan-400 font-mono">
            {config.rate_limit.burst_size.toLocaleString()}
          </span>
        </SettingItem>

        <SettingItem label="Adaptive Rate Limiting" description="Automatically adjust limits based on traffic patterns">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.rate_limit.adaptive}
              onChange={(e) =>
                setConfig({
                  ...config,
                  rate_limit: { ...config.rate_limit, adaptive: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">{config.rate_limit.adaptive ? 'Enabled' : 'Disabled'}</span>
          </label>
        </SettingItem>
      </Section>

      {/* Input Validation */}
      <Section icon={<AlertTriangle />} title="Input Validation" enabled={config.validation.enabled}>
        <SettingItem label="SQL Injection Detection">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.validation.sql_injection_check}
              onChange={(e) =>
                setConfig({
                  ...config,
                  validation: { ...config.validation, sql_injection_check: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.validation.sql_injection_check ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem label="XSS (Cross-Site Scripting) Detection">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.validation.xss_check}
              onChange={(e) =>
                setConfig({
                  ...config,
                  validation: { ...config.validation, xss_check: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.validation.xss_check ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem label="Command Injection Detection">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.validation.command_injection_check}
              onChange={(e) =>
                setConfig({
                  ...config,
                  validation: {
                    ...config.validation,
                    command_injection_check: e.target.checked,
                  },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.validation.command_injection_check ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem label="Path Traversal Detection">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.validation.path_traversal_check}
              onChange={(e) =>
                setConfig({
                  ...config,
                  validation: {
                    ...config.validation,
                    path_traversal_check: e.target.checked,
                  },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.validation.path_traversal_check ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem label="Input Sanitization">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.validation.sanitize_input}
              onChange={(e) =>
                setConfig({
                  ...config,
                  validation: { ...config.validation, sanitize_input: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.validation.sanitize_input ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>
      </Section>

      {/* Threat Detection */}
      <Section
        icon={<Shield />}
        title="Threat Detection"
        enabled={config.threat_detection.enabled}
      >
        <SettingItem label="Bot Detection">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.threat_detection.bot_detection}
              onChange={(e) =>
                setConfig({
                  ...config,
                  threat_detection: { ...config.threat_detection, bot_detection: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.threat_detection.bot_detection ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem label="Anomaly Detection">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.threat_detection.anomaly_detection}
              onChange={(e) =>
                setConfig({
                  ...config,
                  threat_detection: {
                    ...config.threat_detection,
                    anomaly_detection: e.target.checked,
                  },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.threat_detection.anomaly_detection ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem label="Known Attack Patterns">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.threat_detection.known_patterns}
              onChange={(e) =>
                setConfig({
                  ...config,
                  threat_detection: {
                    ...config.threat_detection,
                    known_patterns: e.target.checked,
                  },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.threat_detection.known_patterns ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>
      </Section>

      {/* Authentication */}
      <Section icon={<Lock />} title="Authentication" enabled={config.auth.enabled}>
        <SettingItem
          label="Require Authentication"
          description="All requests must include valid credentials"
        >
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.auth.require_auth}
              onChange={(e) =>
                setConfig({
                  ...config,
                  auth: { ...config.auth, require_auth: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">
              {config.auth.require_auth ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </SettingItem>

        <SettingItem
          label="Token Expiry (seconds)"
          description="JWT tokens expire after this duration"
        >
          <input
            type="number"
            value={config.auth.token_expiry_secs}
            onChange={(e) =>
              setConfig({
                ...config,
                auth: { ...config.auth, token_expiry_secs: Number(e.target.value) },
              })
            }
            className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white w-32"
          />
        </SettingItem>

        <SettingItem
          label="Multi-Factor Authentication"
          description="Require MFA for all users"
        >
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.auth.mfa_enabled}
              onChange={(e) =>
                setConfig({
                  ...config,
                  auth: { ...config.auth, mfa_enabled: e.target.checked },
                })
              }
              className="w-5 h-5"
            />
            <span className="text-gray-300">{config.auth.mfa_enabled ? 'Enabled' : 'Disabled'}</span>
          </label>
        </SettingItem>
      </Section>

      {/* Action Buttons */}
      <div className="flex gap-4 pt-6 border-t border-slate-700">
        <button
          onClick={saveSettings}
          disabled={saving}
          className="px-6 py-3 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 transition-colors font-semibold disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? 'Saving...' : 'Save Security Settings'}
        </button>
        <button
          onClick={fetchSettings}
          className="px-6 py-3 bg-slate-800 border border-slate-700 text-gray-300 rounded-lg hover:bg-slate-700 transition-colors font-semibold"
        >
          Revert Changes
        </button>
      </div>

      {/* Info Box */}
      <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4 text-sm text-blue-300">
        <p className="font-semibold mb-2">ℹ️ Configuration Tips</p>
        <ul className="space-y-1 list-disc list-inside">
          <li>Rate limit of 100,000 (1 lakh) requests is recommended for production</li>
          <li>Enable all validation checks for maximum security</li>
          <li>Bot detection helps identify automated attacks</li>
          <li>Changes take effect immediately</li>
        </ul>
      </div>
    </div>
  )
}

interface SectionProps {
  icon: React.ReactNode
  title: string
  enabled: boolean
  children: React.ReactNode
}

function Section({ icon, title, enabled, children }: SectionProps) {
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-6">
      <div className="flex items-center gap-3 mb-6">
        <div className={enabled ? 'text-cyan-400' : 'text-gray-500'}>{icon}</div>
        <h2 className={`text-xl font-semibold ${enabled ? 'text-white' : 'text-gray-500'}`}>
          {title}
        </h2>
        <span
          className={`ml-auto px-3 py-1 rounded-full text-xs font-semibold ${
            enabled
              ? 'bg-green-900/30 text-green-300'
              : 'bg-gray-900/30 text-gray-400'
          }`}
        >
          {enabled ? 'ENABLED' : 'DISABLED'}
        </span>
      </div>
      <div className="space-y-6">{children}</div>
    </div>
  )
}

interface SettingItemProps {
  label: string
  description?: string
  children: React.ReactNode
}

function SettingItem({ label, description, children }: SettingItemProps) {
  return (
    <div className="flex items-start justify-between py-4 border-b border-slate-800 last:border-b-0">
      <div className="flex-1 pr-4">
        <p className="font-semibold text-white mb-1">{label}</p>
        {description && <p className="text-sm text-gray-400">{description}</p>}
      </div>
      <div className="flex-1 flex justify-end">{children}</div>
    </div>
  )
}
