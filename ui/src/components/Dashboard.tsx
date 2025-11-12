import { useEffect, useState } from 'react'
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import {
  AlertTriangle,
  AlertCircle,
  Shield,
  TrendingUp,
  Clock,
  Lock,
  Eye,
} from 'lucide-react'
import { dashboardApi, DashboardData } from '../api'
import { useAppStore } from '../store'

const getThreatColor = (level: string) => {
  switch (level?.toLowerCase()) {
    case 'critical':
      return '#ff1744'
    case 'high':
      return '#ff5722'
    case 'medium':
      return '#ffc107'
    case 'low':
      return '#4caf50'
    default:
      return '#2196f3'
  }
}

const getThreatBgColor = (level: string) => {
  switch (level?.toLowerCase()) {
    case 'critical':
      return 'bg-red-900'
    case 'high':
      return 'bg-orange-900'
    case 'medium':
      return 'bg-yellow-900'
    case 'low':
      return 'bg-green-900'
    default:
      return 'bg-blue-900'
  }
}

export function Dashboard() {
  const [chartData, setChartData] = useState<any[]>([])
  const [chartHistory, setChartHistory] = useState<any[]>([])
  const dashboard = useAppStore((state) => state.dashboard)
  const setDashboard = useAppStore((state) => state.setDashboard)
  const loading = useAppStore((state) => state.loading)
  const setLoading = useAppStore((state) => state.setLoading)
  const error = useAppStore((state) => state.error)
  const setError = useAppStore((state) => state.setError)
  const settings = useAppStore((state) => state.settings)

  useEffect(() => {
    const fetchDashboard = async () => {
      try {
        setLoading(true)
        setError(null)
        const data = await dashboardApi.getDashboard()
        setDashboard(data)

        // Update chart history and generate data
        const now = new Date()
        setChartHistory(prev => {
          const updated = [...prev, {
            time: now.toLocaleTimeString(),
            requests: data.metrics.total_requests,
            blocked: Math.floor(data.metrics.block_rate * 100),
          }]
          const latest = updated.slice(-6)
          
          // Generate chart data with proper time spacing
          const data_points = latest.map((point, index) => ({
            ...point,
            time: new Date(now.getTime() - (latest.length - 1 - index) * 60000).toLocaleTimeString(),
          }))
          setChartData(data_points)
          
          return latest
        })
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch dashboard')
      } finally {
        setLoading(false)
      }
    }

    fetchDashboard()

    if (settings.autoRefresh) {
      const interval = setInterval(fetchDashboard, settings.refreshInterval)
      return () => clearInterval(interval)
    }
  }, [settings.autoRefresh, settings.refreshInterval, setDashboard, setLoading, setError])

  if (loading && !dashboard) {
    return (
      <div className="flex items-center justify-center h-screen bg-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500 mx-auto mb-4"></div>
          <p className="text-cyan-400">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen bg-slate-900">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <p className="text-red-400">{error}</p>
        </div>
      </div>
    )
  }

  if (!dashboard) {
    return null
  }

  const { metrics, threat_level, top_blocked_ips, security_status, uptime_seconds } = dashboard

  const uptimeHours = Math.floor(uptime_seconds / 3600)
  const uptimeMinutes = Math.floor((uptime_seconds % 3600) / 60)

  return (
    <div className={`min-h-screen ${settings.theme === 'dark' ? 'gradient-bg' : 'bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/50'} text-${settings.theme === 'dark' ? 'white' : 'slate-900'} p-6 animate-fade-in`}>
      {/* Threat Level Alert */}
      <div
        className={`${
          settings.theme === 'dark'
            ? `${getThreatBgColor(threat_level)} glass-card`
            : 'glass-card bg-gradient-to-r from-red-50/80 to-orange-50/80 border-red-200/50'
        } rounded-3xl p-8 mb-8 border-l-4 ${
          threat_level.toLowerCase() === 'critical' ? 'border-red-500' :
          threat_level.toLowerCase() === 'high' ? 'border-orange-500' :
          threat_level.toLowerCase() === 'medium' ? 'border-yellow-500' :
          threat_level.toLowerCase() === 'low' ? 'border-green-500' : 'border-blue-500'
        } card-hover animate-glow`}
      >
        <div className="flex items-center gap-6">
          <div className={`p-4 rounded-2xl ${
            settings.theme === 'dark'
              ? 'bg-red-500/20 border border-red-500/30'
              : 'bg-red-100/80 border border-red-200/50'
          }`}>
            <AlertTriangle className={`w-10 h-10 ${
              settings.theme === 'dark' ? 'text-red-400' : 'text-red-600'
            }`} />
          </div>
          <div className="flex-1">
            <h2 className={`text-3xl font-bold ${
              settings.theme === 'dark' ? 'text-white' : 'text-slate-900'
            } mb-2`}>Threat Level: {threat_level.toUpperCase()}</h2>
            <p className={`text-lg ${
              settings.theme === 'dark' ? 'text-gray-300' : 'text-slate-700'
            }`}>
              {(metrics.blocked_requests + metrics.validation_failures + metrics.rate_limited + metrics.auth_failures)} total blocks · {((metrics.blocked_requests + metrics.validation_failures + metrics.rate_limited + metrics.auth_failures) as any / metrics.total_requests * 100).toFixed(2)}% block rate
            </p>
          </div>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <MetricCard
          label="Total Requests"
          value={metrics.total_requests}
          icon={<TrendingUp className="w-5 h-5" />}
          color="blue"
          theme={settings.theme}
        />
        <MetricCard
          label="Blocked Requests"
          value={metrics.blocked_requests}
          icon={<Lock className="w-5 h-5" />}
          color="red"
          theme={settings.theme}
        />
        <MetricCard
          label="Rate Limited"
          value={metrics.rate_limited}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="yellow"
          theme={settings.theme}
        />
        <MetricCard
          label="Auth Failures"
          value={metrics.auth_failures}
          icon={<Eye className="w-5 h-5" />}
          color="purple"
          theme={settings.theme}
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        <ChartCard title="Request Trends" theme={settings.theme}>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(30, 41, 59, 0.9)',
                  border: '1px solid rgba(71, 85, 105, 0.3)',
                  borderRadius: '8px',
                  backdropFilter: 'blur(10px)',
                  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
                }}
              />
              <Legend />
              <Line
                type="monotone"
                dataKey="requests"
                stroke="#0ea5e9"
                strokeWidth={3}
                dot={{ fill: '#0ea5e9', strokeWidth: 2, r: 4 }}
                activeDot={{ r: 6, stroke: '#0ea5e9', strokeWidth: 2, fill: '#1e293b' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Block Rate" theme={settings.theme}>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(30, 41, 59, 0.9)',
                  border: '1px solid rgba(71, 85, 105, 0.3)',
                  borderRadius: '8px',
                  backdropFilter: 'blur(10px)',
                  boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
                }}
              />
              <Bar dataKey="blocked" fill="#ef4444" radius={[4, 4, 0, 0]}>
                {chartData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill={`rgba(239, 68, 68, ${0.6 + (index * 0.1)})`} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Top Blocked IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <ChartCard title="Top Blocked IPs" theme={settings.theme}>
          <div className="space-y-4">
            {top_blocked_ips.length > 0 ? (
              top_blocked_ips.map((ip: any, idx: number) => (
                <div key={idx} className="glass-morphism rounded-2xl p-4 card-hover border border-slate-600/30">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                      <div>
                        <p className={`font-mono ${settings.theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'} font-semibold`}>{ip.ip}</p>
                        <p className={`text-sm ${settings.theme === 'dark' ? 'text-gray-400' : 'text-slate-500'}`}>{ip.reason}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className={`text-2xl font-bold ${settings.theme === 'dark' ? 'text-red-400' : 'text-red-600'}`}>{ip.block_count}</p>
                      <p className={`text-xs ${settings.theme === 'dark' ? 'text-gray-400' : 'text-slate-500'}`}>blocks</p>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8">
                <Shield className={`w-12 h-12 ${settings.theme === 'dark' ? 'text-green-400' : 'text-green-600'} mx-auto mb-4 opacity-50`} />
                <p className={`${settings.theme === 'dark' ? 'text-gray-400' : 'text-slate-500'}`}>No blocked IPs - System secure!</p>
              </div>
            )}
          </div>
        </ChartCard>

        <ChartCard title="Security Status" theme={settings.theme}>
          <div className="space-y-4">
            <StatusItem
              label="Overall Status"
              status={security_status.overall}
              enabled={security_status.overall === 'secure'}
              theme={settings.theme}
            />
            <StatusItem
              label="Rate Limiting"
              status={security_status.rate_limit_enabled ? 'Enabled' : 'Disabled'}
              enabled={security_status.rate_limit_enabled}
              theme={settings.theme}
            />
            <StatusItem
              label="Input Validation"
              status={security_status.validation_enabled ? 'Enabled' : 'Disabled'}
              enabled={security_status.validation_enabled}
              theme={settings.theme}
            />
            <StatusItem
              label="Authentication"
              status={security_status.auth_enabled ? 'Enabled' : 'Disabled'}
              enabled={security_status.auth_enabled}
              theme={settings.theme}
            />
            <div className={`pt-6 ${settings.theme === 'dark' ? 'border-t border-slate-700/50' : 'border-t border-slate-200/50'} flex items-center gap-4 glass-morphism rounded-2xl p-4`}>
              <div className="p-3 rounded-lg bg-gradient-to-br from-green-400 to-cyan-400">
                <Clock className="w-5 h-5 text-slate-900" />
              </div>
              <div>
                <p className={`text-sm ${settings.theme === 'dark' ? 'text-gray-400' : 'text-slate-500'} font-medium`}>System Uptime</p>
                <p className={`text-xl font-mono ${settings.theme === 'dark' ? 'text-cyan-400' : 'text-cyan-600'} font-bold`}>
                  {uptimeHours}h {uptimeMinutes}m
                </p>
              </div>
            </div>
          </div>
        </ChartCard>
      </div>
    </div>
  )
}

interface MetricCardProps {
  label: string
  value: number
  icon: React.ReactNode
  color: 'blue' | 'red' | 'yellow' | 'purple'
  theme?: 'dark' | 'light'
}

function MetricCard({ label, value, icon, color, theme = 'dark' }: MetricCardProps) {
  const colorClass = {
    blue: 'metric-gradient-blue border-blue-500/30',
    red: 'metric-gradient-red border-red-500/30',
    yellow: 'metric-gradient-yellow border-yellow-500/30',
    purple: 'metric-gradient-purple border-purple-500/30',
  }[color]

  const iconColorClass = {
    blue: 'text-blue-400',
    red: 'text-red-400',
    yellow: 'text-yellow-400',
    purple: 'text-purple-400',
  }[color]

  const glowClass = {
    blue: 'hover:shadow-blue-500/20',
    red: 'hover:shadow-red-500/20',
    yellow: 'hover:shadow-yellow-500/20',
    purple: 'hover:shadow-purple-500/20',
  }[color]

  return (
    <div className={`glass-card rounded-3xl p-6 card-hover hover:shadow-2xl ${colorClass} ${glowClass} transition-all duration-300 animate-float`}>
      <div className="flex items-start justify-between mb-4">
        <div className={`p-3 rounded-2xl bg-white/10 ${iconColorClass}`}>
          {icon}
        </div>
      </div>
      <div className="space-y-2">
        <p className={`text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-slate-600'} font-medium`}>{label}</p>
        <p className={`text-4xl font-bold ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>{value.toLocaleString()}</p>
      </div>
      <div className="mt-4 h-1 bg-gradient-to-r from-transparent via-white/20 to-transparent rounded-full"></div>
    </div>
  )
}

interface ChartCardProps {
  title: string
  children: React.ReactNode
  theme?: 'dark' | 'light'
}

function ChartCard({ title, children, theme = 'dark' }: ChartCardProps) {
  return (
    <div className="glass-card rounded-3xl p-6 card-hover hover:shadow-2xl transition-all duration-300">
      <h3 className={`text-xl font-semibold mb-6 flex items-center gap-3 ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>
        <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-400 to-green-400">
          <Shield className="w-5 h-5 text-slate-900" />
        </div>
        {title}
      </h3>
      <div className="animate-fade-in">
        {children}
      </div>
    </div>
  )
}

interface StatusItemProps {
  label: string
  status: string
  enabled: boolean
  theme?: 'dark' | 'light'
}

function StatusItem({ label, status, enabled, theme = 'dark' }: StatusItemProps) {
  return (
    <div className="glass-morphism rounded-2xl p-4 card-hover border border-slate-600/30">
      <div className="flex items-center justify-between">
        <p className={`text-sm ${theme === 'dark' ? 'text-gray-300' : 'text-slate-600'} font-medium`}>{label}</p>
        <div className="flex items-center gap-3">
          <div
            className={`w-3 h-3 rounded-full animate-pulse ${
              enabled ? 'bg-green-500 shadow-green-500/50 shadow-lg' : 'bg-red-500 shadow-red-500/50 shadow-lg'
            }`}
          ></div>
          <p className={`text-sm font-mono font-semibold ${
            enabled
              ? (theme === 'dark' ? 'text-green-400' : 'text-green-600')
              : (theme === 'dark' ? 'text-red-400' : 'text-red-600')
          }`}>
            {status}
          </p>
        </div>
      </div>
    </div>
  )
}
