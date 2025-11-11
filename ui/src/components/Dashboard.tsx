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
    <div className="min-h-screen bg-slate-950 text-white p-6">
      {/* Threat Level Alert */}
      <div
        className={`${getThreatBgColor(threat_level)} rounded-lg p-6 mb-8 border-l-4 border-red-500`}
      >
        <div className="flex items-center gap-4">
          <AlertTriangle className="w-8 h-8 flex-shrink-0" />
          <div className="flex-1">
            <h2 className="text-2xl font-bold">Threat Level: {threat_level.toUpperCase()}</h2>
            <p className="text-sm opacity-80">
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
        />
        <MetricCard
          label="Blocked Requests"
          value={metrics.blocked_requests}
          icon={<Lock className="w-5 h-5" />}
          color="red"
        />
        <MetricCard
          label="Rate Limited"
          value={metrics.rate_limited}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="yellow"
        />
        <MetricCard
          label="Auth Failures"
          value={metrics.auth_failures}
          icon={<Eye className="w-5 h-5" />}
          color="purple"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        <ChartCard title="Request Trends">
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #475569',
                }}
              />
              <Legend />
              <Line type="monotone" dataKey="requests" stroke="#0ea5e9" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Block Rate">
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #475569',
                }}
              />
              <Bar dataKey="blocked" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* Top Blocked IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <ChartCard title="Top Blocked IPs">
          <div className="space-y-4">
            {top_blocked_ips.length > 0 ? (
              top_blocked_ips.map((ip, idx) => (
                <div key={idx} className="flex items-center justify-between bg-slate-900 p-3 rounded">
                  <div>
                    <p className="font-mono text-cyan-400">{ip.ip}</p>
                    <p className="text-xs text-gray-400">{ip.reason}</p>
                  </div>
                  <div className="text-right">
                    <p className="font-bold text-red-400">{ip.block_count}</p>
                    <p className="text-xs text-gray-400">blocks</p>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-gray-400">No blocked IPs</p>
            )}
          </div>
        </ChartCard>

        <ChartCard title="Security Status">
          <div className="space-y-4">
            <StatusItem
              label="Overall Status"
              status={security_status.overall}
              enabled={security_status.overall === 'secure'}
            />
            <StatusItem
              label="Rate Limiting"
              status={security_status.rate_limit_enabled ? 'Enabled' : 'Disabled'}
              enabled={security_status.rate_limit_enabled}
            />
            <StatusItem
              label="Input Validation"
              status={security_status.validation_enabled ? 'Enabled' : 'Disabled'}
              enabled={security_status.validation_enabled}
            />
            <StatusItem
              label="Authentication"
              status={security_status.auth_enabled ? 'Enabled' : 'Disabled'}
              enabled={security_status.auth_enabled}
            />
            <div className="pt-4 border-t border-slate-700 flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <div>
                <p className="text-sm text-gray-400">Uptime</p>
                <p className="font-mono text-cyan-400">
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
}

function MetricCard({ label, value, icon, color }: MetricCardProps) {
  const colorClass = {
    blue: 'bg-blue-900 border-blue-700',
    red: 'bg-red-900 border-red-700',
    yellow: 'bg-yellow-900 border-yellow-700',
    purple: 'bg-purple-900 border-purple-700',
  }[color]

  const iconColorClass = {
    blue: 'text-blue-400',
    red: 'text-red-400',
    yellow: 'text-yellow-400',
    purple: 'text-purple-400',
  }[color]

  return (
    <div className={`${colorClass} border rounded-lg p-4`}>
      <div className="flex items-start justify-between mb-2">
        <p className="text-sm text-gray-300">{label}</p>
        <div className={iconColorClass}>{icon}</div>
      </div>
      <p className="text-3xl font-bold">{value.toLocaleString()}</p>
    </div>
  )
}

interface ChartCardProps {
  title: string
  children: React.ReactNode
}

function ChartCard({ title, children }: ChartCardProps) {
  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 p-6">
      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Shield className="w-5 h-5 text-cyan-400" />
        {title}
      </h3>
      {children}
    </div>
  )
}

interface StatusItemProps {
  label: string
  status: string
  enabled: boolean
}

function StatusItem({ label, status, enabled }: StatusItemProps) {
  return (
    <div className="flex items-center justify-between bg-slate-800 p-3 rounded">
      <p className="text-sm text-gray-300">{label}</p>
      <div className="flex items-center gap-2">
        <div
          className={`w-2 h-2 rounded-full ${enabled ? 'bg-green-500' : 'bg-red-500'}`}
        ></div>
        <p className={`text-sm font-mono ${enabled ? 'text-green-400' : 'text-red-400'}`}>
          {status}
        </p>
      </div>
    </div>
  )
}
