import { useEffect, useState } from 'react'
import { AlertCircle, AlertTriangle, Info, X } from 'lucide-react'
import { dashboardApi, AlertsData } from '../api'
import { useAppStore } from '../store'

export function Alerts() {
  const [alerts, setAlerts] = useState<AlertsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const selectedAlert = useAppStore((state) => state.selectedAlert)
  const selectAlert = useAppStore((state) => state.selectAlert)
  const dismissAlert = useAppStore((state) => state.dismissAlert)

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        setLoading(true)
        setError(null)
        const data = await dashboardApi.getAlerts()
        setAlerts(data)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch alerts')
      } finally {
        setLoading(false)
      }
    }

    fetchAlerts()
    const interval = setInterval(fetchAlerts, 3000)
    return () => clearInterval(interval)
  }, [])

  const handleDismiss = (alertId: string) => {
    dismissAlert(alertId)
    if (selectedAlert === alertId) {
      selectAlert(null)
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <AlertTriangle className="w-5 h-5 text-red-500" />
      case 'warning':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />
      case 'info':
        return <Info className="w-5 h-5 text-blue-500" />
      default:
        return <AlertCircle className="w-5 h-5 text-gray-500" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'border-red-700 bg-red-900 hover:bg-red-800'
      case 'warning':
        return 'border-yellow-700 bg-yellow-900 hover:bg-yellow-800'
      case 'info':
        return 'border-blue-700 bg-blue-900 hover:bg-blue-800'
      default:
        return 'border-gray-700 bg-gray-900 hover:bg-gray-800'
    }
  }

  const getSeverityBadgeColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-600 text-red-100'
      case 'warning':
        return 'bg-yellow-600 text-yellow-100'
      case 'info':
        return 'bg-blue-600 text-blue-100'
      default:
        return 'bg-gray-600 text-gray-100'
    }
  }

  if (loading && !alerts) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500 mx-auto mb-4"></div>
          <p className="text-cyan-400">Loading alerts...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-900 border border-red-700 rounded-lg p-4 text-red-200">
        <p>Error: {error}</p>
      </div>
    )
  }

  if (!alerts) {
    return null
  }

  const { summary, alerts: alertList } = alerts

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">Alerts</h1>
        <p className="text-gray-400">Monitor security alerts and system warnings</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SummaryCard
          label="Total Alerts"
          value={summary.total}
          color="blue"
          icon={<AlertCircle className="w-5 h-5" />}
        />
        <SummaryCard
          label="Critical"
          value={summary.critical}
          color="red"
          icon={<AlertTriangle className="w-5 h-5" />}
        />
        <SummaryCard
          label="Warnings"
          value={summary.warning}
          color="yellow"
          icon={<AlertCircle className="w-5 h-5" />}
        />
        <SummaryCard
          label="Info"
          value={summary.info}
          color="blue"
          icon={<Info className="w-5 h-5" />}
        />
      </div>

      {summary.requires_attention && (
        <div className="bg-red-900 border-l-4 border-red-500 rounded-lg p-4 mb-6">
          <p className="font-semibold text-red-100">⚠️ Immediate Action Required</p>
          <p className="text-red-200 text-sm mt-1">
            There are critical alerts that require immediate attention.
          </p>
        </div>
      )}

      {/* Alerts List */}
      <div className="space-y-3">
        {alertList.length > 0 ? (
          alertList.map((alert) => (
            <div
              key={alert.id}
              onClick={() => selectAlert(alert.id)}
              className={`border rounded-lg p-4 transition-colors cursor-pointer ${getSeverityColor(
                alert.severity,
              )} ${selectedAlert === alert.id ? 'ring-2 ring-cyan-500' : ''}`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start gap-4 flex-1">
                  <div className="mt-1">{getSeverityIcon(alert.severity)}</div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-semibold">{alert.title}</h3>
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityBadgeColor(
                          alert.severity,
                        )}`}
                      >
                        {alert.severity}
                      </span>
                    </div>
                    <p className="text-sm opacity-90">{alert.message}</p>
                    <p className="text-xs opacity-60 mt-2">
                      {new Date(alert.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    handleDismiss(alert.id)
                  }}
                  className="p-2 hover:bg-white hover:bg-opacity-10 rounded transition-colors flex-shrink-0"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Expanded details */}
              {selectedAlert === alert.id && (
                <div className="mt-4 pt-4 border-t border-white border-opacity-10">
                  <p className="text-sm mb-3">Additional Information:</p>
                  <div className="bg-black bg-opacity-30 rounded p-3 font-mono text-xs">
                    <p>Alert ID: {alert.id}</p>
                    <p>Category: {alert.title.split(':')[0]}</p>
                    <p>Timestamp: {new Date(alert.timestamp).toISOString()}</p>
                  </div>
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="bg-slate-900 border border-slate-700 rounded-lg p-8 text-center">
            <AlertCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
            <p className="text-gray-400">No alerts at the moment. System is running normally!</p>
          </div>
        )}
      </div>

      {/* Pagination or Load More */}
      {alertList.length > 10 && (
        <div className="text-center pt-4">
          <button className="px-6 py-2 bg-slate-800 border border-slate-700 rounded-lg text-gray-300 hover:bg-slate-700 transition-colors">
            Load More Alerts
          </button>
        </div>
      )}
    </div>
  )
}

interface SummaryCardProps {
  label: string
  value: number
  color: 'red' | 'yellow' | 'blue'
  icon: React.ReactNode
}

function SummaryCard({ label, value, color, icon }: SummaryCardProps) {
  const colorClass = {
    red: 'bg-red-900 border-red-700',
    yellow: 'bg-yellow-900 border-yellow-700',
    blue: 'bg-blue-900 border-blue-700',
  }[color]

  const iconColorClass = {
    red: 'text-red-400',
    yellow: 'text-yellow-400',
    blue: 'text-blue-400',
  }[color]

  return (
    <div className={`${colorClass} border rounded-lg p-4`}>
      <div className="flex items-start justify-between mb-2">
        <p className="text-sm text-gray-300">{label}</p>
        <div className={iconColorClass}>{icon}</div>
      </div>
      <p className="text-3xl font-bold">{value}</p>
    </div>
  )
}
