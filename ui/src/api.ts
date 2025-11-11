import axios from 'axios'

// Use relative path to leverage Vite's proxy configuration
// @ts-ignore
const API_BASE_URL = import.meta.env.VITE_API_URL || ''

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

export interface DashboardData {
  metrics: {
    total_requests: number
    blocked_requests: number
    rate_limited: number
    validation_failures: number
    auth_failures: number
    block_rate: number
  }
  threat_level: string
  top_blocked_ips: Array<{
    ip: string
    block_count: number
    reason: string
  }>
  security_status: {
    overall: string
    rate_limit_enabled: boolean
    validation_enabled: boolean
    auth_enabled: boolean
  }
  uptime_seconds: number
}

export interface MetricsData {
  timestamp: string
  total_requests: number
  blocked_requests: number
  rate_limited: number
  validation_failures: number
  auth_failures: number
  block_rate: number
  avg_response_time_ms: number
  p95_response_time_ms: number
  p99_response_time_ms: number
  requests_per_second: number
}

export interface AlertsData {
  summary: {
    total: number
    critical: number
    warning: number
    info: number
    requires_attention: boolean
  }
  alerts: Array<{
    id: string
    title: string
    message: string
    severity: string
    timestamp: string
  }>
}

export const dashboardApi = {
  getDashboard: async (): Promise<DashboardData> => {
    const res = await apiClient.get('/api/ui/dashboard')
    return res.data.data
  },

  getMetrics: async (): Promise<MetricsData> => {
    const res = await apiClient.get('/api/ui/metrics')
    return res.data.data
  },

  getAlerts: async (): Promise<AlertsData> => {
    const res = await apiClient.get('/api/ui/alerts')
    return res.data.data
  },

  trackRequest: async (payload: any) => {
    const res = await apiClient.post('/api/ui/request/track', payload)
    return res.data
  },

  dismissAlert: async (alertId: string) => {
    const res = await apiClient.post(`/api/ui/alerts/${alertId}/dismiss`)
    return res.data
  },

  getSecuritySettings: async () => {
    const res = await apiClient.get('/api/ui/settings')
    return res.data.data
  },

  updateSecuritySettings: async (settings: any) => {
    const res = await apiClient.put('/api/ui/settings', settings)
    return res.data
  },

  getBlockedIPs: async () => {
    const res = await apiClient.get('/api/ui/blocked-ips')
    return res.data.data
  },
}
