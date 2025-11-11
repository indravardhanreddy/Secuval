import { create } from 'zustand'
import { DashboardData, MetricsData, AlertsData } from '../api'

interface AppState {
  dashboard: DashboardData | null
  metrics: MetricsData | null
  alerts: AlertsData | null
  loading: boolean
  error: string | null
  lastUpdated: Date | null
  selectedAlert: string | null
  settings: {
    autoRefresh: boolean
    refreshInterval: number
    theme: 'dark' | 'light'
    threatAlertLevel: string
  }

  // Actions
  setDashboard: (data: DashboardData) => void
  setMetrics: (data: MetricsData) => void
  setAlerts: (data: AlertsData) => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
  selectAlert: (alertId: string | null) => void
  updateSettings: (settings: Partial<AppState['settings']>) => void
  dismissAlert: (alertId: string) => void
  reset: () => void
}

const initialState = {
  dashboard: null,
  metrics: null,
  alerts: null,
  loading: false,
  error: null,
  lastUpdated: null,
  selectedAlert: null,
  settings: {
    autoRefresh: true,
    refreshInterval: 3000,
    theme: 'dark' as const,
    threatAlertLevel: 'warning',
  },
}

export const useAppStore = create<AppState>((set) => ({
  ...initialState,

  setDashboard: (data) =>
    set({
      dashboard: data,
      lastUpdated: new Date(),
    }),

  setMetrics: (data) =>
    set({
      metrics: data,
    }),

  setAlerts: (data) =>
    set({
      alerts: data,
    }),

  setLoading: (loading) =>
    set({
      loading,
    }),

  setError: (error) =>
    set({
      error,
    }),

  selectAlert: (alertId) =>
    set({
      selectedAlert: alertId,
    }),

  updateSettings: (newSettings) =>
    set((state) => ({
      settings: {
        ...state.settings,
        ...newSettings,
      },
    })),

  dismissAlert: (alertId) =>
    set((state) => {
      if (!state.alerts) return state
      return {
        alerts: {
          ...state.alerts,
          alerts: state.alerts.alerts.filter((a) => a.id !== alertId),
          summary: {
            ...state.alerts.summary,
            total: Math.max(0, state.alerts.summary.total - 1),
          },
        },
      }
    }),

  reset: () => set(initialState),
}))
