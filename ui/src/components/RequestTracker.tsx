import { useEffect, useState } from 'react'
import { Search, Filter, ChevronDown } from 'lucide-react'
import { dashboardApi } from '../api'
import { useAppStore } from '../store'

interface Request {
  method: string
  path: string
  count: number
  percentage: number
  status: 'success' | 'blocked' | 'rate_limited' | 'validation_error' | 'auth_error'
}

export function RequestTracker() {
  const [requests, setRequests] = useState<Request[]>([])
  const [filteredRequests, setFilteredRequests] = useState<Request[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [sortBy, setSortBy] = useState<'count' | 'percentage'>('count')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchRequests = async () => {
      try {
        setLoading(true)
        setError(null)
        const data = await dashboardApi.getDashboard()
        // Mock data - would come from API
        const mockRequests: Request[] = [
          {
            method: 'GET',
            path: '/api/v1/users',
            count: 2450,
            percentage: 45.2,
            status: 'success',
          },
          {
            method: 'POST',
            path: '/api/v1/login',
            count: 1230,
            percentage: 22.8,
            status: 'success',
          },
          {
            method: 'GET',
            path: '/api/v1/data',
            count: 890,
            percentage: 16.4,
            status: 'blocked',
          },
          {
            method: 'PUT',
            path: '/api/v1/update',
            count: 420,
            percentage: 7.8,
            status: 'rate_limited',
          },
          {
            method: 'DELETE',
            path: '/api/v1/delete',
            count: 150,
            percentage: 2.8,
            status: 'validation_error',
          },
          {
            method: 'POST',
            path: '/api/v1/auth',
            count: 95,
            percentage: 1.8,
            status: 'auth_error',
          },
        ]
        setRequests(mockRequests)
        setFilteredRequests(mockRequests)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch requests')
      } finally {
        setLoading(false)
      }
    }

    fetchRequests()
    const interval = setInterval(fetchRequests, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    let filtered = requests
    if (searchTerm) {
      filtered = filtered.filter(
        (r) =>
          r.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
          r.method.toLowerCase().includes(searchTerm.toLowerCase()),
      )
    }
    if (filterStatus !== 'all') {
      filtered = filtered.filter((r) => r.status === filterStatus)
    }
    if (sortBy === 'count') {
      filtered = [...filtered].sort((a, b) => b.count - a.count)
    } else {
      filtered = [...filtered].sort((a, b) => b.percentage - a.percentage)
    }
    setFilteredRequests(filtered)
  }, [searchTerm, filterStatus, sortBy, requests])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success':
        return 'bg-green-900 text-green-200'
      case 'blocked':
        return 'bg-red-900 text-red-200'
      case 'rate_limited':
        return 'bg-yellow-900 text-yellow-200'
      case 'validation_error':
        return 'bg-orange-900 text-orange-200'
      case 'auth_error':
        return 'bg-purple-900 text-purple-200'
      default:
        return 'bg-gray-900 text-gray-200'
    }
  }

  if (loading && requests.length === 0) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyan-500 mx-auto mb-4"></div>
          <p className="text-cyan-400">Loading requests...</p>
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">Request Tracker</h1>
        <p className="text-gray-400">Monitor and analyze API requests</p>
      </div>

      {/* Controls */}
      <div className="flex flex-col md:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-3 w-5 h-5 text-gray-500" />
          <input
            type="text"
            placeholder="Search requests..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="all">All Status</option>
          <option value="success">Success</option>
          <option value="blocked">Blocked</option>
          <option value="rate_limited">Rate Limited</option>
          <option value="validation_error">Validation Error</option>
          <option value="auth_error">Auth Error</option>
        </select>

        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as 'count' | 'percentage')}
          className="bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="count">Sort by Count</option>
          <option value="percentage">Sort by Percentage</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-700 bg-slate-800">
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-300">Method</th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-300">Path</th>
                <th className="px-6 py-3 text-right text-sm font-semibold text-gray-300">Count</th>
                <th className="px-6 py-3 text-right text-sm font-semibold text-gray-300">Percentage</th>
                <th className="px-6 py-3 text-left text-sm font-semibold text-gray-300">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredRequests.map((req, idx) => (
                <tr key={idx} className="border-b border-slate-700 hover:bg-slate-800 transition">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="font-mono font-bold text-cyan-400">{req.method}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className="font-mono text-gray-300">{req.path}</span>
                  </td>
                  <td className="px-6 py-4 text-right text-white font-semibold">
                    {req.count.toLocaleString()}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-end justify-end gap-2">
                      <div className="w-32 h-6 bg-slate-700 rounded overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400"
                          style={{ width: `${req.percentage}%` }}
                        ></div>
                      </div>
                      <span className="text-gray-400 text-sm w-12 text-right">
                        {req.percentage.toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusColor(
                        req.status,
                      )}`}
                    >
                      {req.status.replace(/_/g, ' ')}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredRequests.length === 0 && (
          <div className="px-6 py-8 text-center text-gray-400">
            <p>No requests found matching your filters</p>
          </div>
        )}
      </div>

      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <p className="text-gray-400 text-sm mb-2">Total Requests</p>
          <p className="text-2xl font-bold text-cyan-400">
            {requests.reduce((sum, r) => sum + r.count, 0).toLocaleString()}
          </p>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <p className="text-gray-400 text-sm mb-2">Success Rate</p>
          <p className="text-2xl font-bold text-green-400">
            {(
              (requests.find((r) => r.status === 'success')?.percentage || 0) +
              (requests.find((r) => r.status === 'success')?.percentage || 0)
            ).toFixed(1)}
            %
          </p>
        </div>
        <div className="bg-slate-900 border border-slate-700 rounded-lg p-4">
          <p className="text-gray-400 text-sm mb-2">Blocked Requests</p>
          <p className="text-2xl font-bold text-red-400">
            {requests.find((r) => r.status === 'blocked')?.count || 0}
          </p>
        </div>
      </div>
    </div>
  )
}
