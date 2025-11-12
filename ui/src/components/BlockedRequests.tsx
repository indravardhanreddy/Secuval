import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Clock, Globe, Code, Search, ChevronDown, ChevronUp } from 'lucide-react';

interface BlockedRequest {
  id: string;
  timestamp: string;
  client_ip: string;
  user_agent: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  payload?: string;
  threat_score: number;
  block_reason: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  user_id?: string;
  request_size: number;
}

interface BlockedRequestsStats {
  total_blocked: number;
  by_reason: Record<string, number>;
  by_ip: Record<string, number>;
  by_severity: Record<string, number>;
  recent_activity: string[];
}

interface BlockedRequestsResponse {
  requests: BlockedRequest[];
  total: number;
  stats: BlockedRequestsStats;
}

const BlockedRequests: React.FC = () => {
  const [requests, setRequests] = useState<BlockedRequest[]>([]);
  const [stats, setStats] = useState<BlockedRequestsStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [expandedRequest, setExpandedRequest] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [limit] = useState(50);

  useEffect(() => {
    fetchBlockedRequests();
  }, [currentPage, filter, severityFilter]);

  const fetchBlockedRequests = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        limit: limit.toString(),
        offset: ((currentPage - 1) * limit).toString(),
      });

      if (filter) params.append('reason', filter);
      if (severityFilter !== 'all') params.append('severity', severityFilter);

      const response = await fetch(`/api/blocked-requests?${params}`);
      if (!response.ok) throw new Error('Failed to fetch blocked requests');

      const data: BlockedRequestsResponse = await response.json();
      setRequests(data.requests);
      setStats(data.stats);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-500 bg-red-500/20';
      case 'High': return 'text-orange-500 bg-orange-500/20';
      case 'Medium': return 'text-yellow-500 bg-yellow-500/20';
      case 'Low': return 'text-green-500 bg-green-500/20';
      default: return 'text-gray-500 bg-gray-500/20';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const toggleExpanded = (id: string) => {
    setExpandedRequest(expandedRequest === id ? null : id);
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
            <span className="text-red-500">Error: {error}</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Shield className="h-8 w-8 text-red-500" />
          <div>
            <h1 className="text-2xl font-bold">Blocked Requests</h1>
            <p className="text-sm opacity-70">Monitor and analyze blocked security threats</p>
          </div>
        </div>
        <button
          onClick={fetchBlockedRequests}
          className="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg transition-colors"
        >
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-500/20 to-red-600/20 backdrop-blur-sm border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm opacity-70">Total Blocked</p>
                <p className="text-2xl font-bold">{stats.total_blocked}</p>
              </div>
              <Shield className="h-8 w-8 text-red-500" />
            </div>
          </div>

          <div className="bg-gradient-to-br from-orange-500/20 to-orange-600/20 backdrop-blur-sm border border-orange-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm opacity-70">High Severity</p>
                <p className="text-2xl font-bold">{stats.by_severity['High'] || 0}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-orange-500" />
            </div>
          </div>

          <div className="bg-gradient-to-br from-blue-500/20 to-blue-600/20 backdrop-blur-sm border border-blue-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm opacity-70">Unique IPs</p>
                <p className="text-2xl font-bold">{Object.keys(stats.by_ip).length}</p>
              </div>
              <Globe className="h-8 w-8 text-blue-500" />
            </div>
          </div>

          <div className="bg-gradient-to-br from-purple-500/20 to-purple-600/20 backdrop-blur-sm border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm opacity-70">Recent Activity</p>
                <p className="text-2xl font-bold">{stats.recent_activity.length}</p>
              </div>
              <Clock className="h-8 w-8 text-purple-500" />
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 opacity-50" />
          <input
            type="text"
            placeholder="Filter by block reason..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-4 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="all">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>

      {/* Requests List */}
      <div className="space-y-4">
        {requests.map((request) => (
          <div
            key={request.id}
            className="bg-white/10 backdrop-blur-sm border border-white/20 rounded-xl overflow-hidden"
          >
            {/* Request Header */}
            <div
              className="p-4 cursor-pointer hover:bg-white/5 transition-colors"
              onClick={() => toggleExpanded(request.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(request.severity)}`}>
                    {request.severity}
                  </div>
                  <span className="font-mono text-sm">{request.method}</span>
                  <span className="text-sm truncate max-w-md">{request.url}</span>
                  <span className="text-sm opacity-70">{request.client_ip}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-sm opacity-70">
                    {formatTimestamp(request.timestamp)}
                  </span>
                  {expandedRequest === request.id ? (
                    <ChevronUp className="h-4 w-4" />
                  ) : (
                    <ChevronDown className="h-4 w-4" />
                  )}
                </div>
              </div>
              <div className="mt-2 text-sm opacity-70">
                {request.block_reason}
              </div>
            </div>

            {/* Expanded Details */}
            {expandedRequest === request.id && (
              <div className="border-t border-white/20 p-4 space-y-4">
                {/* Basic Info */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="opacity-70">Threat Score:</span>
                    <span className="ml-2 font-mono">{request.threat_score}</span>
                  </div>
                  <div>
                    <span className="opacity-70">Request Size:</span>
                    <span className="ml-2 font-mono">{request.request_size} bytes</span>
                  </div>
                  <div>
                    <span className="opacity-70">User Agent:</span>
                    <span className="ml-2 truncate" title={request.user_agent}>
                      {request.user_agent.substring(0, 30)}...
                    </span>
                  </div>
                  {request.user_id && (
                    <div>
                      <span className="opacity-70">User ID:</span>
                      <span className="ml-2 font-mono">{request.user_id}</span>
                    </div>
                  )}
                </div>

                {/* Headers */}
                <div>
                  <h4 className="text-sm font-medium mb-2 flex items-center">
                    <Code className="h-4 w-4 mr-2" />
                    Headers
                  </h4>
                  <div className="bg-black/20 rounded p-3 font-mono text-xs max-h-32 overflow-y-auto">
                    {Object.entries(request.headers).map(([key, value]) => (
                      <div key={key} className="mb-1">
                        <span className="text-blue-400">{key}:</span> {value}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Payload */}
                {request.payload && (
                  <div>
                    <h4 className="text-sm font-medium mb-2 flex items-center">
                      <Code className="h-4 w-4 mr-2" />
                      Request Payload
                    </h4>
                    <div className="bg-black/20 rounded p-3 font-mono text-xs max-h-32 overflow-y-auto">
                      {request.payload}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}

        {requests.length === 0 && !loading && (
          <div className="text-center py-12">
            <Shield className="h-12 w-12 opacity-50 mx-auto mb-4" />
            <p className="text-lg opacity-70">No blocked requests found</p>
            <p className="text-sm opacity-50">Requests that are blocked by security rules will appear here</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {stats && stats.total_blocked > limit && (
        <div className="flex justify-center space-x-2">
          <button
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
            className="px-4 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-white/20 transition-colors"
          >
            Previous
          </button>
          <span className="px-4 py-2">
            Page {currentPage} of {Math.ceil(stats.total_blocked / limit)}
          </span>
          <button
            onClick={() => setCurrentPage(currentPage + 1)}
            disabled={currentPage * limit >= stats.total_blocked}
            className="px-4 py-2 bg-white/10 backdrop-blur-sm border border-white/20 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-white/20 transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};

export default BlockedRequests;