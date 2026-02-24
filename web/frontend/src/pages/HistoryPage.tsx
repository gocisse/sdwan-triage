// History page with list of all analyses

import { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { 
  Loader2, 
  Trash2, 
  ExternalLink, 
  FileText, 
  Search,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import { listHistory, deleteAnalysis, ApiError } from '../api/client';
import type { AnalysisJob } from '../types';
import { formatBytes, formatRelativeTime, getStatusBadgeClasses } from '../utils';

export function HistoryPage() {
  const [jobs, setJobs] = useState<AnalysisJob[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadHistory = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await listHistory(50, 0);
      setJobs(response.items || []);
      setTotal(response.total);
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Failed to load history';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleDelete = useCallback(async (id: string) => {
    if (!confirm('Are you sure you want to delete this analysis?')) {
      return;
    }

    setDeletingId(id);

    try {
      await deleteAnalysis(id);
      setJobs((prev) => prev.filter((job) => job.id !== id));
      setTotal((prev) => prev - 1);
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Failed to delete analysis';
      alert(message);
    } finally {
      setDeletingId(null);
    }
  }, []);

  // Filter jobs by search query
  const filteredJobs = jobs.filter((job) =>
    job.file_name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Analysis History</h1>
          <p className="text-slate-400 text-sm">{total} analyses</p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={loadHistory}
            disabled={isLoading}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/" className="btn-primary">
            New Analysis
          </Link>
        </div>
      </div>

      {/* Search */}
      <div className="relative mb-6">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
        <input
          type="text"
          placeholder="Search by filename..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="input pl-10"
        />
      </div>

      {/* Error */}
      {error && (
        <div className="card p-4 mb-6 bg-red-500/10 border-red-500/30">
          <div className="flex items-center gap-2 text-red-400">
            <AlertCircle className="w-5 h-5" />
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!error && filteredJobs.length === 0 && (
        <div className="card p-12 text-center">
          <FileText className="w-12 h-12 text-slate-500 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">
            {searchQuery ? 'No matching analyses' : 'No analyses yet'}
          </h3>
          <p className="text-slate-400 text-sm mb-4">
            {searchQuery 
              ? 'Try a different search term'
              : 'Upload a PCAP file to get started'
            }
          </p>
          {!searchQuery && (
            <Link to="/" className="btn-primary inline-flex items-center gap-2">
              Upload File
            </Link>
          )}
        </div>
      )}

      {/* Job list */}
      {filteredJobs.length > 0 && (
        <div className="card overflow-hidden">
          {/* Desktop table */}
          <div className="hidden md:block overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">File</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Size</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Status</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Date</th>
                  <th className="px-4 py-3 text-right text-slate-400 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {filteredJobs.map((job) => (
                  <tr key={job.id} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <FileText className="w-5 h-5 text-slate-400 flex-shrink-0" />
                        <span className="text-white font-medium truncate max-w-xs">
                          {job.file_name}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {formatBytes(job.file_size)}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`badge border ${getStatusBadgeClasses(job.status)}`}>
                        {job.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400">
                      {formatRelativeTime(job.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        {job.status === 'completed' && (
                          <Link
                            to={`/results/${job.id}`}
                            className="p-2 hover:bg-slate-700 rounded-lg transition-colors text-blue-400"
                            title="View Results"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </Link>
                        )}
                        {job.status === 'analyzing' && (
                          <Link
                            to={`/analysis/${job.id}`}
                            className="p-2 hover:bg-slate-700 rounded-lg transition-colors text-yellow-400"
                            title="View Progress"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </Link>
                        )}
                        <button
                          onClick={() => handleDelete(job.id)}
                          disabled={deletingId === job.id}
                          className="p-2 hover:bg-red-500/20 rounded-lg transition-colors text-red-400 disabled:opacity-50"
                          title="Delete"
                        >
                          {deletingId === job.id ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <Trash2 className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Mobile list */}
          <div className="md:hidden divide-y divide-slate-700">
            {filteredJobs.map((job) => (
              <div key={job.id} className="p-4">
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <FileText className="w-5 h-5 text-slate-400 flex-shrink-0" />
                    <span className="text-white font-medium truncate">
                      {job.file_name}
                    </span>
                  </div>
                  <span className={`badge border flex-shrink-0 ${getStatusBadgeClasses(job.status)}`}>
                    {job.status}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <div className="text-slate-400">
                    {formatBytes(job.file_size)} • {formatRelativeTime(job.created_at)}
                  </div>
                  <div className="flex items-center gap-1">
                    {job.status === 'completed' && (
                      <Link
                        to={`/results/${job.id}`}
                        className="p-2 hover:bg-slate-700 rounded-lg transition-colors text-blue-400"
                      >
                        <ExternalLink className="w-4 h-4" />
                      </Link>
                    )}
                    <button
                      onClick={() => handleDelete(job.id)}
                      disabled={deletingId === job.id}
                      className="p-2 hover:bg-red-500/20 rounded-lg transition-colors text-red-400"
                    >
                      {deletingId === job.id ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <Trash2 className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
