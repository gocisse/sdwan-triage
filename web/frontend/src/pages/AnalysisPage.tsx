// Analysis progress page

import { useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ProgressDisplay } from '../components';
import { useAnalysis } from '../hooks';
import { ArrowLeft, ExternalLink, Loader2 } from 'lucide-react';

export function AnalysisPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { job, isLoading, error, loadStatus, cancel } = useAnalysis();

  // Load initial status
  useEffect(() => {
    if (id) {
      loadStatus(id);
    }
  }, [id, loadStatus]);

  // Auto-redirect when completed
  useEffect(() => {
    if (job?.status === 'completed') {
      // Small delay for user to see completion
      const timer = setTimeout(() => {
        navigate(`/results/${job.id}`);
      }, 1500);
      return () => clearTimeout(timer);
    }
  }, [job?.status, job?.id, navigate]);

  const handleCancel = useCallback(async () => {
    try {
      await cancel();
    } catch {
      // Error handled by hook
    }
  }, [cancel]);

  if (!id) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-400">Invalid analysis ID</p>
        <Link to="/" className="btn-primary mt-4 inline-flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </Link>
      </div>
    );
  }

  if (isLoading && !job) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
      </div>
    );
  }

  if (error && !job) {
    return (
      <div className="max-w-lg mx-auto text-center py-12">
        <div className="card p-6">
          <h2 className="text-xl font-bold text-red-400 mb-2">Error Loading Analysis</h2>
          <p className="text-slate-400 mb-4">{error}</p>
          <Link to="/" className="btn-primary inline-flex items-center gap-2">
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Link>
        </div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="text-center py-12">
        <p className="text-slate-400">Analysis not found</p>
        <Link to="/" className="btn-primary mt-4 inline-flex items-center gap-2">
          <ArrowLeft className="w-4 h-4" />
          Back to Home
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      {/* Back link */}
      <Link 
        to="/" 
        className="inline-flex items-center gap-2 text-slate-400 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to Home
      </Link>

      {/* Progress display */}
      <ProgressDisplay 
        job={job} 
        onCancel={job.status === 'analyzing' ? handleCancel : undefined}
        isLoading={isLoading}
      />

      {/* Completed actions */}
      {job.status === 'completed' && (
        <div className="mt-6 card p-6">
          <p className="text-green-400 mb-4">
            Redirecting to results...
          </p>
          <Link 
            to={`/results/${job.id}`}
            className="btn-primary inline-flex items-center gap-2"
          >
            View Results
            <ExternalLink className="w-4 h-4" />
          </Link>
        </div>
      )}

      {/* Failed/Cancelled actions */}
      {(job.status === 'failed' || job.status === 'cancelled') && (
        <div className="mt-6 flex flex-col sm:flex-row gap-3">
          <Link to="/" className="btn-primary flex-1 text-center">
            Upload New File
          </Link>
          <Link to="/history" className="btn-secondary flex-1 text-center">
            View History
          </Link>
        </div>
      )}
    </div>
  );
}
