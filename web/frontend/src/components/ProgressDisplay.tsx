// Analysis progress display component

import { Activity, CheckCircle, XCircle, Clock, Loader2 } from 'lucide-react';
import type { AnalysisJob } from '../types';
import { formatDuration } from '../utils';

interface ProgressDisplayProps {
  job: AnalysisJob;
  onCancel?: () => void;
  isLoading?: boolean;
}

export function ProgressDisplay({ job, onCancel, isLoading }: ProgressDisplayProps) {
  const getStatusIcon = () => {
    switch (job.status) {
      case 'completed':
        return <CheckCircle className="w-8 h-8 text-green-400" />;
      case 'failed':
      case 'cancelled':
        return <XCircle className="w-8 h-8 text-red-400" />;
      case 'analyzing':
        return <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />;
      default:
        return <Clock className="w-8 h-8 text-yellow-400" />;
    }
  };

  const getStatusText = () => {
    switch (job.status) {
      case 'completed':
        return 'Analysis Complete';
      case 'failed':
        return 'Analysis Failed';
      case 'cancelled':
        return 'Analysis Cancelled';
      case 'analyzing':
        return 'Analyzing...';
      case 'pending':
        return 'Waiting to Start';
      case 'uploading':
        return 'Uploading...';
      default:
        return job.status;
    }
  };

  const getStatusColor = () => {
    switch (job.status) {
      case 'completed':
        return 'text-green-400';
      case 'failed':
      case 'cancelled':
        return 'text-red-400';
      case 'analyzing':
        return 'text-blue-400';
      default:
        return 'text-yellow-400';
    }
  };

  return (
    <div className="card p-6 sm:p-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="w-16 h-16 bg-slate-700 rounded-xl flex items-center justify-center">
          {getStatusIcon()}
        </div>
        <div>
          <h2 className={`text-xl font-bold ${getStatusColor()}`}>
            {getStatusText()}
          </h2>
          <p className="text-slate-400 text-sm">{job.file_name}</p>
        </div>
      </div>

      {/* Progress bar */}
      {(job.status === 'analyzing' || job.status === 'uploading') && (
        <div className="mb-6">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-slate-400">{job.current_step}</span>
            <span className="text-white font-medium">{job.progress}%</span>
          </div>
          <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-blue-500 to-blue-400 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${job.progress}%` }}
            />
          </div>
          {job.estimated_time > 0 && (
            <p className="text-xs text-slate-500 mt-2">
              Estimated time remaining: {formatDuration(job.estimated_time)}
            </p>
          )}
        </div>
      )}

      {/* Analysis steps */}
      {job.status === 'analyzing' && (
        <div className="space-y-3 mb-6">
          <ProgressStep 
            label="Reading PCAP file" 
            completed={job.progress >= 10}
            active={job.progress < 10}
          />
          <ProgressStep 
            label="Analyzing packets" 
            completed={job.progress >= 80}
            active={job.progress >= 10 && job.progress < 80}
          />
          <ProgressStep 
            label="Generating reports" 
            completed={job.progress >= 95}
            active={job.progress >= 80 && job.progress < 95}
          />
          <ProgressStep 
            label="Finalizing" 
            completed={job.progress >= 100}
            active={job.progress >= 95 && job.progress < 100}
          />
        </div>
      )}

      {/* Error message */}
      {job.status === 'failed' && job.error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 mb-6">
          <p className="text-red-400 text-sm">{job.error}</p>
        </div>
      )}

      {/* Cancel button */}
      {job.status === 'analyzing' && onCancel && (
        <button
          onClick={onCancel}
          disabled={isLoading}
          className="btn-danger w-full sm:w-auto"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin mr-2" />
              Cancelling...
            </>
          ) : (
            'Cancel Analysis'
          )}
        </button>
      )}
    </div>
  );
}

interface ProgressStepProps {
  label: string;
  completed: boolean;
  active: boolean;
}

function ProgressStep({ label, completed, active }: ProgressStepProps) {
  return (
    <div className="flex items-center gap-3">
      <div className={`
        w-6 h-6 rounded-full flex items-center justify-center
        ${completed 
          ? 'bg-green-500' 
          : active 
            ? 'bg-blue-500 animate-pulse' 
            : 'bg-slate-700'
        }
      `}>
        {completed ? (
          <CheckCircle className="w-4 h-4 text-white" />
        ) : active ? (
          <Activity className="w-3 h-3 text-white" />
        ) : (
          <div className="w-2 h-2 bg-slate-500 rounded-full" />
        )}
      </div>
      <span className={`text-sm ${
        completed 
          ? 'text-green-400' 
          : active 
            ? 'text-white' 
            : 'text-slate-500'
      }`}>
        {label}
      </span>
    </div>
  );
}
