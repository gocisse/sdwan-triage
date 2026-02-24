// Custom hook for managing analysis state

import { useState, useCallback, useEffect } from 'react';
import { 
  startAnalysis, 
  getAnalysisStatus, 
  cancelAnalysis,
  getResults,
  ApiError 
} from '../api/client';
import { useWebSocket } from './useWebSocket';
import type { AnalysisJob, AnalysisResults } from '../types';

interface UseAnalysisReturn {
  job: AnalysisJob | null;
  results: AnalysisResults | null;
  isLoading: boolean;
  error: string | null;
  start: (id: string) => Promise<void>;
  cancel: () => Promise<void>;
  loadStatus: (id: string) => Promise<void>;
  loadResults: (id: string) => Promise<void>;
  reset: () => void;
}

export function useAnalysis(): UseAnalysisReturn {
  const [job, setJob] = useState<AnalysisJob | null>(null);
  const [results, setResults] = useState<AnalysisResults | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // WebSocket for real-time updates
  const { lastMessage } = useWebSocket(
    job?.status === 'analyzing' ? job.id : null,
    {
      onMessage: (updatedJob) => {
        setJob(updatedJob);
      },
      onError: (err) => {
        console.error('WebSocket error:', err);
        // Fall back to polling
      },
    }
  );

  // Update job from WebSocket messages
  useEffect(() => {
    if (lastMessage) {
      setJob(lastMessage);
    }
  }, [lastMessage]);

  const start = useCallback(async (id: string) => {
    setIsLoading(true);
    setError(null);

    try {
      await startAnalysis(id);
      // Fetch initial status
      const status = await getAnalysisStatus(id);
      setJob(status);
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Failed to start analysis';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const cancel = useCallback(async () => {
    if (!job) return;

    setIsLoading(true);
    setError(null);

    try {
      await cancelAnalysis(job.id);
      const status = await getAnalysisStatus(job.id);
      setJob(status);
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Failed to cancel analysis';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [job]);

  const loadStatus = useCallback(async (id: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const status = await getAnalysisStatus(id);
      setJob(status);
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Failed to load analysis status';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loadResults = useCallback(async (id: string) => {
    setIsLoading(true);
    setError(null);

    try {
      const data = await getResults(id);
      setResults(data);
    } catch (err) {
      const message = err instanceof ApiError 
        ? err.message 
        : 'Failed to load results';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setJob(null);
    setResults(null);
    setError(null);
    setIsLoading(false);
  }, []);

  return {
    job,
    results,
    isLoading,
    error,
    start,
    cancel,
    loadStatus,
    loadResults,
    reset,
  };
}
