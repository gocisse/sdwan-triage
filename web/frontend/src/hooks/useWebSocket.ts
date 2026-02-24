// Custom hook for WebSocket connection management

import { useEffect, useRef, useState, useCallback } from 'react';
import { getAuthToken, getAnalysisStatus } from '../api/client';
import type { AnalysisJob } from '../types';

interface UseWebSocketOptions {
  onMessage?: (job: AnalysisJob) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onOpen?: () => void;
  reconnectAttempts?: number;
  reconnectInterval?: number;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  isConnecting: boolean;
  error: Error | null;
  connect: () => void;
  disconnect: () => void;
  lastMessage: AnalysisJob | null;
}

export function useWebSocket(
  jobId: string | null,
  options: UseWebSocketOptions = {}
): UseWebSocketReturn {
  const {
    reconnectAttempts = 3,
    reconnectInterval = 2000,
  } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [lastMessage, setLastMessage] = useState<AnalysisJob | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastStatusRef = useRef<string | null>(null);
  const jobIdRef = useRef<string | null>(jobId);
  const usingPollingRef = useRef(false);

  // Store callbacks in refs to avoid dependency churn
  const onMessageRef = useRef(options.onMessage);
  const onErrorRef = useRef(options.onError);
  const onCloseRef = useRef(options.onClose);
  const onOpenRef = useRef(options.onOpen);
  onMessageRef.current = options.onMessage;
  onErrorRef.current = options.onError;
  onCloseRef.current = options.onClose;
  onOpenRef.current = options.onOpen;
  jobIdRef.current = jobId;

  // Start HTTP polling as fallback when WebSocket is unavailable
  const startPolling = useCallback(() => {
    if (pollIntervalRef.current) return; // already polling
    const currentJobId = jobIdRef.current;
    if (!currentJobId) return;

    usingPollingRef.current = true;
    console.log('[WS] Falling back to HTTP polling');

    const poll = async () => {
      const jid = jobIdRef.current;
      if (!jid) return;
      try {
        const status = await getAnalysisStatus(jid);
        setLastMessage(status);
        onMessageRef.current?.(status);
        if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') {
          console.log(`[POLL] Job ${status.status}, stopping poll`);
          if (pollIntervalRef.current) {
            clearInterval(pollIntervalRef.current);
            pollIntervalRef.current = null;
          }
        }
      } catch {
        // ignore poll errors, will retry
      }
    };

    // Poll immediately, then every 2 seconds
    poll();
    pollIntervalRef.current = setInterval(poll, 2000);
  }, []);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    usingPollingRef.current = false;
    setIsConnected(false);
    setIsConnecting(false);
  }, []);

  const connect = useCallback(() => {
    const currentJobId = jobIdRef.current;
    if (!currentJobId) return;

    // Don't reconnect if already open or connecting
    if (wsRef.current?.readyState === WebSocket.OPEN ||
        wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    setIsConnecting(true);
    setError(null);

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const token = getAuthToken();
    const tokenParam = token ? `?token=${encodeURIComponent(token)}` : '';
    const wsUrl = `${protocol}//${host}/api/ws/${currentJobId}${tokenParam}`;
    console.log(`[WS] Connecting to ${wsUrl.replace(/token=[^&]+/, 'token=***')}`);
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log('[WS] Connected');
      setIsConnected(true);
      setIsConnecting(false);
      reconnectCountRef.current = 0;
      onOpenRef.current?.();
    };

    ws.onmessage = (event) => {
      try {
        const job = JSON.parse(event.data) as AnalysisJob;
        lastStatusRef.current = job.status;
        setLastMessage(job);
        onMessageRef.current?.(job);

        // Auto-close on completion
        if (
          job.status === 'completed' ||
          job.status === 'failed' ||
          job.status === 'cancelled'
        ) {
          console.log(`[WS] Job ${job.status}, closing`);
          ws.close(1000, 'Job finished');
        }
      } catch (err) {
        console.error('[WS] Failed to parse message:', err);
      }
    };

    ws.onerror = () => {
      const err = new Error('WebSocket connection error');
      setError(err);
      onErrorRef.current?.(err);
    };

    ws.onclose = (event) => {
      console.log(`[WS] Closed: code=${event.code}, reason=${event.reason}`);
      setIsConnected(false);
      setIsConnecting(false);
      wsRef.current = null;
      onCloseRef.current?.();

      // Only reconnect if job is still analyzing and we haven't exceeded attempts
      if (
        lastStatusRef.current === 'analyzing' &&
        event.code !== 1000 // Don't reconnect on normal close
      ) {
        if (reconnectCountRef.current < reconnectAttempts) {
          reconnectCountRef.current++;
          console.log(`[WS] Reconnecting (attempt ${reconnectCountRef.current}/${reconnectAttempts})...`);
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        } else {
          // All reconnect attempts exhausted — fall back to HTTP polling
          startPolling();
        }
      }
    };

    wsRef.current = ws;
  }, [reconnectAttempts, reconnectInterval, disconnect, startPolling]);

  // Auto-connect when jobId changes
  useEffect(() => {
    if (jobId) {
      reconnectCountRef.current = 0;
      lastStatusRef.current = null;
      connect();
    } else {
      disconnect();
    }

    return () => {
      disconnect();
    };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    isConnected,
    isConnecting,
    error,
    connect,
    disconnect,
    lastMessage,
  };
}
