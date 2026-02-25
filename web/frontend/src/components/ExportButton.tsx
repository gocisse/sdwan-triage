// Export Filtered PCAP button — sends current filter to backend and downloads carved .pcap

import { useState, useCallback } from 'react';
import { Download, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import type { ParsedFilter } from '../hooks/useForensicFilter';

interface ExportButtonProps {
  jobId: string;
  filterText: string;
  parsedFilter: ParsedFilter;
  isFiltered: boolean;
  /** Optional time window for IO Graph drill-down export */
  timeStart?: number;
  timeEnd?: number;
}

type ExportState = 'idle' | 'exporting' | 'success' | 'error';

export default function ExportButton({
  jobId,
  filterText,
  parsedFilter,
  isFiltered,
  timeStart,
  timeEnd,
}: ExportButtonProps) {
  const [state, setState] = useState<ExportState>('idle');
  const [errorMsg, setErrorMsg] = useState('');
  const [packetCount, setPacketCount] = useState(0);

  const handleExport = useCallback(async () => {
    if (!jobId) return;
    setState('exporting');
    setErrorMsg('');

    try {
      // Build request body from filter
      const body: Record<string, unknown> = {};

      if (filterText && parsedFilter.valid) {
        body.filter_expr = filterText;
      }

      if (timeStart && timeEnd) {
        body.time_start = timeStart;
        body.time_end = timeEnd;
      }

      // Get auth token
      const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');

      const response = await fetch(`/api/export-pcap/${jobId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: 'Export failed' }));
        throw new Error(errData.error || `HTTP ${response.status}`);
      }

      // Check if it's an error JSON response (no packets matched)
      const contentType = response.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();
        if (data.error) {
          throw new Error(data.error);
        }
      }

      // Get packet count from header
      const pktCount = parseInt(response.headers.get('X-Packet-Count') || '0', 10);
      setPacketCount(pktCount);

      // Download the file
      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const filenameMatch = disposition.match(/filename="?([^"]+)"?/);
      const filename = filenameMatch ? filenameMatch[1] : `sdwan-export-${Date.now()}.pcap`;

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setState('success');
      setTimeout(() => setState('idle'), 3000);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Export failed');
      setState('error');
      setTimeout(() => setState('idle'), 4000);
    }
  }, [jobId, filterText, parsedFilter, timeStart, timeEnd]);

  const buttonLabel = isFiltered ? 'Export Filtered PCAP' : 'Export Full PCAP';

  return (
    <div className="relative inline-flex items-center">
      <button
        onClick={handleExport}
        disabled={state === 'exporting'}
        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
          state === 'exporting'
            ? 'bg-slate-700 text-slate-400 cursor-wait'
            : state === 'success'
              ? 'bg-green-500/20 text-green-400 border border-green-500/30'
              : state === 'error'
                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                : isFiltered
                  ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30 hover:bg-purple-500/30'
                  : 'bg-slate-700/50 text-slate-400 border border-slate-700/50 hover:bg-slate-700 hover:text-slate-300'
        }`}
        title={isFiltered ? `Export packets matching: ${filterText}` : 'Export all packets as PCAP'}
      >
        {state === 'exporting' ? (
          <>
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            Exporting...
          </>
        ) : state === 'success' ? (
          <>
            <CheckCircle className="w-3.5 h-3.5" />
            {packetCount > 0 ? `${packetCount.toLocaleString()} packets` : 'Done'}
          </>
        ) : state === 'error' ? (
          <>
            <AlertCircle className="w-3.5 h-3.5" />
            {errorMsg || 'Failed'}
          </>
        ) : (
          <>
            <Download className="w-3.5 h-3.5" />
            {buttonLabel}
          </>
        )}
      </button>
    </div>
  );
}
