import React, { useState, useEffect, useMemo } from 'react';
import { X, Copy, Filter, ChevronDown, ChevronUp } from 'lucide-react';
import { StreamResponse, StreamSegmentView } from '../types';
import { getAuthToken } from '../api/client';

interface StreamModalProps {
  isOpen: boolean;
  onClose: () => void;
  jobId: string;
  streamId: string;
  onFilterStream?: (streamId: string) => void;
  onSelectPacket?: (packetIndex: number) => void;
}

const StreamModal: React.FC<StreamModalProps> = ({
  isOpen,
  onClose,
  jobId,
  streamId,
  onFilterStream,
  onSelectPacket,
}) => {
  const [stream, setStream] = useState<StreamResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHex, setShowHex] = useState<Record<number, boolean>>({});
  const [copiedFilter, setCopiedFilter] = useState(false);

  useEffect(() => {
    if (isOpen && jobId && streamId) {
      fetchStream();
    }
  }, [isOpen, jobId, streamId]);

  const fetchStream = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = getAuthToken();
      const response = await fetch(`/api/stream/${jobId}/${encodeURIComponent(streamId)}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        throw new Error('Failed to fetch stream data');
      }
      const data = await response.json();
      setStream(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  // Merge client and server segments into a single timeline sorted by timestamp
  const interleavedSegments = useMemo(() => {
    if (!stream) return [];
    const tagged: { seg: StreamSegmentView; direction: 'client' | 'server' }[] = [
      ...stream.client_data.map(seg => ({ seg, direction: 'client' as const })),
      ...stream.server_data.map(seg => ({ seg, direction: 'server' as const })),
    ];
    tagged.sort((a, b) => a.seg.timestamp.localeCompare(b.seg.timestamp));
    return tagged;
  }, [stream]);

  const copyWiresharkFilter = () => {
    if (stream?.wireshark_filter) {
      navigator.clipboard.writeText(stream.wireshark_filter);
      setCopiedFilter(true);
      setTimeout(() => setCopiedFilter(false), 2000);
    }
  };

  const toggleHex = (index: number) => {
    setShowHex(prev => ({ ...prev, [index]: !prev[index] }));
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        {/* Backdrop */}
        <div 
          className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
          onClick={onClose}
        />

        {/* Modal */}
        <div className="relative w-full max-w-5xl bg-slate-900 rounded-xl shadow-2xl border border-slate-700 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-800/50">
            <div>
              <h2 className="text-xl font-semibold text-white">Follow Stream</h2>
              {stream && (
                <p className="text-sm text-slate-400 mt-1">
                  {stream.src_ip}:{stream.src_port} ↔ {stream.dst_ip}:{stream.dst_port} ({stream.protocol})
                </p>
              )}
            </div>
            <div className="flex items-center gap-3">
              {stream && (
                <>
                  <button
                    onClick={copyWiresharkFilter}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-300 transition-colors"
                  >
                    <Copy className="w-4 h-4" />
                    {copiedFilter ? 'Copied!' : 'Wireshark Filter'}
                  </button>
                  {onFilterStream && (
                    <button
                      onClick={() => onFilterStream(streamId)}
                      className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 rounded-lg text-white transition-colors"
                    >
                      <Filter className="w-4 h-4" />
                      Filter to Stream
                    </button>
                  )}
                </>
              )}
              <button
                onClick={onClose}
                className="p-2 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="p-6 max-h-[70vh] overflow-y-auto">
            {loading && (
              <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                <span className="ml-3 text-slate-400">Loading stream data...</span>
              </div>
            )}

            {error && (
              <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 text-red-400">
                Error: {error}
              </div>
            )}

            {stream && (
              <>
                {/* Stream Summary */}
                <div className="grid grid-cols-4 gap-4 mb-6">
                  <div className="bg-slate-800 rounded-lg p-4">
                    <div className="text-sm text-slate-400">Application</div>
                    <div className="text-lg font-medium text-white mt-1">
                      {stream.application || 'Unknown'}
                    </div>
                  </div>
                  <div className="bg-slate-800 rounded-lg p-4">
                    <div className="text-sm text-slate-400">Packets</div>
                    <div className="text-lg font-medium text-white mt-1">
                      {stream.packet_count}
                    </div>
                  </div>
                  <div className="bg-slate-800 rounded-lg p-4">
                    <div className="text-sm text-slate-400">Total Bytes</div>
                    <div className="text-lg font-medium text-white mt-1">
                      {formatBytes(stream.total_bytes)}
                    </div>
                  </div>
                  <div className="bg-slate-800 rounded-lg p-4">
                    <div className="text-sm text-slate-400">Protocol</div>
                    <div className="text-lg font-medium text-white mt-1">
                      {stream.protocol}
                    </div>
                  </div>
                </div>

                {/* Stream Conversation */}
                <div className="border border-slate-700 rounded-lg overflow-hidden">
                  <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex items-center gap-4">
                    <div className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full bg-red-500" />
                      <span className="text-sm text-slate-300">Client → Server ({stream.client_data.length} packets)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-3 h-3 rounded-full bg-blue-500" />
                      <span className="text-sm text-slate-300">Server → Client ({stream.server_data.length} packets)</span>
                    </div>
                  </div>

                  {/* Interleaved conversation view — sorted by timestamp */}
                  <div className="divide-y divide-slate-700/50 max-h-96 overflow-y-auto">
                    {interleavedSegments.map(({ seg, direction }, idx) => (
                      <SegmentRow
                        key={`${direction}-${seg.packet_index}-${idx}`}
                        segment={seg}
                        direction={direction}
                        showHex={showHex[seg.packet_index]}
                        onToggleHex={() => toggleHex(seg.packet_index)}
                        onSelectPacket={onSelectPacket}
                      />
                    ))}
                  </div>
                </div>

                {/* Combined View (ASCII) */}
                <div className="mt-6">
                  <h3 className="text-sm font-medium text-slate-400 mb-3">Combined ASCII Stream</h3>
                  <div className="bg-slate-950 rounded-lg p-4 font-mono text-xs overflow-x-auto">
                    <div className="text-red-400">
                      {stream.client_data.map((seg, idx) => (
                        <span key={idx}>{seg.data_ascii || ''}</span>
                      ))}
                    </div>
                    <div className="text-blue-400">
                      {stream.server_data.map((seg, idx) => (
                        <span key={idx}>{seg.data_ascii || ''}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Segment row component
interface SegmentRowProps {
  segment: StreamSegmentView;
  direction: 'client' | 'server';
  showHex: boolean;
  onToggleHex: () => void;
  onSelectPacket?: (packetIndex: number) => void;
}

const SegmentRow: React.FC<SegmentRowProps> = ({
  segment,
  direction,
  showHex,
  onToggleHex,
  onSelectPacket,
}) => {
  const bgClass = direction === 'client' 
    ? 'bg-red-950/20 hover:bg-red-950/30' 
    : 'bg-blue-950/20 hover:bg-blue-950/30';
  const textClass = direction === 'client' ? 'text-red-400' : 'text-blue-400';
  const arrow = direction === 'client' ? '→' : '←';

  return (
    <div className={`${bgClass} px-4 py-2 transition-colors`}>
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <button
            onClick={() => onSelectPacket?.(segment.packet_index)}
            className="text-xs text-slate-500 hover:text-white font-mono hover:underline"
            title="View packet details"
          >
            #{segment.packet_index}
          </button>
          <span className="text-xs text-slate-500 font-mono">{segment.timestamp}</span>
          <span className={textClass}>{arrow}</span>
          <span className="text-sm text-slate-300 truncate">{segment.summary}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500">{segment.length} B</span>
          <button
            onClick={onToggleHex}
            className="p-1 hover:bg-slate-700 rounded text-slate-500 hover:text-white transition-colors"
            title={showHex ? 'Hide hex' : 'Show hex'}
          >
            {showHex ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>
      {showHex && segment.data_hex && (
        <div className="mt-2 font-mono text-xs text-slate-400 bg-slate-950 rounded p-2 overflow-x-auto whitespace-pre">
          {segment.data_hex}
        </div>
      )}
    </div>
  );
};

export default StreamModal;
