import React, { useState, useEffect } from 'react';
import { X, Copy, ChevronRight, ChevronDown, FileText, Layers, Hash, ArrowRightLeft } from 'lucide-react';
import { PacketDetailResponse, LayerDetailView } from '../types';
import { getAuthToken } from '../api/client';

interface HexViewerProps {
  isOpen: boolean;
  onClose: () => void;
  jobId: string;
  packetIndex: number;
  onSelectStream?: (streamId: string) => void;
}

const HexViewer: React.FC<HexViewerProps> = ({
  isOpen,
  onClose,
  jobId,
  packetIndex,
  onSelectStream,
}) => {
  const [packet, setPacket] = useState<PacketDetailResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set(['Ethernet', 'IPv4', 'IPv6', 'TCP', 'UDP']));
  const [viewMode, setViewMode] = useState<'hex' | 'ascii'>('hex');
  const [copiedFilter, setCopiedFilter] = useState(false);

  useEffect(() => {
    if (isOpen && jobId && packetIndex >= 0) {
      fetchPacket();
    }
  }, [isOpen, jobId, packetIndex]);

  const fetchPacket = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = getAuthToken();
      const response = await fetch(`/api/packet/${jobId}/${packetIndex}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        throw new Error('Failed to fetch packet data');
      }
      const data = await response.json();
      setPacket(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const toggleLayer = (name: string) => {
    setExpandedLayers(prev => {
      const next = new Set(prev);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  };

  const copyWiresharkFilter = () => {
    if (packet?.wireshark_filter) {
      navigator.clipboard.writeText(packet.wireshark_filter);
      setCopiedFilter(true);
      setTimeout(() => setCopiedFilter(false), 2000);
    }
  };

  const copyRawHex = () => {
    if (packet?.raw_hex) {
      // Convert formatted hex dump back to raw hex
      const rawHex = packet.raw_hex.split('\n')
        .map(line => line.substring(6, 54).replace(/\s+/g, '').replace(/\|.*\|/, ''))
        .join('');
      navigator.clipboard.writeText(rawHex);
    }
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

        {/* Panel */}
        <div className="relative w-full max-w-6xl bg-slate-900 rounded-xl shadow-2xl border border-slate-700 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-800/50">
            <div className="flex items-center gap-4">
              <h2 className="text-xl font-semibold text-white">
                Packet #{packetIndex}
              </h2>
              {packet && (
                <div className="flex items-center gap-2 text-sm text-slate-400">
                  <span className="font-mono">{packet.timestamp}</span>
                  <span className="text-slate-600">•</span>
                  <span>{packet.length} bytes</span>
                  <span className="text-slate-600">•</span>
                  <span className="px-2 py-0.5 bg-slate-700 rounded text-slate-300">{packet.protocol}</span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-3">
              {packet && (
                <>
                  <button
                    onClick={copyWiresharkFilter}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-300 transition-colors"
                  >
                    <Copy className="w-4 h-4" />
                    {copiedFilter ? 'Copied!' : 'Filter'}
                  </button>
                  {packet.stream_id && onSelectStream && (
                    <button
                      onClick={() => onSelectStream(packet.stream_id)}
                      className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-500 rounded-lg text-white transition-colors"
                    >
                      <ArrowRightLeft className="w-4 h-4" />
                      Follow Stream
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
          <div className="flex h-[70vh]">
            {/* Left: Protocol Tree */}
            <div className="w-1/3 border-r border-slate-700 overflow-y-auto bg-slate-800/30">
              <div className="p-4">
                <div className="flex items-center gap-2 text-sm font-medium text-slate-400 mb-3">
                  <Layers className="w-4 h-4" />
                  Protocol Layers
                </div>

                {loading && (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500" />
                  </div>
                )}

                {error && (
                  <div className="bg-red-900/30 border border-red-700 rounded-lg p-3 text-red-400 text-sm">
                    {error}
                  </div>
                )}

                {packet && (
                  <div className="space-y-1">
                    {packet.layers.map((layer, idx) => (
                      <LayerTreeItem
                        key={idx}
                        layer={layer}
                        isExpanded={expandedLayers.has(layer.name)}
                        onToggle={() => toggleLayer(layer.name)}
                      />
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right: Hex View */}
            <div className="flex-1 flex flex-col">
              {/* View mode tabs */}
              <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-700 bg-slate-800/30">
                <button
                  onClick={() => setViewMode('hex')}
                  className={`flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg transition-colors ${
                    viewMode === 'hex'
                      ? 'bg-slate-700 text-white'
                      : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  <Hash className="w-4 h-4" />
                  Hex Dump
                </button>
                <button
                  onClick={() => setViewMode('ascii')}
                  className={`flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg transition-colors ${
                    viewMode === 'ascii'
                      ? 'bg-slate-700 text-white'
                      : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  <FileText className="w-4 h-4" />
                  ASCII
                </button>
                <div className="flex-1" />
                <button
                  onClick={copyRawHex}
                  className="flex items-center gap-1 px-2 py-1 text-xs text-slate-500 hover:text-white hover:bg-slate-700 rounded transition-colors"
                  title="Copy raw hex"
                >
                  <Copy className="w-3 h-3" />
                  Copy
                </button>
              </div>

              {/* Hex content */}
              <div className="flex-1 overflow-auto p-4 bg-slate-950">
                {loading && (
                  <div className="flex items-center justify-center h-full">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
                  </div>
                )}

                {packet && (
                  <pre className="font-mono text-xs leading-relaxed text-slate-300 whitespace-pre">
                    {viewMode === 'hex' ? packet.raw_hex : packet.raw_ascii}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Layer tree item component
interface LayerTreeItemProps {
  layer: LayerDetailView;
  isExpanded: boolean;
  onToggle: () => void;
}

const LayerTreeItem: React.FC<LayerTreeItemProps> = ({ layer, isExpanded, onToggle }) => {
  const hasDetails = (layer.fields && Object.keys(layer.fields).length > 0) || 
                     (layer.flags && Object.keys(layer.flags).length > 0) ||
                     layer.payload_hex;

  return (
    <div className="rounded-lg overflow-hidden">
      {/* Header */}
      <button
        onClick={hasDetails ? onToggle : undefined}
        className={`w-full flex items-center gap-2 px-3 py-2 text-left transition-colors ${
          hasDetails ? 'hover:bg-slate-700/50' : 'cursor-default'
        } ${isExpanded ? 'bg-slate-700/30' : 'bg-slate-800/50'}`}
      >
        {hasDetails ? (
          isExpanded ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronRight className="w-4 h-4 text-slate-500" />
        ) : (
          <span className="w-4" />
        )}
        <span className="font-medium text-white">{layer.name}</span>
        <span className="text-slate-500 text-xs flex-1 truncate">{layer.summary}</span>
      </button>

      {/* Expanded content */}
      {isExpanded && hasDetails && (
        <div className="bg-slate-900/50 px-3 py-2 space-y-2">
          {/* Fields */}
          {layer.fields && Object.entries(layer.fields).length > 0 && (
            <div className="space-y-1">
              {Object.entries(layer.fields).map(([key, value]) => (
                <div key={key} className="flex items-start gap-2 text-xs">
                  <span className="text-slate-500 min-w-24">{key}:</span>
                  <span className="text-slate-300 font-mono">{value}</span>
                </div>
              ))}
            </div>
          )}

          {/* Flags */}
          {layer.flags && Object.entries(layer.flags).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(layer.flags).map(([flag, value]) => (
                <span
                  key={flag}
                  className={`px-2 py-0.5 rounded text-xs font-medium ${
                    value === '✓' || value === 'true'
                      ? 'bg-green-900/50 text-green-400'
                      : 'bg-slate-700 text-slate-400'
                  }`}
                >
                  {flag}
                </span>
              ))}
            </div>
          )}

          {/* Payload hex preview */}
          {layer.payload_hex && (
            <div className="mt-2">
              <div className="text-xs text-slate-500 mb-1">Payload (first 128 bytes):</div>
              <pre className="font-mono text-xs text-slate-400 bg-slate-950 rounded p-2 overflow-x-auto">
                {layer.payload_hex.split('\n').slice(0, 8).join('\n')}
                {layer.payload_hex.split('\n').length > 8 && '\n...'}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default HexViewer;
