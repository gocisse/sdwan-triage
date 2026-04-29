// Glossary.tsx — Interactive glossary for network forensics terms
//
// Provides:
// - GlossaryTerm: Clickable term that shows definition in tooltip/modal
// - GlossaryModal: Full glossary browser
// - useGlossary: Hook for programmatic access

import React, { useState, useCallback, createContext, useContext } from 'react';
import { X, Book, Search, ExternalLink } from 'lucide-react';

// ─── Glossary Data ────────────────────────────────────────────────

export interface GlossaryEntry {
  term: string;
  abbreviation?: string;
  definition: string;
  category: 'tcp' | 'ip' | 'sdwan' | 'performance' | 'security' | 'general';
  relatedTerms?: string[];
  example?: string;
  wiresharkFilter?: string;
}

export const GLOSSARY: Record<string, GlossaryEntry> = {
  // TCP Terms
  mss: {
    term: 'Maximum Segment Size',
    abbreviation: 'MSS',
    definition: 'The largest amount of TCP payload data that can be transmitted in a single segment. MSS is negotiated during the TCP handshake and is typically MTU minus 40 bytes (20 for IP header + 20 for TCP header).',
    category: 'tcp',
    relatedTerms: ['mtu', 'pmtud'],
    example: 'With a 1500-byte MTU, the MSS is typically 1460 bytes. SD-WAN tunnels may require lower MSS (e.g., 1400) due to encapsulation overhead.',
    wiresharkFilter: 'tcp.options.mss',
  },
  rtt: {
    term: 'Round-Trip Time',
    abbreviation: 'RTT',
    definition: 'The time it takes for a packet to travel from source to destination and back. RTT is a key metric for network latency and affects TCP throughput via the bandwidth-delay product.',
    category: 'performance',
    relatedTerms: ['latency', 'jitter'],
    example: 'An RTT of 50ms means it takes 50 milliseconds for a packet to reach the server and for the acknowledgment to return.',
    wiresharkFilter: 'tcp.analysis.ack_rtt',
  },
  rto: {
    term: 'Retransmission Timeout',
    abbreviation: 'RTO',
    definition: 'The time TCP waits before retransmitting a segment that has not been acknowledged. RTO is dynamically calculated based on RTT measurements and increases exponentially with each failed retransmission (exponential backoff).',
    category: 'tcp',
    relatedTerms: ['rtt', 'retransmission'],
    example: 'Initial RTO is typically 1 second. After a timeout, it doubles: 1s → 2s → 4s → 8s, up to a maximum (usually 60-120 seconds).',
  },
  cwnd: {
    term: 'Congestion Window',
    abbreviation: 'CWND',
    definition: 'The sender-side limit on the amount of data that can be in flight (sent but not yet acknowledged). CWND grows during slow start and congestion avoidance, and shrinks when packet loss is detected.',
    category: 'tcp',
    relatedTerms: ['rwnd', 'slow_start'],
    example: 'CWND starts at 1-10 MSS and doubles each RTT during slow start until it reaches ssthresh or detects loss.',
  },
  rwnd: {
    term: 'Receive Window',
    abbreviation: 'RWND',
    definition: 'The receiver-advertised window size indicating how much buffer space is available. A zero window means the receiver is overwhelmed and the sender must pause.',
    category: 'tcp',
    relatedTerms: ['cwnd', 'zero_window'],
    example: 'A slow application reading from the socket can cause RWND to shrink to zero, triggering a "Zero Window" condition.',
    wiresharkFilter: 'tcp.window_size == 0',
  },
  
  // IP Terms
  ttl: {
    term: 'Time to Live',
    abbreviation: 'TTL',
    definition: 'A counter in the IP header that is decremented by each router. When TTL reaches zero, the packet is discarded and an ICMP "Time Exceeded" message is sent. TTL prevents routing loops.',
    category: 'ip',
    relatedTerms: ['hop_count', 'traceroute'],
    example: 'Linux defaults to TTL=64, Windows to TTL=128. A packet with TTL=1 will be dropped by the first router.',
    wiresharkFilter: 'ip.ttl',
  },
  dscp: {
    term: 'Differentiated Services Code Point',
    abbreviation: 'DSCP',
    definition: 'A 6-bit field in the IP header used for Quality of Service (QoS) marking. DSCP values indicate traffic priority and treatment (e.g., EF for voice, AF for video).',
    category: 'ip',
    relatedTerms: ['qos', 'tos'],
    example: 'DSCP 46 (EF - Expedited Forwarding) is used for VoIP traffic to ensure low latency and jitter.',
    wiresharkFilter: 'ip.dsfield.dscp',
  },
  mtu: {
    term: 'Maximum Transmission Unit',
    abbreviation: 'MTU',
    definition: 'The largest packet size (in bytes) that can be transmitted on a network link without fragmentation. Ethernet MTU is typically 1500 bytes.',
    category: 'ip',
    relatedTerms: ['mss', 'pmtud', 'fragmentation'],
    example: 'SD-WAN tunnels add 40-60 bytes of overhead, so the effective MTU inside the tunnel is 1440-1460 bytes.',
  },
  pmtud: {
    term: 'Path MTU Discovery',
    abbreviation: 'PMTUD',
    definition: 'A technique to discover the smallest MTU along a network path. Packets are sent with the "Don\'t Fragment" (DF) bit set; if a router cannot forward the packet, it sends an ICMP "Fragmentation Needed" message.',
    category: 'ip',
    relatedTerms: ['mtu', 'icmp', 'blackhole'],
    example: 'PMTUD blackholes occur when ICMP is blocked, causing large packets to be silently dropped.',
  },
  
  // SD-WAN Terms
  omp: {
    term: 'Overlay Management Protocol',
    abbreviation: 'OMP',
    definition: 'Cisco Viptela\'s control plane protocol for exchanging routing information, policies, and service advertisements between SD-WAN edge devices and controllers.',
    category: 'sdwan',
    relatedTerms: ['bfd', 'viptela', 'vsmart'],
    example: 'OMP runs over DTLS tunnels to vSmart controllers. OMP routes have attributes like TLOC, origin, and preference.',
  },
  bfd: {
    term: 'Bidirectional Forwarding Detection',
    abbreviation: 'BFD',
    definition: 'A lightweight protocol for rapid detection of link or path failures. BFD sends periodic keepalives; if a configured number are missed, the session is declared down.',
    category: 'sdwan',
    relatedTerms: ['omp', 'tunnel', 'failover'],
    example: 'BFD with 300ms interval and multiplier 3 detects failures in ~1 second (3 × 300ms).',
    wiresharkFilter: 'bfd',
  },
  tloc: {
    term: 'Transport Locator',
    abbreviation: 'TLOC',
    definition: 'In Cisco SD-WAN, a TLOC identifies a WAN transport endpoint. It consists of system IP, color (transport type), and encapsulation (IPsec/GRE).',
    category: 'sdwan',
    relatedTerms: ['omp', 'viptela'],
    example: 'A router with two WAN links has two TLOCs: one for MPLS (color: mpls) and one for Internet (color: biz-internet).',
  },
  vcmp: {
    term: 'VeloCloud Management Protocol',
    abbreviation: 'VCMP',
    definition: 'VMware VeloCloud\'s proprietary protocol for SD-WAN overlay management, running on UDP port 2426.',
    category: 'sdwan',
    relatedTerms: ['velocloud', 'sdwan'],
    example: 'VCMP traffic appears as encrypted UDP on port 2426 between edges and gateways.',
    wiresharkFilter: 'udp.port == 2426',
  },
  
  // Performance Terms
  latency: {
    term: 'Latency',
    definition: 'The time delay for data to travel from source to destination. One-way latency is half the RTT. High latency affects interactive applications and TCP throughput.',
    category: 'performance',
    relatedTerms: ['rtt', 'jitter'],
    example: 'VoIP requires latency under 150ms for acceptable call quality.',
  },
  jitter: {
    term: 'Jitter',
    definition: 'The variation in packet arrival times. High jitter causes audio/video quality issues even when average latency is acceptable.',
    category: 'performance',
    relatedTerms: ['latency', 'rtt'],
    example: 'A jitter buffer of 30-50ms can compensate for network jitter in VoIP applications.',
  },
  throughput: {
    term: 'Throughput',
    definition: 'The actual data transfer rate achieved, measured in bits per second (bps). Throughput is limited by bandwidth, latency (via BDP), and packet loss.',
    category: 'performance',
    relatedTerms: ['bandwidth', 'bdp'],
    example: 'A 100 Mbps link with 100ms RTT and 1% loss may only achieve 10-20 Mbps throughput.',
  },
  bdp: {
    term: 'Bandwidth-Delay Product',
    abbreviation: 'BDP',
    definition: 'The amount of data "in flight" on a network path, calculated as Bandwidth × RTT. TCP must have a window size at least equal to BDP to fully utilize the link.',
    category: 'performance',
    relatedTerms: ['throughput', 'cwnd', 'rwnd'],
    example: 'A 100 Mbps link with 50ms RTT has BDP = 100 Mbps × 0.05s = 625 KB. TCP window must be ≥625 KB.',
  },
  
  // Analysis Terms
  retransmission: {
    term: 'Retransmission',
    definition: 'When TCP resends a segment because the original was lost or the acknowledgment was not received in time. Retransmissions indicate packet loss or network congestion.',
    category: 'tcp',
    relatedTerms: ['rto', 'fast_retransmit'],
    example: 'Fast retransmit occurs after 3 duplicate ACKs, without waiting for RTO.',
    wiresharkFilter: 'tcp.analysis.retransmission',
  },
  duplicate_ack: {
    term: 'Duplicate ACK',
    definition: 'An acknowledgment for a sequence number that has already been acknowledged. Three or more duplicate ACKs trigger fast retransmit.',
    category: 'tcp',
    relatedTerms: ['retransmission', 'fast_retransmit'],
    example: 'Duplicate ACKs indicate out-of-order delivery or packet loss.',
    wiresharkFilter: 'tcp.analysis.duplicate_ack',
  },
  zero_window: {
    term: 'Zero Window',
    definition: 'When the TCP receive window is advertised as zero, indicating the receiver\'s buffer is full. The sender must stop transmitting until a window update is received.',
    category: 'tcp',
    relatedTerms: ['rwnd', 'window_update'],
    example: 'A slow application not reading from the socket can cause zero window conditions.',
    wiresharkFilter: 'tcp.analysis.zero_window',
  },
  rst: {
    term: 'Reset',
    abbreviation: 'RST',
    definition: 'A TCP flag that abruptly terminates a connection. RST can indicate a connection refused, timeout, or application crash.',
    category: 'tcp',
    relatedTerms: ['fin', 'connection_reset'],
    example: 'Connecting to a closed port results in RST. Firewalls may send RST to reject connections.',
    wiresharkFilter: 'tcp.flags.reset == 1',
  },
};

// ─── Glossary Context ─────────────────────────────────────────────

interface GlossaryContextType {
  showTerm: (termKey: string) => void;
  showGlossary: () => void;
  hideGlossary: () => void;
  activeTerm: string | null;
  isGlossaryOpen: boolean;
}

const GlossaryContext = createContext<GlossaryContextType | null>(null);

export function useGlossary() {
  const ctx = useContext(GlossaryContext);
  if (!ctx) {
    throw new Error('useGlossary must be used within GlossaryProvider');
  }
  return ctx;
}

// ─── Glossary Provider ────────────────────────────────────────────

export function GlossaryProvider({ children }: { children: React.ReactNode }) {
  const [activeTerm, setActiveTerm] = useState<string | null>(null);
  const [isGlossaryOpen, setIsGlossaryOpen] = useState(false);

  const showTerm = useCallback((termKey: string) => {
    setActiveTerm(termKey.toLowerCase());
    setIsGlossaryOpen(true);
  }, []);

  const showGlossary = useCallback(() => {
    setIsGlossaryOpen(true);
  }, []);

  const hideGlossary = useCallback(() => {
    setIsGlossaryOpen(false);
    setActiveTerm(null);
  }, []);

  return (
    <GlossaryContext.Provider value={{ showTerm, showGlossary, hideGlossary, activeTerm, isGlossaryOpen }}>
      {children}
      {isGlossaryOpen && (
        <GlossaryModal
          initialTerm={activeTerm}
          onClose={hideGlossary}
        />
      )}
    </GlossaryContext.Provider>
  );
}

// ─── Glossary Term Component ──────────────────────────────────────

interface GlossaryTermProps {
  term: string;
  children?: React.ReactNode;
  className?: string;
}

export function GlossaryTerm({ term, children, className = '' }: GlossaryTermProps) {
  const [showTooltip, setShowTooltip] = useState(false);
  const entry = GLOSSARY[term.toLowerCase()];

  if (!entry) {
    return <span className={className}>{children || term}</span>;
  }

  return (
    <span
      className={`relative inline-block ${className}`}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <span className="border-b border-dotted border-blue-400 text-blue-400 cursor-help hover:text-blue-300 transition-colors">
        {children || entry.abbreviation || entry.term}
      </span>
      
      {showTooltip && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-72 p-3 bg-slate-800 border border-slate-600 rounded-lg shadow-xl text-left">
          <div className="text-xs font-semibold text-white mb-1">
            {entry.term}
            {entry.abbreviation && (
              <span className="ml-1 text-slate-400">({entry.abbreviation})</span>
            )}
          </div>
          <p className="text-[11px] text-slate-300 leading-relaxed">{entry.definition}</p>
          {entry.example && (
            <p className="text-[10px] text-slate-400 mt-2 italic">💡 {entry.example}</p>
          )}
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-full">
            <div className="border-8 border-transparent border-t-slate-800" />
          </div>
        </div>
      )}
    </span>
  );
}

// ─── Clickable Term (for use in text) ─────────────────────────────

interface ClickableTermProps {
  term: string;
  children?: React.ReactNode;
}

export function ClickableTerm({ term, children }: ClickableTermProps) {
  const { showTerm } = useGlossary();
  const entry = GLOSSARY[term.toLowerCase()];

  if (!entry) {
    return <span>{children || term}</span>;
  }

  return (
    <button
      onClick={() => showTerm(term)}
      className="text-blue-400 hover:text-blue-300 border-b border-dotted border-blue-400 hover:border-blue-300 transition-colors"
    >
      {children || entry.abbreviation || entry.term}
    </button>
  );
}

// ─── Glossary Modal ───────────────────────────────────────────────

interface GlossaryModalProps {
  initialTerm?: string | null;
  onClose: () => void;
}

function GlossaryModal({ initialTerm, onClose }: GlossaryModalProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTerm, setSelectedTerm] = useState<string | null>(initialTerm || null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

  const categories = {
    tcp: { name: 'TCP', color: 'bg-blue-500' },
    ip: { name: 'IP/Network', color: 'bg-green-500' },
    sdwan: { name: 'SD-WAN', color: 'bg-purple-500' },
    performance: { name: 'Performance', color: 'bg-yellow-500' },
    security: { name: 'Security', color: 'bg-red-500' },
    general: { name: 'General', color: 'bg-slate-500' },
  };

  const filteredTerms = Object.entries(GLOSSARY).filter(([key, entry]) => {
    if (selectedCategory && entry.category !== selectedCategory) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        key.includes(q) ||
        entry.term.toLowerCase().includes(q) ||
        entry.abbreviation?.toLowerCase().includes(q) ||
        entry.definition.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const selectedEntry = selectedTerm ? GLOSSARY[selectedTerm] : null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-4xl h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Book className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Network Forensics Glossary</h2>
              <p className="text-xs text-slate-400">{Object.keys(GLOSSARY).length} terms</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-lg transition-colors">
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Search & Filters */}
        <div className="px-6 py-3 border-b border-slate-700/50 space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search terms..."
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setSelectedCategory(null)}
              className={`px-2.5 py-1 text-xs rounded-lg transition-colors ${
                !selectedCategory ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
              }`}
            >
              All
            </button>
            {Object.entries(categories).map(([key, cat]) => (
              <button
                key={key}
                onClick={() => setSelectedCategory(key)}
                className={`px-2.5 py-1 text-xs rounded-lg transition-colors flex items-center gap-1.5 ${
                  selectedCategory === key ? 'bg-blue-600 text-white' : 'bg-slate-700 text-slate-400 hover:bg-slate-600'
                }`}
              >
                <div className={`w-2 h-2 rounded-full ${cat.color}`} />
                {cat.name}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 flex overflow-hidden">
          {/* Term List */}
          <div className="w-1/3 border-r border-slate-700/50 overflow-y-auto">
            {filteredTerms.map(([key, entry]) => (
              <button
                key={key}
                onClick={() => setSelectedTerm(key)}
                className={`w-full px-4 py-3 text-left border-b border-slate-700/30 transition-colors ${
                  selectedTerm === key
                    ? 'bg-blue-600/20 border-l-2 border-l-blue-500'
                    : 'hover:bg-slate-800/50 border-l-2 border-l-transparent'
                }`}
              >
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${categories[entry.category]?.color || 'bg-slate-500'}`} />
                  <span className="text-sm font-medium text-white">
                    {entry.abbreviation || entry.term}
                  </span>
                </div>
                {entry.abbreviation && (
                  <p className="text-xs text-slate-500 mt-0.5 ml-4">{entry.term}</p>
                )}
              </button>
            ))}
            {filteredTerms.length === 0 && (
              <div className="px-4 py-8 text-center text-slate-500 text-sm">
                No terms match your search
              </div>
            )}
          </div>

          {/* Term Detail */}
          <div className="flex-1 overflow-y-auto p-6">
            {selectedEntry ? (
              <div className="space-y-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-3 h-3 rounded-full ${categories[selectedEntry.category]?.color || 'bg-slate-500'}`} />
                    <span className="text-xs text-slate-400">{categories[selectedEntry.category]?.name}</span>
                  </div>
                  <h3 className="text-xl font-semibold text-white">
                    {selectedEntry.term}
                    {selectedEntry.abbreviation && (
                      <span className="ml-2 text-lg text-slate-400">({selectedEntry.abbreviation})</span>
                    )}
                  </h3>
                </div>

                <p className="text-sm text-slate-300 leading-relaxed">{selectedEntry.definition}</p>

                {selectedEntry.example && (
                  <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                    <div className="text-xs font-semibold text-yellow-400 mb-1">💡 Example</div>
                    <p className="text-sm text-slate-300">{selectedEntry.example}</p>
                  </div>
                )}

                {selectedEntry.wiresharkFilter && (
                  <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                    <div className="text-xs font-semibold text-cyan-400 mb-1">🔍 Wireshark Filter</div>
                    <code className="text-sm text-cyan-300 font-mono">{selectedEntry.wiresharkFilter}</code>
                  </div>
                )}

                {selectedEntry.relatedTerms && selectedEntry.relatedTerms.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold text-slate-400 mb-2">Related Terms</div>
                    <div className="flex flex-wrap gap-2">
                      {selectedEntry.relatedTerms.map(rt => {
                        const related = GLOSSARY[rt];
                        return related ? (
                          <button
                            key={rt}
                            onClick={() => setSelectedTerm(rt)}
                            className="px-2.5 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors flex items-center gap-1"
                          >
                            <ExternalLink className="w-3 h-3" />
                            {related.abbreviation || related.term}
                          </button>
                        ) : null;
                      })}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500">
                <div className="text-center">
                  <Book className="w-12 h-12 mx-auto mb-3 opacity-40" />
                  <p>Select a term to view its definition</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-700/50 text-xs text-slate-500">
          Tip: Click on highlighted terms in the Packet Dissector to see their definitions
        </div>
      </div>
    </div>
  );
}

export default GlossaryModal;
