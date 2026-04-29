import React, { useState, useMemo, useRef, useCallback, useEffect } from 'react';
import {
  Search,
  X,
  CheckCircle2,
  AlertCircle,
  BookOpen,
  Lightbulb,
  ChevronDown,
  ChevronUp,
  Copy,
  Zap,
  HelpCircle,
  Filter,
  Play,
} from 'lucide-react';
import type { Discrepancy } from '../types';
import { useFilterContext } from './FilterContext';

// ─── Types ────────────────────────────────────────────────────────

interface FilterBuilderEducatorProps {
  discrepancies: Discrepancy[];
}

interface FilterField {
  token: string;
  label: string;
  definition: string;
  example: string;
  category: 'ip' | 'tcp' | 'udp' | 'frame' | 'sdwan' | 'state';
}

interface CommonFilter {
  name: string;
  description: string;
  filter: string;
  category: string;
  explanation: string;
}

// ─── Field Definitions ────────────────────────────────────────────

const FILTER_FIELDS: FilterField[] = [
  // IP fields
  { token: 'ip.src', label: 'Source IP', definition: 'The IP address of the device that sent this packet. In a LAN capture, this is usually the user device or server on your local network.', example: 'ip.src == 10.0.0.1', category: 'ip' },
  { token: 'ip.dst', label: 'Destination IP', definition: 'The IP address of the intended recipient. The router uses this to decide where to forward the packet.', example: 'ip.dst == 8.8.8.8', category: 'ip' },
  { token: 'ip.addr', label: 'Any IP (src or dst)', definition: 'Matches either the source or destination IP. Use this when you want to see all traffic to/from a specific host.', example: 'ip.addr == 192.168.1.100', category: 'ip' },
  // TCP fields
  { token: 'tcp.port', label: 'TCP Port (any)', definition: 'Matches either the source or destination TCP port. Ports identify applications: 80=HTTP, 443=HTTPS, 22=SSH, 3389=RDP.', example: 'tcp.port == 443', category: 'tcp' },
  { token: 'tcp.srcport', label: 'TCP Source Port', definition: 'The port on the sending device. Client ports are usually random high numbers (1024-65535), called "ephemeral ports".', example: 'tcp.srcport == 80', category: 'tcp' },
  { token: 'tcp.dstport', label: 'TCP Destination Port', definition: 'The port on the receiving device. This identifies which service the sender is trying to reach.', example: 'tcp.dstport == 443', category: 'tcp' },
  { token: 'tcp.flags.syn', label: 'SYN Flag', definition: 'The Synchronize flag, used to start new TCP connections. A SYN without ACK is the very first packet of the 3-way handshake.', example: 'tcp.flags.syn == 1 && tcp.flags.ack == 0', category: 'tcp' },
  { token: 'tcp.flags.ack', label: 'ACK Flag', definition: 'The Acknowledge flag, confirming receipt of data. Almost every TCP packet after the first SYN has ACK set.', example: 'tcp.flags.ack == 1', category: 'tcp' },
  { token: 'tcp.flags.rst', label: 'RST Flag', definition: 'The Reset flag, used to abort a connection immediately. Often sent by firewalls to kill unwanted connections.', example: 'tcp.flags.rst == 1', category: 'tcp' },
  { token: 'tcp.flags.fin', label: 'FIN Flag', definition: 'The Finish flag, used to gracefully close a connection. Both sides must send FIN to complete the shutdown.', example: 'tcp.flags.fin == 1', category: 'tcp' },
  // UDP fields
  { token: 'udp.port', label: 'UDP Port (any)', definition: 'Matches either source or destination UDP port. Common: 53=DNS, 67/68=DHCP, 123=NTP, 161=SNMP, 3784=BFD.', example: 'udp.port == 53', category: 'udp' },
  { token: 'udp.dstport', label: 'UDP Destination Port', definition: 'The destination UDP port. Unlike TCP, UDP is connectionless — no handshake, no guaranteed delivery.', example: 'udp.dstport == 3784', category: 'udp' },
  // Frame fields
  { token: 'frame.protocol', label: 'Protocol', definition: 'The protocol name: TCP, UDP, ICMP, etc. Use this to filter for a specific type of traffic.', example: 'frame.protocol == TCP', category: 'frame' },
  { token: 'frame.len', label: 'Packet Length', definition: 'The total size of the packet in bytes. Large packets (>1400) may have MTU issues in tunnels.', example: 'frame.len > 1400', category: 'frame' },
  // SD-WAN specific (comparison mode)
  { token: 'state', label: 'Discrepancy State', definition: 'The comparison result: MISSING_B (dropped by device), MISSING_A (WAN-only/asymmetric), MODIFIED (changed in transit).', example: 'state == MISSING_B', category: 'state' },
  // SD-WAN control plane
  { token: 'sdwan.bfd', label: 'BFD Traffic', definition: 'Bidirectional Forwarding Detection — probes that monitor tunnel health. Runs on UDP 3784/4784. If BFD fails, the tunnel goes down.', example: 'udp.port == 3784', category: 'sdwan' },
  { token: 'sdwan.omp', label: 'OMP Traffic', definition: 'Overlay Management Protocol — Cisco SD-WAN\'s routing protocol that runs inside DTLS tunnels. Exchanges routes between vEdge/cEdge devices.', example: 'udp.port == 12346', category: 'sdwan' },
  { token: 'sdwan.dtls', label: 'DTLS Tunnel', definition: 'Datagram Transport Layer Security — the encrypted tunnel used by Cisco SD-WAN. Typically runs on UDP ports 12346-12426.', example: 'udp.dstport >= 12346 && udp.dstport <= 12426', category: 'sdwan' },
  { token: 'sdwan.vcmp', label: 'VCMP (VeloCloud)', definition: 'VeloCloud Management Protocol — VeloCloud SD-WAN\'s tunnel protocol. Runs on UDP port 2426.', example: 'udp.port == 2426', category: 'sdwan' },
];

// ─── Common Filters Library ───────────────────────────────────────

const COMMON_FILTERS: CommonFilter[] = [
  {
    name: 'Find All Dropped Traffic',
    description: 'Packets that entered LAN but never appeared on WAN',
    filter: 'state == MISSING_B',
    category: 'Drops',
    explanation: 'Shows all packets the SD-WAN device dropped. These are the most important packets to investigate — they represent traffic your users sent that never reached the WAN.',
  },
  {
    name: 'Find Blocked Connections (SYN Drops)',
    description: 'New TCP connections blocked by firewall/ACL',
    filter: 'state == MISSING_B && tcp.flags.syn == 1',
    category: 'Drops',
    explanation: 'Filters for TCP SYN packets (connection requests) that were dropped. This means the SD-WAN device\'s firewall or ACL is blocking new connections. Check Zone-Based Firewall (ZBFW) rules.',
  },
  {
    name: 'Find Large Packet Drops (MTU Issues)',
    description: 'Dropped packets larger than typical tunnel MTU',
    filter: 'state == MISSING_B && frame.len > 1400',
    category: 'Drops',
    explanation: 'Large packets (>1400 bytes) are often dropped because SD-WAN tunnel encapsulation adds 40-60 bytes of overhead, pushing them over the WAN interface MTU. Fix: enable TCP MSS clamping ("ip tcp adjust-mss 1360").',
  },
  {
    name: 'Find Control Plane Traffic',
    description: 'BFD, OMP, and DTLS keepalives',
    filter: 'udp.port == 3784 || udp.port == 12346',
    category: 'Control Plane',
    explanation: 'Shows BFD probes (UDP 3784) and DTLS/OMP tunnel traffic (UDP 12346). This is the SD-WAN device\'s "heartbeat" — if this stops, tunnels go down. It\'s normal to see this on WAN captures.',
  },
  {
    name: 'Find VeloCloud Tunnel Traffic',
    description: 'VCMP overlay traffic on UDP 2426',
    filter: 'udp.port == 2426',
    category: 'Control Plane',
    explanation: 'VeloCloud SD-WAN uses VCMP (VeloCloud Management Protocol) on UDP port 2426 for its overlay tunnels. This traffic should only appear in WAN captures.',
  },
  {
    name: 'Find Modified Packets (NAT/QoS)',
    description: 'Packets changed by the SD-WAN device',
    filter: 'state == MODIFIED',
    category: 'Modifications',
    explanation: 'Shows packets found in both captures but with changes. Common changes: NAT (IP address translation for internet traffic), DSCP remarking (QoS), or TTL decrement (normal routing).',
  },
  {
    name: 'Find Asymmetric Traffic',
    description: 'Packets on WAN but not LAN (remote site traffic)',
    filter: 'state == MISSING_A',
    category: 'Routing',
    explanation: 'Packets that appeared on the WAN but not the LAN. Often normal — return traffic from remote sites, device-generated probes (BFD/ICMP), or traffic from other branches in the SD-WAN fabric.',
  },
  {
    name: 'Find HTTPS Traffic',
    description: 'All TLS/HTTPS traffic on port 443',
    filter: 'tcp.port == 443',
    category: 'Application',
    explanation: 'Filters for HTTPS (TLS) traffic. If dropped, users can\'t access websites. If modified (NAT), verify the DIA (Direct Internet Access) policy is correctly configured.',
  },
  {
    name: 'Find DNS Traffic',
    description: 'All DNS queries and responses',
    filter: 'udp.port == 53',
    category: 'Application',
    explanation: 'Shows DNS traffic. If DNS packets are dropped, users will experience "website not loading" even though the network is up. DNS is often the first thing to check.',
  },
  {
    name: 'Find SSH Traffic',
    description: 'SSH management connections',
    filter: 'tcp.port == 22',
    category: 'Application',
    explanation: 'SSH traffic for remote management. If dropped, you can\'t SSH to devices on the other side of the SD-WAN. Check if SSH is allowed through the firewall policy.',
  },
  {
    name: 'Find RST (Aborted Connections)',
    description: 'TCP connections that were forcefully terminated',
    filter: 'tcp.flags.rst == 1',
    category: 'Troubleshooting',
    explanation: 'TCP RST packets abort connections immediately. Common causes: firewall injection (fake RSTs to kill connections), application crash, connection refused, or timeout. If you see many RSTs, check firewall logs.',
  },
  {
    name: 'Find Specific Host Traffic',
    description: 'All traffic to/from a specific IP',
    filter: 'ip.addr == 10.0.0.1',
    category: 'Troubleshooting',
    explanation: 'Shows all packets where 10.0.0.1 is either the source or destination. Replace with the IP you\'re investigating. This is the most common starting point for troubleshooting a specific device.',
  },
];

// ─── Filter Parser for Comparison Mode ────────────────────────────

interface ComparisonFilterToken {
  field: string;
  operator: string;
  value: string;
}

function parseComparisonFilter(raw: string): { tokens: ComparisonFilterToken[]; valid: boolean; error?: string } {
  const trimmed = raw.trim();
  if (!trimmed) return { tokens: [], valid: true };

  const tokens: ComparisonFilterToken[] = [];
  // Split on && or || (keep it simple)
  const clauses = trimmed.split(/\s*(?:&&|\|\|)\s*/);

  for (const clause of clauses) {
    const c = clause.trim();
    if (!c) continue;

    const match = c.match(/^([a-zA-Z_.]+)\s*(==|!=|>|<|>=|<=|contains)\s*(.+)$/i);
    if (match) {
      tokens.push({ field: match[1].toLowerCase(), operator: match[2], value: match[3].trim() });
    } else {
      return { tokens: [], valid: false, error: `Invalid: "${c}"` };
    }
  }

  return { tokens, valid: true };
}

function matchDiscrepancy(d: Discrepancy, tokens: ComparisonFilterToken[]): boolean {
  for (const t of tokens) {
    let actual: string | number | undefined;
    switch (t.field) {
      case 'ip.src': actual = d.src_ip; break;
      case 'ip.dst': actual = d.dst_ip; break;
      case 'ip.addr': {
        const v = t.value.toLowerCase();
        if (d.src_ip.toLowerCase() === v || d.dst_ip.toLowerCase() === v) { continue; }
        return false;
      }
      case 'tcp.port': case 'udp.port': {
        const v = parseInt(t.value);
        if (d.src_port === v || d.dst_port === v) { continue; }
        return false;
      }
      case 'tcp.srcport': case 'udp.srcport': actual = d.src_port; break;
      case 'tcp.dstport': case 'udp.dstport': actual = d.dst_port; break;
      case 'tcp.flags.syn': {
        const hasSyn = d.tcp_flags?.includes('SYN') ? '1' : '0';
        if (hasSyn !== t.value) return false;
        continue;
      }
      case 'tcp.flags.ack': {
        const hasAck = d.tcp_flags?.includes('ACK') ? '1' : '0';
        if (hasAck !== t.value) return false;
        continue;
      }
      case 'tcp.flags.rst': {
        const hasRst = d.tcp_flags?.includes('RST') ? '1' : '0';
        if (hasRst !== t.value) return false;
        continue;
      }
      case 'tcp.flags.fin': {
        const hasFin = d.tcp_flags?.includes('FIN') ? '1' : '0';
        if (hasFin !== t.value) return false;
        continue;
      }
      case 'frame.protocol': actual = d.protocol; break;
      case 'frame.len': actual = d.length; break;
      case 'state': actual = d.state; break;
      default: return false;
    }

    const aStr = String(actual ?? '').toLowerCase();
    const eStr = t.value.toLowerCase();

    switch (t.operator) {
      case '==': if (aStr !== eStr) return false; break;
      case '!=': if (aStr === eStr) return false; break;
      case '>': if (parseFloat(aStr) <= parseFloat(eStr)) return false; break;
      case '<': if (parseFloat(aStr) >= parseFloat(eStr)) return false; break;
      case '>=': if (parseFloat(aStr) < parseFloat(eStr)) return false; break;
      case '<=': if (parseFloat(aStr) > parseFloat(eStr)) return false; break;
      case 'contains': if (!aStr.includes(eStr)) return false; break;
      default: return false;
    }
  }
  return true;
}

// ─── Plain-English Filter Translator ──────────────────────────────

function translateFilterToEnglish(raw: string): string {
  const parsed = parseComparisonFilter(raw);
  if (!parsed.valid || parsed.tokens.length === 0) return '';

  const parts = parsed.tokens.map(t => {
    const fieldDef = FILTER_FIELDS.find(f => f.token === t.field);
    const fieldLabel = fieldDef?.label || t.field;

    switch (t.operator) {
      case '==': return `${fieldLabel} is ${t.value}`;
      case '!=': return `${fieldLabel} is NOT ${t.value}`;
      case '>': return `${fieldLabel} greater than ${t.value}`;
      case '<': return `${fieldLabel} less than ${t.value}`;
      case 'contains': return `${fieldLabel} contains "${t.value}"`;
      default: return `${fieldLabel} ${t.operator} ${t.value}`;
    }
  });

  return `Show me packets where ${parts.join(' AND ')}`;
}

// ─── Main Component ───────────────────────────────────────────────

export const FilterBuilderEducator: React.FC<FilterBuilderEducatorProps> = ({ discrepancies }) => {
  const [collapsed, setCollapsed] = useState(false);
  const [activeSection, setActiveSection] = useState<'scratchpad' | 'library' | 'learn'>('scratchpad');

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-slate-700/30 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <Filter className="w-4.5 h-4.5 text-green-400" />
          <span className="text-sm font-medium text-slate-300">Filter Builder & Explainer</span>
          <span className="px-2 py-0.5 text-[10px] font-medium bg-green-500/15 text-green-400 rounded-full">
            Learn to Write Filters
          </span>
        </div>
        {collapsed ? <ChevronDown className="w-4 h-4 text-slate-500" /> : <ChevronUp className="w-4 h-4 text-slate-500" />}
      </button>

      {!collapsed && (
        <div className="border-t border-slate-700/30">
          {/* Section Tabs */}
          <div className="flex items-center gap-1 px-5 pt-3 pb-2">
            {([
              { id: 'scratchpad' as const, label: 'Filter Scratchpad', icon: <Search className="w-3 h-3" /> },
              { id: 'library' as const, label: 'Common Patterns', icon: <BookOpen className="w-3 h-3" /> },
              { id: 'learn' as const, label: 'Learn Fields', icon: <Lightbulb className="w-3 h-3" /> },
            ]).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveSection(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  activeSection === tab.id
                    ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                    : 'bg-slate-700/30 text-slate-400 hover:text-slate-300'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Section Content */}
          <div className="px-5 pb-5">
            {activeSection === 'scratchpad' && <FilterScratchpad discrepancies={discrepancies} />}
            {activeSection === 'library' && <CommonFiltersLibrary discrepancies={discrepancies} />}
            {activeSection === 'learn' && <LearnFields />}
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Filter Scratchpad ────────────────────────────────────────────

const FilterScratchpad: React.FC<{ discrepancies: Discrepancy[] }> = ({ discrepancies }) => {
  // Filter text lives in a shared context so that right-click → "Apply as
  // Filter" from anywhere in the comparison view can seed this scratchpad.
  // When no FilterProvider is mounted (e.g. in tests) the hook returns a
  // no-op implementation and the scratchpad falls back to local state.
  const { filterText, setFilterText } = useFilterContext();
  const [verified, setVerified] = useState<number | null>(null);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [copiedFilter, setCopiedFilter] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Re-verify and focus the scratchpad whenever filterText changes from
  // an external source (e.g. a right-click "Apply as Filter" action).
  // We use a ref to compare prior text so we only respond to true changes.
  const prevFilterText = useRef(filterText);
  useEffect(() => {
    if (prevFilterText.current !== filterText) {
      prevFilterText.current = filterText;
      setVerified(null);
    }
  }, [filterText]);

  const parsed = useMemo(() => parseComparisonFilter(filterText), [filterText]);
  const englishTranslation = useMemo(() => translateFilterToEnglish(filterText), [filterText]);

  // Autocomplete suggestions based on current input
  const suggestions = useMemo(() => {
    const text = filterText.toLowerCase();
    const lastToken = text.split(/\s+/).pop() || '';
    if (!lastToken || lastToken.includes('==') || lastToken.includes('!=')) return [];
    return FILTER_FIELDS.filter(f =>
      f.token.toLowerCase().startsWith(lastToken) || f.label.toLowerCase().includes(lastToken)
    ).slice(0, 8);
  }, [filterText]);

  const handleVerify = useCallback(() => {
    if (!parsed.valid || parsed.tokens.length === 0) {
      setVerified(0);
      return;
    }
    const count = discrepancies.filter(d => matchDiscrepancy(d, parsed.tokens)).length;
    setVerified(count);
  }, [discrepancies, parsed]);

  const handleInsertField = useCallback((field: string) => {
    const parts = filterText.trim().split(/\s+/);
    parts.pop(); // Remove partial token
    const prefix = parts.length > 0 ? parts.join(' ') + ' ' : '';
    setFilterText(prefix + field + ' == ');
    setShowSuggestions(false);
    setVerified(null);
    inputRef.current?.focus();
  }, [filterText]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(filterText);
    setCopiedFilter(true);
    setTimeout(() => setCopiedFilter(false), 2000);
  }, [filterText]);

  // Close suggestions on outside click
  useEffect(() => {
    if (!showSuggestions) return;
    const handler = (e: MouseEvent) => {
      if (!(e.target as Element)?.closest('.scratchpad-container')) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showSuggestions]);

  return (
    <div className="space-y-3 scratchpad-container">
      {/* Input */}
      <div className="relative">
        <div className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border transition-all ${
          filterText && !parsed.valid
            ? 'border-red-500/50 bg-red-900/10'
            : filterText && parsed.valid
            ? 'border-green-500/50 bg-green-900/10'
            : 'border-slate-600/50 bg-slate-900/50'
        }`}>
          <Search className="w-4 h-4 text-slate-500 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={filterText}
            onChange={e => {
              setFilterText(e.target.value);
              setVerified(null);
              setShowSuggestions(true);
            }}
            onFocus={() => setShowSuggestions(true)}
            placeholder="Type a filter here... e.g. ip.src == 10.0.0.1 && tcp.port == 443"
            className="flex-1 bg-transparent text-sm text-slate-200 placeholder:text-slate-600 outline-none font-mono"
            spellCheck={false}
          />
          {filterText && (
            <>
              <button onClick={handleCopy} className="p-1 hover:bg-slate-700/50 rounded transition-colors" title="Copy filter">
                <Copy className={`w-3.5 h-3.5 ${copiedFilter ? 'text-green-400' : 'text-slate-500'}`} />
              </button>
              <button onClick={() => { setFilterText(''); setVerified(null); }} className="p-1 hover:bg-slate-700/50 rounded transition-colors" title="Clear">
                <X className="w-3.5 h-3.5 text-slate-500" />
              </button>
            </>
          )}
          <button
            onClick={handleVerify}
            disabled={!filterText.trim()}
            className="px-3 py-1 text-xs font-medium rounded bg-green-600/20 text-green-400 hover:bg-green-600/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-1.5"
          >
            <Play className="w-3 h-3" />
            Verify
          </button>
        </div>

        {/* Autocomplete Dropdown */}
        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute top-full left-0 right-0 mt-1 z-50 bg-slate-800 border border-slate-700/50 rounded-lg shadow-2xl shadow-black/40 overflow-hidden max-h-[240px] overflow-y-auto">
            {suggestions.map(s => (
              <button
                key={s.token}
                onClick={() => handleInsertField(s.token)}
                className="w-full flex items-center gap-3 px-3 py-2 hover:bg-slate-700/50 transition-colors text-left"
              >
                <code className="text-xs text-green-400 font-mono w-28 flex-shrink-0">{s.token}</code>
                <span className="text-[11px] text-slate-400 truncate">{s.label}</span>
                <span className="text-[9px] text-slate-600 ml-auto px-1.5 py-0.5 bg-slate-700/50 rounded">{s.category}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Parse Error */}
      {filterText && !parsed.valid && (
        <div className="flex items-center gap-2 px-3 py-2 bg-red-900/20 border border-red-700/30 rounded-lg">
          <AlertCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
          <span className="text-xs text-red-400">{parsed.error}</span>
        </div>
      )}

      {/* English Translation */}
      {englishTranslation && parsed.valid && (
        <div className="px-3 py-2.5 bg-blue-900/15 border border-blue-700/25 rounded-lg">
          <div className="text-[10px] font-medium text-blue-400 mb-1">📖 Plain English:</div>
          <p className="text-xs text-slate-300 leading-relaxed italic">"{englishTranslation}"</p>
        </div>
      )}

      {/* Filter Breakdown — clickable tokens */}
      {parsed.valid && parsed.tokens.length > 0 && (
        <FilterBreakdown tokens={parsed.tokens} />
      )}

      {/* Verify Result */}
      {verified !== null && (
        <div className={`flex items-center gap-2 px-3 py-2.5 rounded-lg border ${
          verified > 0
            ? 'bg-green-900/20 border-green-700/30'
            : 'bg-yellow-900/20 border-yellow-700/30'
        }`}>
          {verified > 0 ? (
            <CheckCircle2 className="w-4 h-4 text-green-400" />
          ) : (
            <AlertCircle className="w-4 h-4 text-yellow-400" />
          )}
          <div>
            <span className={`text-sm font-semibold ${verified > 0 ? 'text-green-400' : 'text-yellow-400'}`}>
              {verified} packet{verified !== 1 ? 's' : ''} match
            </span>
            <span className="text-xs text-slate-500 ml-2">
              out of {discrepancies.length} total discrepancies
            </span>
          </div>
        </div>
      )}

      {/* Tip */}
      <div className="text-[10px] text-slate-600 leading-relaxed">
        💡 <span className="text-slate-500">Tip:</span> Start typing a field name to see autocomplete suggestions.
        Use <code className="text-green-400/80">&&</code> to combine multiple conditions.
      </div>
    </div>
  );
};

// ─── Filter Breakdown Component ───────────────────────────────────

const FilterBreakdown: React.FC<{ tokens: ComparisonFilterToken[] }> = ({ tokens }) => {
  const [expandedToken, setExpandedToken] = useState<number | null>(null);

  return (
    <div className="px-3 py-2.5 bg-slate-900/50 border border-slate-700/30 rounded-lg">
      <div className="text-[10px] font-medium text-slate-400 mb-2">🔍 Filter Breakdown (click any part):</div>
      <div className="flex flex-wrap items-center gap-1.5">
        {tokens.map((token, idx) => {
          return (
            <React.Fragment key={idx}>
              {idx > 0 && <span className="text-[10px] text-slate-600 font-mono">AND</span>}
              <button
                onClick={() => setExpandedToken(expandedToken === idx ? null : idx)}
                className={`group inline-flex items-center gap-1 px-2 py-1 rounded border text-xs font-mono transition-all ${
                  expandedToken === idx
                    ? 'bg-green-500/20 border-green-500/40 text-green-300'
                    : 'bg-slate-700/30 border-slate-600/30 text-slate-300 hover:border-green-500/30'
                }`}
              >
                <span className="text-green-400">{token.field}</span>
                <span className="text-slate-500">{token.operator}</span>
                <span className="text-cyan-300">{token.value}</span>
                <HelpCircle className="w-2.5 h-2.5 text-slate-600 group-hover:text-blue-400 ml-0.5" />
              </button>
            </React.Fragment>
          );
        })}
      </div>

      {/* Expanded Definition */}
      {expandedToken !== null && expandedToken < tokens.length && (
        <div className="mt-2 pt-2 border-t border-slate-700/30">
          {(() => {
            const token = tokens[expandedToken];
            const fieldDef = FILTER_FIELDS.find(f => f.token === token.field);
            return (
              <div className="space-y-1">
                <div className="text-xs font-semibold text-green-400">
                  {fieldDef?.label || token.field}
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {fieldDef?.definition || `Custom field: ${token.field}`}
                </p>
                {fieldDef?.example && (
                  <div className="text-[10px] text-slate-600">
                    Example: <code className="text-slate-400">{fieldDef.example}</code>
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
};

// ─── Common Filters Library ───────────────────────────────────────

const CommonFiltersLibrary: React.FC<{ discrepancies: Discrepancy[] }> = ({ discrepancies }) => {
  const [expandedFilter, setExpandedFilter] = useState<number | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const categories = useMemo(() => {
    const cats = new Set(COMMON_FILTERS.map(f => f.category));
    return ['all', ...Array.from(cats)];
  }, []);

  const filtered = useMemo(() => {
    if (categoryFilter === 'all') return COMMON_FILTERS;
    return COMMON_FILTERS.filter(f => f.category === categoryFilter);
  }, [categoryFilter]);

  // Count matches for each filter
  const matchCounts = useMemo(() => {
    return COMMON_FILTERS.map(f => {
      const parsed = parseComparisonFilter(f.filter);
      if (!parsed.valid) return 0;
      return discrepancies.filter(d => matchDiscrepancy(d, parsed.tokens)).length;
    });
  }, [discrepancies]);

  const handleCopy = (filter: string) => {
    navigator.clipboard.writeText(filter);
  };

  return (
    <div className="space-y-3">
      {/* Category Filter */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-2.5 py-1 text-[10px] rounded-lg transition-colors ${
              categoryFilter === cat
                ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                : 'bg-slate-700/30 text-slate-500 hover:text-slate-400'
            }`}
          >
            {cat === 'all' ? 'All' : cat}
          </button>
        ))}
      </div>

      {/* Filter Cards */}
      <div className="space-y-2">
        {filtered.map((filter) => {
          const globalIdx = COMMON_FILTERS.indexOf(filter);
          const matchCount = matchCounts[globalIdx] ?? 0;
          const isExpanded = expandedFilter === globalIdx;

          return (
            <div
              key={globalIdx}
              className={`border rounded-lg overflow-hidden transition-all ${
                isExpanded ? 'border-green-500/40 bg-green-900/10' : 'border-slate-700/30 bg-slate-800/30'
              }`}
            >
              <button
                onClick={() => setExpandedFilter(isExpanded ? null : globalIdx)}
                className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-slate-700/20 transition-colors"
              >
                <Zap className={`w-3.5 h-3.5 flex-shrink-0 ${matchCount > 0 ? 'text-green-400' : 'text-slate-600'}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-semibold text-white">{filter.name}</div>
                  <div className="text-[10px] text-slate-500 truncate">{filter.description}</div>
                </div>
                <span className={`text-xs font-mono px-2 py-0.5 rounded flex-shrink-0 ${
                  matchCount > 0 ? 'bg-green-500/20 text-green-400' : 'bg-slate-700/50 text-slate-500'
                }`}>
                  {matchCount}
                </span>
                {isExpanded ? <ChevronUp className="w-3 h-3 text-slate-500" /> : <ChevronDown className="w-3 h-3 text-slate-500" />}
              </button>

              {isExpanded && (
                <div className="px-3 pb-3 space-y-2">
                  {/* Filter Code */}
                  <div className="flex items-center gap-2 px-3 py-2 bg-slate-900/50 rounded border border-slate-700/30">
                    <code className="text-xs text-green-400 font-mono flex-1">{filter.filter}</code>
                    <button
                      onClick={() => handleCopy(filter.filter)}
                      className="p-1 hover:bg-slate-700/50 rounded transition-colors"
                      title="Copy filter to clipboard"
                    >
                      <Copy className="w-3 h-3 text-slate-500" />
                    </button>
                  </div>

                  {/* Plain English */}
                  <div className="px-3 py-2 bg-blue-900/15 border border-blue-700/25 rounded">
                    <p className="text-[11px] text-slate-300 leading-relaxed italic">
                      "{translateFilterToEnglish(filter.filter)}"
                    </p>
                  </div>

                  {/* Explanation */}
                  <div className="px-3 py-2 bg-slate-800/50 rounded">
                    <div className="text-[10px] font-semibold text-slate-400 mb-1">📚 Why Use This:</div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">{filter.explanation}</p>
                  </div>

                  {/* Match Info */}
                  <div className="flex items-center gap-2 text-[10px]">
                    {matchCount > 0 ? (
                      <span className="text-green-400">✓ {matchCount} packets match in your current capture</span>
                    ) : (
                      <span className="text-slate-600">0 matches in current capture</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

// ─── Learn Fields Panel ───────────────────────────────────────────

const LearnFields: React.FC = () => {
  const [expandedField, setExpandedField] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const categories = ['all', 'ip', 'tcp', 'udp', 'frame', 'sdwan', 'state'];
  const categoryLabels: Record<string, string> = {
    all: 'All', ip: 'IP', tcp: 'TCP', udp: 'UDP', frame: 'Frame', sdwan: 'SD-WAN', state: 'Comparison',
  };

  const filtered = useMemo(() => {
    if (categoryFilter === 'all') return FILTER_FIELDS;
    return FILTER_FIELDS.filter(f => f.category === categoryFilter);
  }, [categoryFilter]);

  return (
    <div className="space-y-3">
      {/* Category Filter */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-2.5 py-1 text-[10px] rounded-lg transition-colors ${
              categoryFilter === cat
                ? 'bg-green-500/20 text-green-400 border border-green-500/40'
                : 'bg-slate-700/30 text-slate-500 hover:text-slate-400'
            }`}
          >
            {categoryLabels[cat]}
          </button>
        ))}
      </div>

      {/* Field Cards */}
      <div className="grid grid-cols-1 gap-1.5">
        {filtered.map(field => {
          const isExpanded = expandedField === field.token;
          return (
            <button
              key={field.token}
              onClick={() => setExpandedField(isExpanded ? null : field.token)}
              className={`w-full text-left rounded-lg border transition-all ${
                isExpanded
                  ? 'border-green-500/40 bg-green-900/10 p-3'
                  : 'border-slate-700/20 bg-slate-800/30 hover:bg-slate-700/20 px-3 py-2'
              }`}
            >
              <div className="flex items-center gap-3">
                <code className="text-xs text-green-400 font-mono w-32 flex-shrink-0">{field.token}</code>
                <span className="text-xs text-slate-300 flex-1">{field.label}</span>
                <span className="text-[9px] text-slate-600 px-1.5 py-0.5 bg-slate-700/50 rounded">{field.category}</span>
              </div>

              {isExpanded && (
                <div className="mt-2 pt-2 border-t border-slate-700/30 space-y-2">
                  <p className="text-[11px] text-slate-400 leading-relaxed">{field.definition}</p>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-600">Example:</span>
                    <code className="text-[10px] text-green-400/80 font-mono bg-slate-900/50 px-2 py-0.5 rounded">
                      {field.example}
                    </code>
                  </div>
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Pro Tips */}
      <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/30 space-y-2">
        <div className="text-xs font-semibold text-slate-300">🎓 Filter Writing Cheat Sheet</div>
        <div className="grid grid-cols-2 gap-2 text-[10px]">
          <div>
            <div className="text-slate-500 mb-0.5">Combine filters:</div>
            <code className="text-green-400">filter1 && filter2</code>
          </div>
          <div>
            <div className="text-slate-500 mb-0.5">Exact match:</div>
            <code className="text-green-400">field == value</code>
          </div>
          <div>
            <div className="text-slate-500 mb-0.5">Not equal:</div>
            <code className="text-green-400">field != value</code>
          </div>
          <div>
            <div className="text-slate-500 mb-0.5">Greater than:</div>
            <code className="text-green-400">frame.len &gt; 1400</code>
          </div>
          <div>
            <div className="text-slate-500 mb-0.5">Contains text:</div>
            <code className="text-green-400">dns.qry.name contains google</code>
          </div>
          <div>
            <div className="text-slate-500 mb-0.5">TCP flags:</div>
            <code className="text-green-400">tcp.flags.syn == 1</code>
          </div>
        </div>
      </div>
    </div>
  );
};
