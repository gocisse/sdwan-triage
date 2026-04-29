// ProtocolHierarchy.tsx — Protocol breakdown tree view (A2)
//
// Displays a collapsible hierarchy of protocols with packet/byte counts
// and percentage breakdown: Ethernet → IP → TCP/UDP → HTTP/TLS/etc.

import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Layers, Network, Globe, Lock, Server, Database, Radio } from 'lucide-react';
import type { Discrepancy, FlowComparisonSummary } from '../types';

// ─── Types ────────────────────────────────────────────────────────

interface ProtocolNode {
  name: string;
  displayName: string;
  packets: number;
  bytes: number;
  percentage: number;
  children: ProtocolNode[];
  icon?: React.ReactNode;
  color: string;
}

interface ProtocolHierarchyProps {
  discrepancies: Discrepancy[];
  flows: FlowComparisonSummary[];
  totalPackets: number;
  totalBytes: number;
}

// ─── Protocol Icons ───────────────────────────────────────────────

const protocolIcons: Record<string, React.ReactNode> = {
  Ethernet: <Layers className="w-3.5 h-3.5" />,
  IPv4: <Network className="w-3.5 h-3.5" />,
  IPv6: <Network className="w-3.5 h-3.5" />,
  TCP: <Globe className="w-3.5 h-3.5" />,
  UDP: <Radio className="w-3.5 h-3.5" />,
  HTTP: <Server className="w-3.5 h-3.5" />,
  HTTPS: <Lock className="w-3.5 h-3.5" />,
  TLS: <Lock className="w-3.5 h-3.5" />,
  DNS: <Database className="w-3.5 h-3.5" />,
  BFD: <Radio className="w-3.5 h-3.5" />,
  ICMP: <Network className="w-3.5 h-3.5" />,
};

const protocolColors: Record<string, string> = {
  Ethernet: 'text-slate-400',
  IPv4: 'text-blue-400',
  IPv6: 'text-cyan-400',
  TCP: 'text-green-400',
  UDP: 'text-yellow-400',
  HTTP: 'text-orange-400',
  HTTPS: 'text-emerald-400',
  TLS: 'text-emerald-400',
  DNS: 'text-purple-400',
  BFD: 'text-pink-400',
  ICMP: 'text-red-400',
  Other: 'text-slate-500',
};

// ─── Main Component ───────────────────────────────────────────────

export function ProtocolHierarchy({ discrepancies, flows, totalPackets, totalBytes }: ProtocolHierarchyProps) {
  const hierarchy = useMemo(() => buildHierarchy(discrepancies, flows, totalPackets, totalBytes), [discrepancies, flows, totalPackets, totalBytes]);

  return (
    <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-slate-700/50 bg-slate-800/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-white">Protocol Hierarchy</h3>
          </div>
          <div className="text-xs text-slate-500">
            {totalPackets.toLocaleString()} packets • {formatBytes(totalBytes)}
          </div>
        </div>
      </div>

      {/* Column Headers */}
      <div className="px-4 py-2 bg-slate-900/50 border-b border-slate-700/30 grid grid-cols-12 gap-2 text-[10px] font-semibold text-slate-500">
        <div className="col-span-5">Protocol</div>
        <div className="col-span-2 text-right">Packets</div>
        <div className="col-span-2 text-right">Bytes</div>
        <div className="col-span-3 text-right">% of Total</div>
      </div>

      {/* Tree */}
      <div className="max-h-[400px] overflow-y-auto">
        {hierarchy.map((node, i) => (
          <ProtocolTreeNode key={i} node={node} depth={0} />
        ))}
      </div>

      {/* Legend */}
      <div className="px-4 py-2 border-t border-slate-700/30 bg-slate-900/30">
        <div className="flex flex-wrap gap-3 text-[10px]">
          {Object.entries(protocolColors).slice(0, 8).map(([proto, color]) => (
            <div key={proto} className="flex items-center gap-1">
              <div className={`w-2 h-2 rounded-full ${color.replace('text-', 'bg-')}`} />
              <span className="text-slate-500">{proto}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Tree Node Component ──────────────────────────────────────────

interface ProtocolTreeNodeProps {
  node: ProtocolNode;
  depth: number;
}

function ProtocolTreeNode({ node, depth }: ProtocolTreeNodeProps) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children.length > 0;
  const indent = depth * 16;

  return (
    <>
      <div
        className={`grid grid-cols-12 gap-2 px-4 py-1.5 hover:bg-slate-700/30 cursor-pointer transition-colors ${
          depth === 0 ? 'bg-slate-800/30' : ''
        }`}
        style={{ paddingLeft: `${16 + indent}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {/* Protocol Name */}
        <div className="col-span-5 flex items-center gap-2">
          {hasChildren ? (
            <button className="flex-shrink-0 w-4 h-4 flex items-center justify-center">
              {expanded ? (
                <ChevronDown className="w-3 h-3 text-slate-500" />
              ) : (
                <ChevronRight className="w-3 h-3 text-slate-500" />
              )}
            </button>
          ) : (
            <div className="w-4" />
          )}
          <span className={node.color}>{node.icon}</span>
          <span className={`text-xs font-medium ${node.color}`}>{node.displayName}</span>
        </div>

        {/* Packets */}
        <div className="col-span-2 text-right text-xs text-slate-400 font-mono">
          {node.packets.toLocaleString()}
        </div>

        {/* Bytes */}
        <div className="col-span-2 text-right text-xs text-slate-400 font-mono">
          {formatBytes(node.bytes)}
        </div>

        {/* Percentage Bar */}
        <div className="col-span-3 flex items-center gap-2">
          <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${node.color.replace('text-', 'bg-')}`}
              style={{ width: `${Math.min(node.percentage, 100)}%` }}
            />
          </div>
          <span className="text-[10px] text-slate-500 font-mono w-10 text-right">
            {node.percentage.toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Children */}
      {expanded && hasChildren && (
        <>
          {node.children.map((child, i) => (
            <ProtocolTreeNode key={i} node={child} depth={depth + 1} />
          ))}
        </>
      )}
    </>
  );
}

// ─── Hierarchy Builder ────────────────────────────────────────────

function buildHierarchy(
  discrepancies: Discrepancy[],
  flows: FlowComparisonSummary[],
  totalPackets: number,
  totalBytes: number
): ProtocolNode[] {
  // Count protocols from flows and discrepancies
  const protocolCounts: Record<string, { packets: number; bytes: number }> = {};
  const portProtocols: Record<string, { packets: number; bytes: number }> = {};

  // Process flows
  flows.forEach(f => {
    const proto = f.protocol.toUpperCase();
    if (!protocolCounts[proto]) {
      protocolCounts[proto] = { packets: 0, bytes: 0 };
    }
    protocolCounts[proto].packets += f.packets_a + f.packets_b;
    // Estimate bytes (average 500 bytes per packet if not available)
    protocolCounts[proto].bytes += (f.packets_a + f.packets_b) * 500;

    // Detect application protocol by port
    const appProto = detectAppProtocol(f.src_port, f.dst_port);
    if (appProto) {
      if (!portProtocols[appProto]) {
        portProtocols[appProto] = { packets: 0, bytes: 0 };
      }
      portProtocols[appProto].packets += f.packets_a + f.packets_b;
      portProtocols[appProto].bytes += (f.packets_a + f.packets_b) * 500;
    }
  });

  // Process discrepancies for more accurate counts
  discrepancies.forEach(d => {
    const proto = d.protocol.toUpperCase();
    if (!protocolCounts[proto]) {
      protocolCounts[proto] = { packets: 0, bytes: 0 };
    }
    protocolCounts[proto].packets += 1;
    protocolCounts[proto].bytes += d.length || 500;

    const appProto = detectAppProtocol(d.src_port, d.dst_port);
    if (appProto) {
      if (!portProtocols[appProto]) {
        portProtocols[appProto] = { packets: 0, bytes: 0 };
      }
      portProtocols[appProto].packets += 1;
      portProtocols[appProto].bytes += d.length || 500;
    }
  });

  // Build hierarchy
  const tcpCount = protocolCounts['TCP'] || { packets: 0, bytes: 0 };
  const udpCount = protocolCounts['UDP'] || { packets: 0, bytes: 0 };
  const icmpCount = protocolCounts['ICMP'] || { packets: 0, bytes: 0 };
  const otherCount = {
    packets: Math.max(0, totalPackets - tcpCount.packets - udpCount.packets - icmpCount.packets),
    bytes: Math.max(0, totalBytes - tcpCount.bytes - udpCount.bytes - icmpCount.bytes),
  };

  // TCP children (application protocols)
  const tcpChildren: ProtocolNode[] = [];
  ['HTTPS', 'HTTP', 'TLS', 'SSH'].forEach(proto => {
    const count = portProtocols[proto];
    if (count && count.packets > 0) {
      tcpChildren.push({
        name: proto,
        displayName: proto,
        packets: count.packets,
        bytes: count.bytes,
        percentage: (count.packets / totalPackets) * 100,
        children: [],
        icon: protocolIcons[proto],
        color: protocolColors[proto] || 'text-slate-400',
      });
    }
  });

  // Add "Other TCP" if there are unaccounted TCP packets
  const accountedTcpPackets = tcpChildren.reduce((sum, c) => sum + c.packets, 0);
  if (tcpCount.packets > accountedTcpPackets) {
    tcpChildren.push({
      name: 'OtherTCP',
      displayName: 'Other TCP',
      packets: tcpCount.packets - accountedTcpPackets,
      bytes: tcpCount.bytes - tcpChildren.reduce((sum, c) => sum + c.bytes, 0),
      percentage: ((tcpCount.packets - accountedTcpPackets) / totalPackets) * 100,
      children: [],
      color: 'text-slate-500',
    });
  }

  // UDP children
  const udpChildren: ProtocolNode[] = [];
  ['DNS', 'BFD', 'QUIC', 'DTLS'].forEach(proto => {
    const count = portProtocols[proto];
    if (count && count.packets > 0) {
      udpChildren.push({
        name: proto,
        displayName: proto,
        packets: count.packets,
        bytes: count.bytes,
        percentage: (count.packets / totalPackets) * 100,
        children: [],
        icon: protocolIcons[proto],
        color: protocolColors[proto] || 'text-slate-400',
      });
    }
  });

  // Add "Other UDP"
  const accountedUdpPackets = udpChildren.reduce((sum, c) => sum + c.packets, 0);
  if (udpCount.packets > accountedUdpPackets) {
    udpChildren.push({
      name: 'OtherUDP',
      displayName: 'Other UDP',
      packets: udpCount.packets - accountedUdpPackets,
      bytes: udpCount.bytes - udpChildren.reduce((sum, c) => sum + c.bytes, 0),
      percentage: ((udpCount.packets - accountedUdpPackets) / totalPackets) * 100,
      children: [],
      color: 'text-slate-500',
    });
  }

  // Build IP layer
  const ipChildren: ProtocolNode[] = [];

  if (tcpCount.packets > 0) {
    ipChildren.push({
      name: 'TCP',
      displayName: 'TCP',
      packets: tcpCount.packets,
      bytes: tcpCount.bytes,
      percentage: (tcpCount.packets / totalPackets) * 100,
      children: tcpChildren,
      icon: protocolIcons.TCP,
      color: protocolColors.TCP,
    });
  }

  if (udpCount.packets > 0) {
    ipChildren.push({
      name: 'UDP',
      displayName: 'UDP',
      packets: udpCount.packets,
      bytes: udpCount.bytes,
      percentage: (udpCount.packets / totalPackets) * 100,
      children: udpChildren,
      icon: protocolIcons.UDP,
      color: protocolColors.UDP,
    });
  }

  if (icmpCount.packets > 0) {
    ipChildren.push({
      name: 'ICMP',
      displayName: 'ICMP',
      packets: icmpCount.packets,
      bytes: icmpCount.bytes,
      percentage: (icmpCount.packets / totalPackets) * 100,
      children: [],
      icon: protocolIcons.ICMP,
      color: protocolColors.ICMP,
    });
  }

  // Build Ethernet -> IPv4 -> ...
  const hierarchy: ProtocolNode[] = [
    {
      name: 'Ethernet',
      displayName: 'Ethernet',
      packets: totalPackets,
      bytes: totalBytes,
      percentage: 100,
      icon: protocolIcons.Ethernet,
      color: protocolColors.Ethernet,
      children: [
        {
          name: 'IPv4',
          displayName: 'IPv4',
          packets: totalPackets - otherCount.packets,
          bytes: totalBytes - otherCount.bytes,
          percentage: ((totalPackets - otherCount.packets) / totalPackets) * 100,
          icon: protocolIcons.IPv4,
          color: protocolColors.IPv4,
          children: ipChildren,
        },
        ...(otherCount.packets > 0 ? [{
          name: 'Other',
          displayName: 'Other (ARP, etc.)',
          packets: otherCount.packets,
          bytes: otherCount.bytes,
          percentage: (otherCount.packets / totalPackets) * 100,
          children: [],
          color: protocolColors.Other,
        }] : []),
      ],
    },
  ];

  return hierarchy;
}

// ─── Helpers ──────────────────────────────────────────────────────

function detectAppProtocol(srcPort: number, dstPort: number): string | null {
  const ports = [srcPort, dstPort];
  
  if (ports.includes(443) || ports.includes(8443)) return 'HTTPS';
  if (ports.includes(80) || ports.includes(8080)) return 'HTTP';
  if (ports.includes(22)) return 'SSH';
  if (ports.includes(53)) return 'DNS';
  if (ports.includes(3784) || ports.includes(4784)) return 'BFD';
  if (ports.includes(443)) return 'QUIC'; // Could be QUIC on 443/UDP
  if (ports.includes(12346) || ports.includes(12426)) return 'DTLS'; // Viptela
  
  return null;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export default ProtocolHierarchy;
