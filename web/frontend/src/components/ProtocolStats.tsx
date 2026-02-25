// Protocol Hierarchy View — tree view of protocols with traffic percentages

import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Layers } from 'lucide-react';
import type { AnalysisResults } from '../types';

interface ProtocolStatsProps {
  results: AnalysisResults;
}

interface ProtocolNode {
  name: string;
  packets: number;
  bytes: number;
  percent: number;
  children: ProtocolNode[];
}

// Build protocol hierarchy from analysis results
function buildProtocolHierarchy(results: AnalysisResults): ProtocolNode[] {
  // Aggregate from traffic flows
  const flows = results.traffic_analysis || [];
  const totalBytes = results.total_bytes || flows.reduce((s, f) => s + f.total_bytes, 0) || 1;
  const totalPackets = results.packet_count || 0;

  // Layer 2: Ethernet (everything)
  const ethNode: ProtocolNode = {
    name: 'Ethernet',
    packets: totalPackets,
    bytes: totalBytes,
    percent: 100,
    children: [],
  };

  // Layer 3 aggregation
  const l3: Record<string, { packets: number; bytes: number }> = {};
  // Layer 4 aggregation under each L3
  const l4: Record<string, Record<string, { packets: number; bytes: number }>> = {};
  // Layer 7 aggregation
  const l7: Record<string, Record<string, { packets: number; bytes: number }>> = {};

  for (const flow of flows) {
    const proto = (flow.protocol || 'Unknown').toUpperCase();
    let l3proto = 'IPv4';
    let l4proto = proto;
    let l7proto = '';

    // Classify
    if (proto === 'TCP' || proto === 'UDP' || proto === 'ICMP' || proto === 'SCTP') {
      l4proto = proto;
    } else if (proto === 'ARP') {
      l3proto = 'ARP';
      l4proto = '';
    } else if (proto === 'IPV6') {
      l3proto = 'IPv6';
      l4proto = '';
    } else {
      l4proto = proto;
    }

    // Detect L7 from port
    if (l4proto === 'TCP' || l4proto === 'UDP') {
      const port = Math.min(flow.src_port || 0, flow.dst_port || 0);
      const dport = flow.dst_port || 0;
      if (dport === 53 || port === 53) l7proto = 'DNS';
      else if (dport === 80 || port === 80) l7proto = 'HTTP';
      else if (dport === 443 || port === 443) l7proto = 'TLS/HTTPS';
      else if (dport === 22 || port === 22) l7proto = 'SSH';
      else if (dport === 25 || dport === 587) l7proto = 'SMTP';
      else if (dport === 5060 || port === 5060) l7proto = 'SIP';
      else if (dport === 123 || port === 123) l7proto = 'NTP';
      else if (dport === 67 || dport === 68) l7proto = 'DHCP';
      else if (dport === 4789) l7proto = 'VXLAN';
      else if (dport === 2426) l7proto = 'VCMP';
      else if (dport >= 12346 && dport <= 12426) l7proto = 'Viptela';
    }

    // Accumulate L3
    if (!l3[l3proto]) l3[l3proto] = { packets: 0, bytes: 0 };
    l3[l3proto].packets += 1;
    l3[l3proto].bytes += flow.total_bytes;

    // Accumulate L4
    if (l4proto) {
      if (!l4[l3proto]) l4[l3proto] = {};
      if (!l4[l3proto][l4proto]) l4[l3proto][l4proto] = { packets: 0, bytes: 0 };
      l4[l3proto][l4proto].packets += 1;
      l4[l3proto][l4proto].bytes += flow.total_bytes;
    }

    // Accumulate L7
    if (l7proto && l4proto) {
      const key = `${l3proto}/${l4proto}`;
      if (!l7[key]) l7[key] = {};
      if (!l7[key][l7proto]) l7[key][l7proto] = { packets: 0, bytes: 0 };
      l7[key][l7proto].packets += 1;
      l7[key][l7proto].bytes += flow.total_bytes;
    }
  }

  // Also add tunnel, LAN protocol stats
  const tunnels = results.tunnel_analysis || [];
  for (const t of tunnels) {
    const name = t.type || 'Tunnel';
    if (!l3['IPv4']) l3['IPv4'] = { packets: 0, bytes: 0 };
    if (!l4['IPv4']) l4['IPv4'] = {};
    if (!l4['IPv4'][name]) l4['IPv4'][name] = { packets: 0, bytes: 0 };
    l4['IPv4'][name].packets += t.packet_count;
    l4['IPv4'][name].bytes += (t.byte_count || 0);
  }

  // DNS anomalies count
  const dnsCount = (results.dns_anomalies?.length || 0);
  if (dnsCount > 0) {
    const key = 'IPv4/UDP';
    if (!l7[key]) l7[key] = {};
    if (!l7[key]['DNS (Anomalous)']) l7[key]['DNS (Anomalous)'] = { packets: 0, bytes: 0 };
    l7[key]['DNS (Anomalous)'].packets += dnsCount;
  }

  // Build tree
  for (const [l3name, l3data] of Object.entries(l3)) {
    const l3Node: ProtocolNode = {
      name: l3name,
      packets: l3data.packets,
      bytes: l3data.bytes,
      percent: totalBytes > 0 ? (l3data.bytes / totalBytes) * 100 : 0,
      children: [],
    };

    if (l4[l3name]) {
      for (const [l4name, l4data] of Object.entries(l4[l3name])) {
        const l4Node: ProtocolNode = {
          name: l4name,
          packets: l4data.packets,
          bytes: l4data.bytes,
          percent: totalBytes > 0 ? (l4data.bytes / totalBytes) * 100 : 0,
          children: [],
        };

        const key = `${l3name}/${l4name}`;
        if (l7[key]) {
          for (const [l7name, l7data] of Object.entries(l7[key])) {
            l4Node.children.push({
              name: l7name,
              packets: l7data.packets,
              bytes: l7data.bytes,
              percent: totalBytes > 0 ? (l7data.bytes / totalBytes) * 100 : 0,
              children: [],
            });
          }
        }

        l3Node.children.push(l4Node);
      }
    }

    ethNode.children.push(l3Node);
  }

  // Sort children by bytes descending at each level
  const sortChildren = (node: ProtocolNode) => {
    node.children.sort((a, b) => b.bytes - a.bytes);
    node.children.forEach(sortChildren);
  };
  sortChildren(ethNode);

  return [ethNode];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// ─── Tree Node Renderer ──────────────────────────────────────────
interface TreeNodeProps {
  node: ProtocolNode;
  depth: number;
}

function TreeNode({ node, depth }: TreeNodeProps) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children.length > 0;

  const barColor = depth === 0 ? 'bg-blue-500' : depth === 1 ? 'bg-cyan-500' : depth === 2 ? 'bg-green-500' : 'bg-purple-500';
  const textColor = depth === 0 ? 'text-white' : 'text-slate-300';

  return (
    <div>
      <button
        onClick={() => hasChildren && setExpanded(!expanded)}
        className={`w-full flex items-center gap-2 px-3 py-1.5 text-sm hover:bg-slate-700/30 rounded-lg transition-colors ${
          hasChildren ? 'cursor-pointer' : 'cursor-default'
        }`}
        style={{ paddingLeft: `${depth * 20 + 12}px` }}
      >
        {/* Expand icon */}
        <span className="w-4 h-4 flex-shrink-0 flex items-center justify-center">
          {hasChildren ? (
            expanded ? <ChevronDown className="w-3.5 h-3.5 text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
          ) : (
            <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
          )}
        </span>

        {/* Protocol name */}
        <span className={`font-mono text-xs font-medium ${textColor} flex-shrink-0`}>{node.name}</span>

        {/* Percentage bar */}
        <div className="flex-1 mx-2 h-1.5 rounded-full bg-slate-700/50 overflow-hidden">
          <div
            className={`h-full rounded-full ${barColor} transition-all`}
            style={{ width: `${Math.max(node.percent, 0.5)}%` }}
          />
        </div>

        {/* Stats */}
        <span className="text-[10px] text-slate-500 flex-shrink-0 w-14 text-right font-mono">{node.percent.toFixed(1)}%</span>
        <span className="text-[10px] text-slate-500 flex-shrink-0 w-16 text-right">{formatBytes(node.bytes)}</span>
        <span className="text-[10px] text-slate-500 flex-shrink-0 w-14 text-right">{node.packets.toLocaleString()} pkt</span>
      </button>

      {expanded && hasChildren && (
        <div>
          {node.children.map((child, i) => (
            <TreeNode key={`${child.name}-${i}`} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────
export default function ProtocolStats({ results }: ProtocolStatsProps) {
  const hierarchy = useMemo(() => buildProtocolHierarchy(results), [results]);

  if (hierarchy.length === 0 || hierarchy[0].children.length === 0) {
    return (
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-8 text-center">
        <Layers className="w-8 h-8 text-slate-600 mx-auto mb-3" />
        <p className="text-sm text-slate-500">No protocol data available</p>
      </div>
    );
  }

  // Summary stats
  const totalBytes = hierarchy[0].bytes;
  const totalPackets = hierarchy[0].packets;
  const uniqueProtocols = new Set<string>();
  const countProtos = (node: ProtocolNode) => {
    if (node.children.length === 0 || node.name !== 'Ethernet') uniqueProtocols.add(node.name);
    node.children.forEach(countProtos);
  };
  hierarchy[0].children.forEach(countProtos);

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-700/50">
        <div className="flex items-center gap-2.5">
          <Layers className="w-4 h-4 text-blue-400" />
          <h3 className="text-sm font-semibold text-white">Protocol Hierarchy</h3>
        </div>
        <div className="flex items-center gap-4 text-[10px] text-slate-500">
          <span>{uniqueProtocols.size} protocols</span>
          <span>{totalPackets.toLocaleString()} packets</span>
          <span>{formatBytes(totalBytes)}</span>
        </div>
      </div>

      {/* Column headers */}
      <div className="flex items-center gap-2 px-5 py-1.5 border-b border-slate-700/30 text-[10px] text-slate-600 uppercase tracking-wider font-medium">
        <span className="flex-1">Protocol</span>
        <span className="w-14 text-right">%</span>
        <span className="w-16 text-right">Bytes</span>
        <span className="w-14 text-right">Packets</span>
      </div>

      {/* Tree */}
      <div className="py-1 max-h-[500px] overflow-y-auto">
        {hierarchy.map((node, i) => (
          <TreeNode key={i} node={node} depth={0} />
        ))}
      </div>
    </div>
  );
}
