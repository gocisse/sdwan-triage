import React from 'react';
import {
  X,
  AlertCircle,
  CheckCircle,
  XCircle,
  Info,
  Lightbulb,
  FileText,
  Layers,
  Network,
} from 'lucide-react';
import type { Discrepancy } from '../types';

interface DiscrepancyDeepDiveProps {
  discrepancy: Discrepancy;
  onClose: () => void;
}

interface ForensicExplanation {
  event: string;
  failure: string;
  logic: string;
  seniorTip: string;
  configCheck: string[];
  hexHighlights?: HexHighlight[];
}

interface HexHighlight {
  offset: number;
  length: number;
  label: string;
  description: string;
  color: string;
}

export const DiscrepancyDeepDive: React.FC<DiscrepancyDeepDiveProps> = ({ discrepancy, onClose }) => {
  const explanation = getForensicExplanation(discrepancy);
  const hexDump = generateMockHexDump(discrepancy);

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-w-5xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Lightbulb className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Forensic Coach: Packet Deep-Dive</h2>
              <p className="text-xs text-slate-400">
                Packet #{discrepancy.packet_index} • {discrepancy.state.replace('_', ' ')}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Packet Summary */}
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <Network className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-semibold text-white">Packet Summary</span>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-slate-500">Flow:</span>
                <div className="font-mono text-slate-300 mt-1">
                  {discrepancy.src_ip}:{discrepancy.src_port} → {discrepancy.dst_ip}:{discrepancy.dst_port}
                </div>
              </div>
              <div>
                <span className="text-slate-500">Protocol:</span>
                <div className="text-slate-300 mt-1">{discrepancy.protocol}</div>
              </div>
              <div>
                <span className="text-slate-500">Timestamp:</span>
                <div className="font-mono text-slate-300 mt-1">{discrepancy.timestamp}</div>
              </div>
              <div>
                <span className="text-slate-500">Length:</span>
                <div className="text-slate-300 mt-1">{discrepancy.length} bytes</div>
              </div>
              {discrepancy.tcp_flags && (
                <div className="col-span-2">
                  <span className="text-slate-500">TCP Flags:</span>
                  <div className="text-slate-300 mt-1">
                    <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-[10px] font-mono">
                      {discrepancy.tcp_flags}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Forensic Explanation */}
          <div className="space-y-4">
            {/* The Event */}
            <div className="bg-blue-900/20 border border-blue-700/40 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-sm font-semibold text-blue-300 mb-1">The Event</div>
                  <p className="text-sm text-slate-300 leading-relaxed">{explanation.event}</p>
                </div>
              </div>
            </div>

            {/* The Failure */}
            <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-sm font-semibold text-red-300 mb-1">The Failure</div>
                  <p className="text-sm text-slate-300 leading-relaxed">{explanation.failure}</p>
                </div>
              </div>
            </div>

            {/* The Logic */}
            <div className="bg-purple-900/20 border border-purple-700/40 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-sm font-semibold text-purple-300 mb-1">The Logic (Why We Know This)</div>
                  <p className="text-sm text-slate-300 leading-relaxed">{explanation.logic}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Senior Engineer Tip */}
          <div className="bg-gradient-to-r from-yellow-900/20 to-orange-900/20 border border-yellow-700/40 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Lightbulb className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div className="flex-1">
                <div className="text-sm font-semibold text-yellow-300 mb-2">
                  💡 What Would a Senior Engineer Check?
                </div>
                <p className="text-sm text-slate-300 leading-relaxed mb-3">{explanation.seniorTip}</p>
                
                {explanation.configCheck.length > 0 && (
                  <div>
                    <div className="text-xs font-medium text-yellow-400 mb-2">Configuration to Review:</div>
                    <ul className="space-y-1.5">
                      {explanation.configCheck.map((item, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                          <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0 mt-0.5" />
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Hex Dump with Highlights */}
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <FileText className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-semibold text-white">Packet Data (Simulated)</span>
              <span className="text-xs text-slate-500">
                • Hover over highlighted bytes for explanations
              </span>
            </div>
            <div className="font-mono text-xs bg-slate-900 rounded p-3 overflow-x-auto">
              {hexDump.map((line, i) => (
                <div key={i} className="flex gap-4 hover:bg-slate-800/50 px-1 py-0.5">
                  <span className="text-slate-600 select-none">{line.offset}</span>
                  <span className="text-slate-400">{line.hex}</span>
                  <span className="text-slate-600">{line.ascii}</span>
                </div>
              ))}
            </div>
            
            {/* Legend for highlighted fields */}
            {explanation.hexHighlights && explanation.hexHighlights.length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-700/50">
                <div className="text-xs font-medium text-slate-400 mb-2">Field Highlights:</div>
                <div className="flex flex-wrap gap-2">
                  {explanation.hexHighlights.map((hl, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-1.5 px-2 py-1 bg-slate-800 rounded text-xs"
                    >
                      <div className={`w-2 h-2 rounded-full ${hl.color}`} />
                      <span className="text-slate-300">{hl.label}</span>
                      <span className="text-slate-500">•</span>
                      <span className="text-slate-400">{hl.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Additional Context */}
          {discrepancy.tunnel_type && (
            <div className="bg-cyan-900/20 border border-cyan-700/40 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <Layers className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="text-sm font-semibold text-cyan-300 mb-1">Tunnel Context</div>
                  <p className="text-sm text-slate-300">
                    This packet was encapsulated in a <span className="font-semibold text-cyan-400">{discrepancy.tunnel_type}</span> tunnel.
                    The outer headers were added by the SD-WAN device for transport across the WAN.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-700 bg-slate-800/50">
          <div className="flex items-center justify-between">
            <div className="text-xs text-slate-500">
              💡 Tip: Use this analysis to understand <span className="text-slate-400 font-medium">why</span> the packet was flagged
            </div>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
            >
              Got It
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Forensic Explanation Generator ───────────────────────────────

function getForensicExplanation(d: Discrepancy): ForensicExplanation {
  // MISSING_B: Dropped packets
  if (d.state === 'MISSING_B') {
    // TCP SYN dropped
    if (d.tcp_flags && d.tcp_flags.includes('SYN') && !d.tcp_flags.includes('ACK')) {
      return {
        event: `This TCP SYN packet tried to start a new connection from ${d.src_ip}:${d.src_port} to ${d.dst_ip}:${d.dst_port} on the LAN side.`,
        failure: 'It never appeared on the WAN side. The SD-WAN device silently dropped it before it could reach the tunnel.',
        logic: 'Because only the first packet (SYN) is missing, this indicates a Firewall/ACL block, not a link failure. If the link was down, we would see many consecutive drops across multiple flows.',
        seniorTip: `Compare the source IP (${d.src_ip}) and destination IP (${d.dst_ip}) against your Firewall Rules and Zone-Based Firewall (ZBFW) policies. Is this source allowed to talk to this destination on port ${d.dst_port}? Check for "implicit deny" rules that might be catching legitimate traffic.`,
        configCheck: [
          `Check Zone-Based Firewall (ZBFW) policy: Does the zone pair allow traffic from ${d.src_ip} to ${d.dst_ip}?`,
          `Review Access Control Lists (ACL): Is there an ACL blocking port ${d.dst_port} (${getServiceName(d.dst_port)})?`,
          `Verify SD-WAN App-Aware Routing: Is this application classified and allowed?`,
          `Check interface service policies: Are there any "deny" statements on the LAN or WAN interface?`,
        ],
        hexHighlights: [
          { offset: 47, length: 1, label: 'SYN Flag', description: 'Bit set to 1 = new connection', color: 'bg-blue-400' },
          { offset: 36, length: 2, label: 'Dst Port', description: `${d.dst_port} (${getServiceName(d.dst_port)})`, color: 'bg-green-400' },
        ],
      };
    }

    // Large packet dropped (MTU issue)
    if (d.length > 1400) {
      return {
        event: `This ${d.protocol} packet (${d.length} bytes) was sent from ${d.src_ip} to ${d.dst_ip} on the LAN side.`,
        failure: 'It never appeared on the WAN side. The packet was too large to fit in the tunnel after encapsulation overhead was added.',
        logic: `The packet size (${d.length} bytes) exceeds the typical tunnel MTU (1400-1460 bytes). When the SD-WAN device tried to encapsulate it (adding 40-60 bytes of tunnel headers), it exceeded the interface MTU and was dropped. Path MTU Discovery (PMTUD) should have prevented this, but it may be broken.`,
        seniorTip: `Check the interface MTU settings on both LAN and WAN interfaces. For tunneled traffic, the WAN interface MTU should be at least 1500 bytes, and the tunnel MTU should be 1400-1460 bytes. Also verify that ICMP "Fragmentation Needed" messages are not being blocked by a firewall.`,
        configCheck: [
          `Check WAN interface MTU: Should be 1500+ bytes (show interface <wan-if>)`,
          `Check tunnel interface MTU: Should be 1400-1460 bytes (show interface tunnel <id>)`,
          `Verify TCP MSS clamping: Should be set to 1360-1420 bytes (ip tcp adjust-mss)`,
          `Check if ICMP is blocked: PMTUD requires ICMP Type 3 Code 4 (Fragmentation Needed)`,
          `Review QoS policies: Some policers drop large packets`,
        ],
        hexHighlights: [
          { offset: 16, length: 2, label: 'Total Length', description: `${d.length} bytes (too large)`, color: 'bg-red-400' },
          { offset: 20, length: 2, label: 'Fragment Offset', description: 'DF bit may be set', color: 'bg-yellow-400' },
        ],
      };
    }

    // UDP drop
    if (d.protocol === 'UDP') {
      return {
        event: `This UDP packet was sent from ${d.src_ip}:${d.src_port} to ${d.dst_ip}:${d.dst_port} on the LAN side.`,
        failure: 'It was not forwarded to the WAN. The SD-WAN device dropped it.',
        logic: 'UDP is connectionless, so there is no handshake to fail. The drop is likely due to an Application-Aware policy blocking this specific application, or a port-based ACL.',
        seniorTip: `Check the SD-WAN App-Aware Routing policy. Is port ${d.dst_port} (${getServiceName(d.dst_port)}) classified as an application that should be blocked or deprioritized? Also verify that there are no ACLs blocking UDP traffic to this destination.`,
        configCheck: [
          `Check App-Aware Routing policy: Is ${getServiceName(d.dst_port)} allowed?`,
          `Review ACLs for UDP port ${d.dst_port}`,
          `Verify QoS policies: Is this traffic being policed/dropped?`,
          `Check for rate limiting on the WAN interface`,
        ],
        hexHighlights: [
          { offset: 23, length: 1, label: 'Protocol', description: '17 = UDP', color: 'bg-purple-400' },
          { offset: 36, length: 2, label: 'Dst Port', description: `${d.dst_port} (${getServiceName(d.dst_port)})`, color: 'bg-green-400' },
        ],
      };
    }

    // TCP data drop
    if (d.protocol === 'TCP') {
      return {
        event: `This TCP data packet was part of an established connection from ${d.src_ip}:${d.src_port} to ${d.dst_ip}:${d.dst_port}.`,
        failure: 'It was dropped mid-flow. The connection was already established, but this specific packet never made it to the WAN.',
        logic: 'Since the connection was already established (this is not a SYN), the drop indicates either a mid-flow policy enforcement, a route change, or buffer overflow on the device. Check interface utilization and QoS queues.',
        seniorTip: `Check the interface utilization on the WAN interface. If it is near 100%, packets are being tail-dropped due to congestion. Also review QoS policies to see if this traffic class is being deprioritized or policed.`,
        configCheck: [
          `Check WAN interface utilization: show interface <wan-if> | include rate`,
          `Review QoS queue statistics: show policy-map interface <wan-if>`,
          `Check for route flapping: show ip route ${d.dst_ip}`,
          `Verify no mid-flow ACL changes were made`,
        ],
        hexHighlights: [
          { offset: 47, length: 1, label: 'TCP Flags', description: d.tcp_flags || 'ACK/PSH', color: 'bg-blue-400' },
          { offset: 42, length: 4, label: 'Seq Number', description: 'Identifies this packet in the stream', color: 'bg-cyan-400' },
        ],
      };
    }

    // Generic drop
    return {
      event: `This ${d.protocol} packet was sent from ${d.src_ip} to ${d.dst_ip} on the LAN side.`,
      failure: 'It never appeared on the WAN side. The SD-WAN device dropped it.',
      logic: 'The packet entered the LAN interface but did not exit the WAN interface. This could be due to a routing issue, firewall rule, or interface problem.',
      seniorTip: `Check the routing table to ensure there is a valid route to ${d.dst_ip}. Also verify that the WAN interface is up and that there are no firewall rules blocking this traffic.`,
      configCheck: [
        `Check routing table: show ip route ${d.dst_ip}`,
        `Verify WAN interface status: show interface <wan-if>`,
        `Review firewall rules and ACLs`,
        `Check for any recent configuration changes`,
      ],
      hexHighlights: [],
    };
  }

  // MISSING_A: Asymmetric routing
  if (d.state === 'MISSING_A') {
    if (d.encrypted) {
      return {
        event: `This encrypted packet appeared on the WAN side but has no matching packet on the LAN side.`,
        failure: 'There is no failure here. This is normal behavior.',
        logic: 'The SD-WAN device itself generated this packet as part of the tunnel control plane (BFD keepalive, OMP update, or DTLS handshake). These packets originate from the device, not from user endpoints, so they will never appear in the LAN capture.',
        seniorTip: `This is expected behavior. Control plane traffic (BFD, OMP, DTLS) is generated by the SD-WAN device to maintain tunnel health and exchange routing information. These packets are excluded from the Path Integrity Score denominator because they are not user data.`,
        configCheck: [
          `Verify BFD is healthy: show bfd summary`,
          `Check OMP peer status: show sdwan omp peers`,
          `Review tunnel status: show sdwan ipsec outbound-connections`,
        ],
        hexHighlights: [
          { offset: 23, length: 1, label: 'Protocol', description: '50 = ESP (encrypted)', color: 'bg-cyan-400' },
        ],
      };
    }

    if (d.protocol === 'ICMP' || d.protocol === 'ICMPv6') {
      return {
        event: `This ICMP packet appeared on the WAN side but not on the LAN side.`,
        failure: 'There is no failure here. This is normal behavior.',
        logic: 'The SD-WAN device generated this ICMP packet itself (ping, traceroute, or ICMP unreachable). Devices probe WAN paths for SLA measurement and send ICMP unreachables when they drop packets.',
        seniorTip: `This is expected. SD-WAN devices continuously probe WAN paths using ICMP to measure latency, jitter, and packet loss for SLA monitoring. These probes help the device make intelligent path selection decisions.`,
        configCheck: [
          `Check SLA monitoring: show sdwan policy sla-class`,
          `Review app-route policy: show sdwan policy app-route`,
        ],
        hexHighlights: [
          { offset: 23, length: 1, label: 'Protocol', description: '1 = ICMP', color: 'bg-blue-400' },
          { offset: 34, length: 1, label: 'ICMP Type', description: 'Echo Request/Reply', color: 'bg-green-400' },
        ],
      };
    }

    return {
      event: `This packet appeared on the WAN side but not on the LAN side.`,
      failure: 'This indicates asymmetric routing or traffic injected by a remote site.',
      logic: 'The packet came from the WAN, but it did not originate from the local LAN. This is common for return traffic that is using a different path (e.g., direct internet breakout at the remote site), or traffic from another branch arriving via the SD-WAN fabric.',
      seniorTip: `Check if this is return traffic from a flow that originated locally. If the source IP is external (internet), verify your DIA (Direct Internet Access) policy. If the source is another branch, this is normal SD-WAN fabric traffic.`,
      configCheck: [
        `Check if source IP is from another branch: show sdwan omp routes`,
        `Review DIA policy: show sdwan policy app-route`,
        `Verify this is not a routing loop`,
      ],
      hexHighlights: [],
    };
  }

  // MODIFIED: NAT/QoS changes
  if (d.state === 'MODIFIED') {
    const changes = d.field_changes?.map(fc => fc.field).join(', ') || '';
    if (changes.includes('SrcIP') || changes.includes('DstIP')) {
      return {
        event: `This packet was found in both LAN and WAN captures, but the IP address was changed.`,
        failure: 'There is no failure here. This is expected NAT behavior.',
        logic: 'The SD-WAN device applied Network Address Translation (NAT), changing the source or destination IP. This is normal for internet-bound traffic or when the device is performing NAT for private IP ranges.',
        seniorTip: `Verify the NAT pool configuration matches your design. For internet-bound traffic, the source IP should be translated to a public IP. For site-to-site traffic, NAT should not be applied unless explicitly configured.`,
        configCheck: [
          `Check NAT pool: show ip nat translations`,
          `Review NAT configuration: show run | section ip nat`,
          `Verify DIA policy is applying NAT correctly`,
        ],
        hexHighlights: [
          { offset: 26, length: 4, label: 'Src IP', description: 'Changed by NAT', color: 'bg-yellow-400' },
          { offset: 30, length: 4, label: 'Dst IP', description: 'May be changed by NAT', color: 'bg-yellow-400' },
        ],
      };
    }

    if (changes.includes('DSCP')) {
      return {
        event: `This packet was found in both captures, but the DSCP (QoS marking) was changed.`,
        failure: 'There is no failure here. This is expected QoS policy behavior.',
        logic: 'The SD-WAN device applied a QoS policy that remarked the DSCP value. This is used to prioritize traffic (e.g., marking voice as EF, video as AF41) so that downstream routers can apply appropriate queuing.',
        seniorTip: `Verify the App-Aware Routing policy is classifying traffic correctly. The DSCP remarking should match your QoS design (e.g., voice = EF/46, video = AF41/34, bulk data = AF11/10).`,
        configCheck: [
          `Check QoS policy: show policy-map interface <wan-if>`,
          `Review app-route policy: show sdwan policy app-route`,
          `Verify DSCP values match design: show sdwan app-route stats`,
        ],
        hexHighlights: [
          { offset: 15, length: 1, label: 'DSCP', description: 'QoS marking changed', color: 'bg-purple-400' },
        ],
      };
    }

    return {
      event: `This packet was found in both captures, but some fields were modified.`,
      failure: 'There is no failure here. The SD-WAN device altered the packet as part of normal operation.',
      logic: `The device changed: ${changes}. This is expected behavior for routing (TTL decrement), NAT (IP changes), or QoS (DSCP remarking).`,
      seniorTip: `Review the specific field changes to understand what the device did. TTL changes are normal (each hop decrements TTL by 1). NAT and DSCP changes should match your policy configuration.`,
      configCheck: [
        `Review the field changes in the discrepancy detail`,
        `Verify changes match your policy design`,
      ],
      hexHighlights: [],
    };
  }

  // Default
  return {
    event: `This packet was found in both LAN and WAN captures.`,
    failure: 'There is no failure. This packet successfully transited the SD-WAN device.',
    logic: 'The packet was matched in both captures, indicating successful forwarding.',
    seniorTip: `This is normal behavior. The packet was forwarded correctly.`,
    configCheck: [],
    hexHighlights: [],
  };
}

// ─── Helper Functions ──────────────────────────────────────────────

function getServiceName(port: number): string {
  const services: Record<number, string> = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 123: 'NTP', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-TRAP',
    179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 514: 'Syslog',
    587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP', 5061: 'SIP-TLS',
    8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
  };
  return services[port] || 'Unknown';
}

function generateMockHexDump(d: Discrepancy): Array<{ offset: string; hex: string; ascii: string }> {
  // Generate a realistic-looking hex dump based on the discrepancy
  const lines: Array<{ offset: string; hex: string; ascii: string }> = [];
  
  // Ethernet header (14 bytes)
  lines.push({
    offset: '0000',
    hex: 'ff ff ff ff ff ff 00 11 22 33 44 55 08 00',
    ascii: '..........3DU..',
  });
  
  // IP header (20 bytes) - simplified
  const srcOctets = d.src_ip.split('.').map(n => parseInt(n).toString(16).padStart(2, '0'));
  const dstOctets = d.dst_ip.split('.').map(n => parseInt(n).toString(16).padStart(2, '0'));
  const totalLen = d.length.toString(16).padStart(4, '0');
  const protocol = d.protocol === 'TCP' ? '06' : d.protocol === 'UDP' ? '11' : '01';
  
  lines.push({
    offset: '0010',
    hex: `45 00 ${totalLen.slice(0, 2)} ${totalLen.slice(2)} 00 01 00 00 40 ${protocol}`,
    ascii: 'E.....@...@.',
  });
  
  lines.push({
    offset: '0020',
    hex: `00 00 ${srcOctets.join(' ')} ${dstOctets.join(' ')}`,
    ascii: `..${d.src_ip.slice(0, 8).padEnd(8, '.')}`,
  });
  
  // TCP/UDP header
  if (d.protocol === 'TCP') {
    const srcPort = d.src_port.toString(16).padStart(4, '0');
    const dstPort = d.dst_port.toString(16).padStart(4, '0');
    const flags = d.tcp_flags?.includes('SYN') ? '02' : '10';
    
    lines.push({
      offset: '0030',
      hex: `${srcPort.slice(0, 2)} ${srcPort.slice(2)} ${dstPort.slice(0, 2)} ${dstPort.slice(2)} 00 00 00 01 00 00 00 00`,
      ascii: '............',
    });
    
    lines.push({
      offset: '0040',
      hex: `50 ${flags} 20 00 00 00 00 00 00 00 00 00 00 00`,
      ascii: 'P. ............',
    });
  } else {
    const srcPort = d.src_port.toString(16).padStart(4, '0');
    const dstPort = d.dst_port.toString(16).padStart(4, '0');
    
    lines.push({
      offset: '0030',
      hex: `${srcPort.slice(0, 2)} ${srcPort.slice(2)} ${dstPort.slice(0, 2)} ${dstPort.slice(2)} 00 08 00 00`,
      ascii: '........',
    });
  }
  
  // Payload (simplified)
  lines.push({
    offset: '0050',
    hex: '47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a',
    ascii: 'GET / HTTP/1.1..',
  });
  
  return lines;
}
