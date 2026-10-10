// filterResults — Applies global IP/port/protocol filters to AnalysisResults.
// Supports partial matches (e.g., '10.0' matches '10.0.0.5').

import type { AnalysisResults } from '../types';
import type { GlobalFilters } from '../contexts/FilterContext';

// Well-known service-to-port mapping for text-based port filter
const SERVICE_MAP: Record<string, number[]> = {
  http: [80, 8080],
  https: [443, 8443],
  dns: [53],
  ssh: [22],
  ftp: [21, 20],
  smtp: [25, 587],
  ntp: [123],
  snmp: [161, 162],
  rdp: [3389],
  telnet: [23],
  sip: [5060, 5061],
  rtp: [5004],
  imap: [143, 993],
  pop3: [110, 995],
  mysql: [3306],
  postgres: [5432],
  redis: [6379],
  ldap: [389, 636],
};

/** Check if an IP matches the partial filter (prefix match) */
function matchIP(ip: string | undefined | null, filter: string): boolean {
  if (!filter) return true;
  if (!ip) return false;
  return ip.startsWith(filter) || ip.includes(filter);
}

/** Check if a port matches the filter (number or service name) */
function matchPort(port: number | undefined | null, filter: string): boolean {
  if (!filter) return true;
  if (port === undefined || port === null) return false;
  // Try numeric match
  const numFilter = parseInt(filter, 10);
  if (!isNaN(numFilter)) {
    return port === numFilter;
  }
  // Try service name match
  const servicePorts = SERVICE_MAP[filter.toLowerCase()];
  if (servicePorts) {
    return servicePorts.includes(port);
  }
  return false;
}

/** Check if a protocol matches */
function matchProtocol(protocol: string | undefined | null, filter: 'all' | 'tcp' | 'udp'): boolean {
  if (filter === 'all') return true;
  if (!protocol) return false;
  return protocol.toLowerCase() === filter;
}

/** Check if any port in a flow matches */
function flowMatchesPort(srcPort: number | undefined, dstPort: number | undefined, filter: string): boolean {
  if (!filter) return true;
  return matchPort(srcPort, filter) || matchPort(dstPort, filter);
}

/** Check if a flow matches IP filters (src or dst in either direction) */
function flowMatchesIPs(
  srcIP: string | undefined,
  dstIP: string | undefined,
  filterSrc: string,
  filterDst: string
): boolean {
  if (!filterSrc && !filterDst) return true;
  if (filterSrc && filterDst) {
    return matchIP(srcIP, filterSrc) && matchIP(dstIP, filterDst);
  }
  if (filterSrc) {
    return matchIP(srcIP, filterSrc) || matchIP(dstIP, filterSrc);
  }
  if (filterDst) {
    return matchIP(srcIP, filterDst) || matchIP(dstIP, filterDst);
  }
  return true;
}

/**
 * Apply global filters to AnalysisResults.
 * Returns a new AnalysisResults object with filtered arrays.
 * Non-filterable top-level data (risk_score, packet_count, etc.) is preserved.
 */
export function filterResults(results: AnalysisResults, filters: GlobalFilters): AnalysisResults {
  const { srcIP, dstIP, port, protocol } = filters;
  const noFilter = !srcIP && !dstIP && !port && protocol === 'all';
  if (noFilter) return results;

  const filtered: AnalysisResults = { ...results };

  // ─── Security Findings ──────────────────────────────────────
  if (results.security) {
    filtered.security = { ...results.security };

    if (results.security.ddos_findings) {
      filtered.security.ddos_findings = results.security.ddos_findings.filter(f =>
        flowMatchesIPs(f.source_ip, f.target_ip, srcIP, dstIP)
      );
    }
    if (results.security.port_scan_findings) {
      filtered.security.port_scan_findings = results.security.port_scan_findings.filter(f =>
        flowMatchesIPs(f.source_ip, f.target_ip, srcIP, dstIP)
      );
    }
    if (results.security.ioc_findings) {
      filtered.security.ioc_findings = results.security.ioc_findings.filter(f =>
        flowMatchesIPs(f.source_ip, f.dest_ip, srcIP, dstIP)
      );
    }
    if (results.security.tls_security_findings) {
      filtered.security.tls_security_findings = results.security.tls_security_findings.filter(f =>
        flowMatchesIPs(f.server_ip, undefined, srcIP, dstIP) &&
        flowMatchesPort(f.server_port, undefined, port)
      );
    }
  }

  // ─── TCP Flows ──────────────────────────────────────────────
  if (results.tcp_retransmissions) {
    filtered.tcp_retransmissions = results.tcp_retransmissions.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port)
    );
  }
  if (results.failed_handshakes) {
    filtered.failed_handshakes = results.failed_handshakes.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port)
    );
  }

  // ─── TCP Handshakes ─────────────────────────────────────────
  if (results.tcp_handshakes) {
    const filterHandshakeFlows = (flows: typeof results.tcp_handshakes.syn_flows) =>
      flows?.filter(f =>
        flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
        flowMatchesPort(f.src_port, f.dst_port, port)
      );
    filtered.tcp_handshakes = {
      syn_flows: filterHandshakeFlows(results.tcp_handshakes.syn_flows),
      synack_flows: filterHandshakeFlows(results.tcp_handshakes.synack_flows),
      successful_handshakes: filterHandshakeFlows(results.tcp_handshakes.successful_handshakes),
      failed_handshake_attempts: filterHandshakeFlows(results.tcp_handshakes.failed_handshake_attempts),
    };
  }

  // ─── Traffic Analysis ───────────────────────────────────────
  if (results.traffic_analysis) {
    filtered.traffic_analysis = results.traffic_analysis.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port) &&
      matchProtocol(f.protocol, protocol)
    );
  }

  // ─── RTT Analysis ──────────────────────────────────────────
  if (results.rtt_analysis) {
    filtered.rtt_analysis = results.rtt_analysis.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port)
    );
  }

  // ─── Tunnel Analysis ───────────────────────────────────────
  if (results.tunnel_analysis) {
    filtered.tunnel_analysis = results.tunnel_analysis.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port)
    );
  }

  // ─── Timeline ──────────────────────────────────────────────
  if (results.timeline) {
    filtered.timeline = results.timeline.filter(f =>
      flowMatchesIPs(f.source_ip, f.dest_ip, srcIP, dstIP) &&
      matchProtocol(f.protocol, protocol)
    );
  }

  // ─── DNS Anomalies ─────────────────────────────────────────
  if (results.dns_anomalies) {
    filtered.dns_anomalies = results.dns_anomalies.filter(f =>
      flowMatchesIPs(f.server_ip, f.answer_ip, srcIP, dstIP)
    );
  }

  // ─── Packet Loss (per-flow) ────────────────────────────────
  if (results.packet_loss?.per_flow_loss) {
    filtered.packet_loss = {
      ...results.packet_loss,
      per_flow_loss: results.packet_loss.per_flow_loss.filter(f =>
        flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
        flowMatchesPort(f.src_port, f.dst_port, port) &&
        matchProtocol(f.protocol, protocol)
      ),
    };
  }

  // ─── Bandwidth Report ──────────────────────────────────────
  if (results.bandwidth_report) {
    filtered.bandwidth_report = {
      top_conversations_by_bytes: results.bandwidth_report.top_conversations_by_bytes?.filter(f =>
        flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
        matchProtocol(f.protocol, protocol)
      ),
      top_conversations_by_packets: results.bandwidth_report.top_conversations_by_packets?.filter(f =>
        flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
        matchProtocol(f.protocol, protocol)
      ),
    };
  }

  // ─── DNS Tunneling ─────────────────────────────────────────
  if (results.dns_tunneling_findings) {
    filtered.dns_tunneling_findings = results.dns_tunneling_findings.filter(f =>
      flowMatchesIPs(f.source_ip, f.server_ip, srcIP, dstIP)
    );
  }

  // ─── C2 Beaconing ─────────────────────────────────────────
  if (results.c2_beaconing_findings) {
    filtered.c2_beaconing_findings = results.c2_beaconing_findings.filter(f =>
      flowMatchesIPs(f.source_ip, f.dest_ip, srcIP, dstIP) &&
      flowMatchesPort(undefined, f.dest_port, port) &&
      matchProtocol(f.protocol, protocol)
    );
  }

  // ─── TCP Window Findings ───────────────────────────────────
  if (results.tcp_window_findings) {
    filtered.tcp_window_findings = results.tcp_window_findings.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port)
    );
  }

  // ─── TCP Out-of-Order ──────────────────────────────────────
  if (results.tcp_out_of_order_flows) {
    filtered.tcp_out_of_order_flows = results.tcp_out_of_order_flows.filter(f =>
      flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP) &&
      flowMatchesPort(f.src_port, f.dst_port, port)
    );
  }

  // ─── NTP Findings ──────────────────────────────────────────
  if (results.ntp_findings) {
    filtered.ntp_findings = results.ntp_findings.filter(f =>
      flowMatchesIPs(f.source_ip, f.dest_ip, srcIP, dstIP)
    );
  }

  // ─── DHCP Findings ─────────────────────────────────────────
  if (results.dhcp_findings) {
    filtered.dhcp_findings = results.dhcp_findings.filter(f =>
      flowMatchesIPs(f.server_ip, f.offered_ip, srcIP, dstIP)
    );
  }

  // ─── ICMP Analysis ─────────────────────────────────────────
  if (results.icmp_analysis) {
    filtered.icmp_analysis = results.icmp_analysis.filter(f =>
      flowMatchesIPs(f.source_ip, f.dest_ip, srcIP, dstIP)
    );
  }

  // ─── VoIP Analysis ─────────────────────────────────────────
  if (results.voip_analysis) {
    filtered.voip_analysis = { ...results.voip_analysis };
    if (results.voip_analysis.sip_calls) {
      filtered.voip_analysis.sip_calls = results.voip_analysis.sip_calls.filter(f =>
        flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP)
      );
    }
    if (results.voip_analysis.rtp_streams) {
      filtered.voip_analysis.rtp_streams = results.voip_analysis.rtp_streams.filter(f =>
        flowMatchesIPs(f.src_ip, f.dst_ip, srcIP, dstIP)
      );
    }
  }

  // ─── TLS Certs ─────────────────────────────────────────────
  if (results.tls_certs) {
    filtered.tls_certs = results.tls_certs.filter(f =>
      flowMatchesIPs(f.server_ip, undefined, srcIP, dstIP) &&
      flowMatchesPort(f.server_port, undefined, port)
    );
  }

  // ─── Stability Findings ────────────────────────────────────
  if (results.stability_findings) {
    filtered.stability_findings = results.stability_findings.filter(f =>
      flowMatchesIPs(f.source_ip, f.peer_ip, srcIP, dstIP)
    );
  }

  // ─── Threat Intel Matches ───────────────────────────────────
  if (results.threat_intel_matches) {
    filtered.threat_intel_matches = results.threat_intel_matches.filter(f =>
      flowMatchesIPs(f.source_ip, f.dest_ip, srcIP, dstIP)
    );
  }

  return filtered;
}
