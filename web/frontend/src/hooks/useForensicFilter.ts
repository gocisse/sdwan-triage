// Global forensic filter engine — Wireshark-like display filter with React context

import { createContext, useContext } from 'react';
import type { AnalysisResults } from '../types';

// ─── Filter AST ──────────────────────────────────────────────────
export interface FilterToken {
  field: string;       // e.g. 'ip.src', 'tcp.port', 'dns.qry.name'
  operator: '==' | '!=' | 'contains' | '>' | '<';
  value: string;
}

export interface ParsedFilter {
  tokens: FilterToken[];
  raw: string;
  valid: boolean;
  error?: string;
}

// ─── Supported Fields ────────────────────────────────────────────
const FIELD_HELP: Record<string, string> = {
  'ip.src':        'Source IP address',
  'ip.dst':        'Destination IP address',
  'ip.addr':       'Any IP address (src or dst)',
  'tcp.port':      'TCP port (src or dst)',
  'tcp.srcport':   'TCP source port',
  'tcp.dstport':   'TCP destination port',
  'udp.port':      'UDP port (src or dst)',
  'udp.srcport':   'UDP source port',
  'udp.dstport':   'UDP destination port',
  'dns.qry.name':  'DNS query domain name',
  'frame.protocol': 'Protocol name (TCP, UDP, DNS, etc.)',
  'frame.time_epoch': 'Packet timestamp (epoch seconds, use > and <)',
  'eth.type':       'Ethernet type',
};

export function getFieldSuggestions(): Array<{ field: string; help: string }> {
  return Object.entries(FIELD_HELP).map(([field, help]) => ({ field, help }));
}

// ─── Parser ──────────────────────────────────────────────────────
export function parseFilter(raw: string): ParsedFilter {
  const trimmed = raw.trim();
  if (!trimmed) return { tokens: [], raw: trimmed, valid: true };

  const tokens: FilterToken[] = [];
  // Split on ' && ' or ' and ' (case-insensitive)
  const clauses = trimmed.split(/\s+(?:&&|and)\s+/i);

  for (const clause of clauses) {
    const c = clause.trim();
    if (!c) continue;

    // Try operators: ==, !=, contains, >, <
    let match = c.match(/^([a-zA-Z_.]+)\s*(==|!=|contains|>|<)\s*(.+)$/i);
    if (match) {
      const field = match[1].toLowerCase();
      const operator = match[2].toLowerCase() as FilterToken['operator'];
      const value = match[3].replace(/^["']|["']$/g, ''); // strip quotes
      if (!FIELD_HELP[field]) {
        return { tokens: [], raw: trimmed, valid: false, error: `Unknown field: ${field}` };
      }
      tokens.push({ field, operator, value });
    } else {
      // Try shorthand: just "ip.src 10.0.0.1" → "ip.src == 10.0.0.1"
      match = c.match(/^([a-zA-Z_.]+)\s+(.+)$/);
      if (match) {
        const field = match[1].toLowerCase();
        const value = match[2].replace(/^["']|["']$/g, '');
        if (!FIELD_HELP[field]) {
          return { tokens: [], raw: trimmed, valid: false, error: `Unknown field: ${field}` };
        }
        tokens.push({ field, operator: '==', value });
      } else {
        return { tokens: [], raw: trimmed, valid: false, error: `Invalid expression: ${c}` };
      }
    }
  }

  return { tokens, raw: trimmed, valid: true };
}

// ─── Matcher ─────────────────────────────────────────────────────
interface Matchable {
  src_ip?: string;
  dst_ip?: string;
  source_ip?: string;
  dest_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  query?: string;      // DNS
  domain?: string;     // DNS tunneling
  timestamp?: string | number;  // ISO timestamp for time-range filtering
}

function matchValue(actual: string | undefined, op: FilterToken['operator'], expected: string): boolean {
  if (actual === undefined) return false;
  const a = actual.toLowerCase();
  const e = expected.toLowerCase();
  switch (op) {
    case '==': return a === e;
    case '!=': return a !== e;
    case 'contains': return a.includes(e);
    case '>': return parseFloat(a) > parseFloat(e);
    case '<': return parseFloat(a) < parseFloat(e);
    default: return false;
  }
}

export function matchesFilter(item: Matchable, filter: ParsedFilter): boolean {
  if (!filter.valid || filter.tokens.length === 0) return true;

  const srcIp = item.src_ip || item.source_ip || '';
  const dstIp = item.dst_ip || item.dest_ip || '';
  const srcPort = String(item.src_port ?? '');
  const dstPort = String(item.dst_port ?? '');
  const protocol = item.protocol || '';
  const dnsName = item.query || item.domain || '';

  for (const token of filter.tokens) {
    let matches = false;

    switch (token.field) {
      case 'ip.src':
        matches = matchValue(srcIp, token.operator, token.value);
        break;
      case 'ip.dst':
        matches = matchValue(dstIp, token.operator, token.value);
        break;
      case 'ip.addr':
        matches = matchValue(srcIp, token.operator, token.value) ||
                  matchValue(dstIp, token.operator, token.value);
        break;
      case 'tcp.port':
      case 'udp.port':
        matches = matchValue(srcPort, token.operator, token.value) ||
                  matchValue(dstPort, token.operator, token.value);
        break;
      case 'tcp.srcport':
      case 'udp.srcport':
        matches = matchValue(srcPort, token.operator, token.value);
        break;
      case 'tcp.dstport':
      case 'udp.dstport':
        matches = matchValue(dstPort, token.operator, token.value);
        break;
      case 'dns.qry.name':
        matches = matchValue(dnsName, token.operator, token.value);
        break;
      case 'frame.protocol':
        matches = matchValue(protocol, token.operator, token.value);
        break;
      case 'eth.type':
        matches = matchValue(protocol, token.operator, token.value);
        break;
      case 'frame.time_epoch': {
        const rawTs = item.timestamp;
        const ts = typeof rawTs === 'number' ? rawTs : (rawTs ? new Date(rawTs).getTime() / 1000 : 0);
        if (ts > 0) {
          matches = matchValue(String(ts), token.operator, token.value);
        } else {
          matches = false;
        }
        break;
      }
      default:
        matches = false;
    }

    if (!matches) return false; // AND logic
  }
  return true;
}

// ─── Filtered Results Helper ─────────────────────────────────────
export function applyFilter(results: AnalysisResults, filter: ParsedFilter): AnalysisResults {
  if (!filter.valid || filter.tokens.length === 0) return results;

  const filterArr = <T extends Matchable>(arr: T[] | undefined): T[] | undefined =>
    arr?.filter(item => matchesFilter(item, filter));

  return {
    ...results,
    traffic_analysis: filterArr(results.traffic_analysis),
    tcp_retransmissions: filterArr(results.tcp_retransmissions),
    failed_handshakes: filterArr(results.failed_handshakes),
    rtt_analysis: filterArr(results.rtt_analysis),
    timeline: results.timeline?.filter(ev => matchesFilter({
      source_ip: ev.source_ip,
      dest_ip: ev.dest_ip,
      protocol: ev.protocol,
    }, filter)),
    dns_anomalies: results.dns_anomalies?.filter(d => matchesFilter({
      source_ip: d.server_ip,
      query: d.query,
    }, filter)),
    dns_tunneling_findings: results.dns_tunneling_findings?.filter(d => matchesFilter({
      source_ip: d.source_ip,
      dest_ip: d.server_ip,
      domain: d.domain,
    }, filter)),
    c2_beaconing_findings: results.c2_beaconing_findings?.filter(b => matchesFilter({
      source_ip: b.source_ip,
      dest_ip: b.dest_ip,
      dst_port: b.dest_port,
      protocol: b.protocol,
    }, filter)),
    tcp_window_findings: results.tcp_window_findings?.filter(w => matchesFilter({
      src_ip: w.src_ip,
      dst_ip: w.dst_ip,
      src_port: w.src_port,
      dst_port: w.dst_port,
    }, filter)),
    tcp_out_of_order_flows: filterArr(results.tcp_out_of_order_flows),
    security: results.security ? {
      ...results.security,
      ddos_findings: results.security.ddos_findings?.filter(d => matchesFilter({
        source_ip: d.source_ip,
        dest_ip: d.target_ip,
      }, filter)),
      port_scan_findings: results.security.port_scan_findings?.filter(p => matchesFilter({
        source_ip: p.source_ip,
        dest_ip: p.target_ip,
      }, filter)),
      tls_security_findings: results.security.tls_security_findings?.filter(t => matchesFilter({
        dest_ip: t.server_ip,
        dst_port: t.server_port,
      }, filter)),
    } : undefined,
    bandwidth_report: results.bandwidth_report ? {
      ...results.bandwidth_report,
      top_conversations_by_bytes: results.bandwidth_report.top_conversations_by_bytes?.filter(c => matchesFilter({
        src_ip: c.src_ip,
        dst_ip: c.dst_ip,
        protocol: c.protocol,
      }, filter)),
      top_conversations_by_packets: results.bandwidth_report.top_conversations_by_packets?.filter(c => matchesFilter({
        src_ip: c.src_ip,
        dst_ip: c.dst_ip,
        protocol: c.protocol,
      }, filter)),
    } : undefined,
  };
}

// ─── Context ─────────────────────────────────────────────────────
export interface ForensicFilterContextValue {
  filterText: string;
  parsedFilter: ParsedFilter;
  setFilterText: (text: string) => void;
  filteredResults: AnalysisResults;
  isFiltered: boolean;
  clearFilter: () => void;
}

export const ForensicFilterContext = createContext<ForensicFilterContextValue | null>(null);

export function useForensicFilter(): ForensicFilterContextValue {
  const ctx = useContext(ForensicFilterContext);
  if (!ctx) throw new Error('useForensicFilter must be used within ForensicFilterContext.Provider');
  return ctx;
}
