// applyTimeFilter — Produces a time-filtered copy of AnalysisResults
// by filtering sub-arrays that have timestamp fields.

import type { AnalysisResults, TimelineEvent } from '../types';
import type { TimeRange } from '../contexts/TimeRangeContext';

/**
 * Filter AnalysisResults to only include data within the given time range.
 * Returns a shallow copy with filtered arrays; arrays without timestamps are passed through.
 */
export function applyTimeFilter(results: AnalysisResults, range: TimeRange): AnalysisResults {
  const { start, end } = range;

  // Helper: check if an ISO timestamp string falls within range
  const inRange = (ts: string | undefined | null): boolean => {
    if (!ts) return true; // no timestamp = include
    const epoch = new Date(ts).getTime() / 1000;
    if (!epoch || !isFinite(epoch)) return true;
    return epoch >= start && epoch <= end;
  };

  // Helper: check if a numeric timestamp (seconds) falls within range
  const inRangeNum = (epoch: number | undefined | null): boolean => {
    if (!epoch || !isFinite(epoch)) return true;
    return epoch >= start && epoch <= end;
  };

  return {
    ...results,

    // Timeline events (ISO string timestamp)
    timeline: results.timeline?.filter((ev: TimelineEvent) => inRange(ev.timestamp)),

    // TCP retransmissions / failed handshakes — no direct timestamp, pass through
    // Security findings — nested, pass through (most are aggregate)

    // DNS anomalies have timestamp field
    dns_anomalies: results.dns_anomalies?.filter((a) => inRange((a as any).timestamp)),

    // TLS certs may have numeric timestamp from backend
    tls_certs: results.tls_certs?.filter((c) => inRangeNum((c as any).timestamp)),

    // DHCP findings
    dhcp_findings: results.dhcp_findings?.filter((f) => inRange((f as any).timestamp)),

    // NTP findings
    ntp_findings: results.ntp_findings?.filter((f) => inRange((f as any).timestamp)),

    // DNS tunneling
    dns_tunneling_findings: results.dns_tunneling_findings?.filter((f) => inRange((f as any).timestamp)),

    // C2 beaconing
    c2_beaconing_findings: results.c2_beaconing_findings?.filter((f) => inRange((f as any).first_seen)),

    // ICMP
    icmp_analysis: results.icmp_analysis?.filter((f) => inRange((f as any).timestamp)),

    // Stability findings
    stability_findings: results.stability_findings?.filter((f) => inRange((f as any).timestamp)),
  };
}
