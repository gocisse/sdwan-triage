import type { ComparisonReport, Discrepancy, FlowComparisonSummary } from '../types';

export function makeDiscrepancy(overrides: Partial<Discrepancy> = {}): Discrepancy {
  return {
    state: 'PRESENT_BOTH',
    src_ip: '192.168.1.10',
    dst_ip: '10.0.0.1',
    src_port: 12345,
    dst_port: 443,
    protocol: 'TCP',
    packet_index: 1,
    timestamp: '2025-06-01T12:00:00Z',
    length: 128,
    detail: 'Matched',
    tcp_flags: 'SYN',
    ...overrides,
  };
}

export function makeFlow(overrides: Partial<FlowComparisonSummary> = {}): FlowComparisonSummary {
  return {
    src_ip: '192.168.1.10',
    dst_ip: '10.0.0.1',
    src_port: 12345,
    dst_port: 443,
    protocol: 'TCP',
    packets_a: 100,
    packets_b: 95,
    matched: 90,
    missing_b: 5,
    missing_a: 0,
    modified: 5,
    match_rate: 0.9,
    has_nat: false,
    encapsulated: false,
    ...overrides,
  };
}

export function makeReport(overrides: Partial<ComparisonReport> = {}): ComparisonReport {
  return {
    file_a: 'lan.pcap',
    file_b: 'wan.pcap',
    total_packets_a: 1000,
    total_packets_b: 950,
    matched_count: 900,
    missing_b_count: 50,
    missing_a_count: 10,
    modified_count: 40,
    verified_encrypted_count: 0,
    ignored_local_count: 0,
    ignored_mgmt_count: 0,
    ignored_routing_count: 0,
    ignored_local_lan_count: 0,
    ignored_control_plane_count: 0,
    policy_drop_count: 5,
    blackhole_count: 2,
    path_integrity_score: 85.0,
    integrity_rating: 'Degraded',
    discrepancies: [
      makeDiscrepancy({ state: 'MISSING_B', detail: 'Dropped by device' }),
      makeDiscrepancy({ state: 'MODIFIED', detail: 'TTL changed: 64 → 63', field_changes: [{ field: 'TTL', value_a: '64', value_b: '63' }] }),
      makeDiscrepancy({ state: 'PRESENT_BOTH' }),
    ],
    flow_summaries: [makeFlow()],
    nat_detected: false,
    ttl_changes: 40,
    dscp_changes: 0,
    tunnel_detected: false,
    encapsulated_count: 0,
    encrypted_count: 0,
    analysis_duration_ms: 250,
    forensics: {
      total_flows_matched: 10,
      flows_dropped_lan_to_wan: 2,
      flows_dropped_wan_to_lan: 1,
      avg_one_way_latency_ms: 5.2,
      min_one_way_latency_ms: 0.3,
      max_one_way_latency_ms: 45.0,
      p95_one_way_latency_ms: 20.0,
      latency_sample_count: 50,
      total_retransmissions_dropped: 12,
    },
    ...overrides,
  };
}
