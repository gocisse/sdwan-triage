// TypeScript interfaces matching backend data models exactly

// Analysis job status enum
export type AnalysisStatus = 
  | 'pending'
  | 'uploading'
  | 'analyzing'
  | 'completed'
  | 'failed'
  | 'cancelled';

// Analysis job interface - matches backend storage.AnalysisJob
export interface AnalysisJob {
  id: string;
  file_name: string;
  file_size: number;
  file_path: string;
  status: AnalysisStatus;
  progress: number;
  current_step: string;
  estimated_time: number; // seconds remaining
  created_at: string;
  updated_at: string;
  completed_at?: string;
  error?: string;
  results_path?: string;
  html_path?: string;
}

// Upload response
export interface UploadResponse {
  id: string;
  file_name: string;
  file_size: number;
  status: string;
  message: string;
}

// Health check response
export interface HealthResponse {
  status: string;
  timestamp: string;
  version: string;
}

// System status response
export interface SystemStatus {
  status: string;
  version: string;
  uptime: string;
  platform: string;
  go_version: string;
  num_goroutine: number;
  memory_mb: number;
}

// History list response
export interface HistoryResponse {
  items: AnalysisJob[];
  total: number;
  limit: number;
  offset: number;
}

// Analysis results - matches the WebResultsWrapper + TriageReport structure
export interface AnalysisResults {
  // Metadata from WebResultsWrapper
  file_name: string;
  file_size: string;
  packet_count: number;
  duration: string;
  generated_at: string;
  capture_format?: string; // "pcap" or "pcapng"
  
  // Risk assessment
  risk_score?: number;
  risk_level?: string;
  top_issue?: string;
  recommended_actions?: string[];
  
  // Security findings (nested in security object)
  security?: SecurityAnalysis;
  
  // DNS anomalies (top-level)
  dns_anomalies?: DNSAnomaly[];
  
  // ARP conflicts (top-level)
  arp_conflicts?: ARPConflict[];
  
  // Performance - TCP handshakes
  tcp_handshakes?: TCPHandshakeStats;
  tcp_retransmissions?: TCPFlow[];
  failed_handshakes?: TCPFlow[];
  
  // Packet loss
  packet_loss?: PacketLossStats;
  
  // Traffic analysis
  traffic_analysis?: TrafficFlow[];
  rtt_analysis?: RTTFlow[];
  total_bytes?: number;
  
  // LAN Protocols
  lan_protocols?: LANProtocols;
  
  // SD-WAN
  sdwan_vendors?: SDWANVendor[];
  tunnel_analysis?: TunnelFinding[];
  
  // Timeline
  timeline?: TimelineEvent[];
  
  // Devices
  device_fingerprinting?: DeviceFingerprint[];
  
  // TLS
  tls_certs?: TLSCertInfo[];
  
  // Bandwidth
  bandwidth_report?: BandwidthReport;

  // DHCP findings
  dhcp_findings?: DHCPFinding[];

  // NTP findings
  ntp_findings?: NTPFinding[];

  // DNS Tunneling findings
  dns_tunneling_findings?: DNSTunnelingFinding[];

  // C2 Beaconing findings
  c2_beaconing_findings?: C2BeaconingFinding[];

  // TCP Advanced findings
  tcp_window_findings?: TCPWindowFinding[];
  tcp_out_of_order_flows?: TCPOutOfOrderFlow[];

  // Interface Stability / Flapping Detection
  stability_findings?: StabilityFinding[];

  // VoIP
  voip_analysis?: VoIPAnalysis;

  // ICMP
  icmp_analysis?: ICMPFinding[];

  // Plain English Summary
  plain_english_summary?: PlainEnglishSummary;

  // QoS Analysis
  qos_analysis?: QoSReport;
}

// Security analysis container
export interface SecurityAnalysis {
  ddos_findings?: DDoSFinding[];
  port_scan_findings?: PortScanFinding[];
  ioc_findings?: IOCFinding[];
  tls_security_findings?: TLSSecurityFinding[];
}

// DDoS finding from backend
export interface DDoSFinding {
  timestamp: number;
  source_ip: string;
  target_ip?: string;
  type: string;
  packet_count: number;
  threshold: number;
  duration_seconds: number;
  severity: string;
}

// Port scan finding
export interface PortScanFinding {
  timestamp: number;
  source_ip: string;
  target_ip?: string;
  type: string;
  ports_scanned: number;
  sample_ports?: number[];
  severity: string;
}

// IOC finding
export interface IOCFinding {
  timestamp: number;
  matched_value: string;
  type: string;
  ioc_type: string;
  source_ip?: string;
  dest_ip?: string;
  confidence: string;
  description: string;
}

// TLS security finding
export interface TLSSecurityFinding {
  timestamp: number;
  server_ip: string;
  server_port: number;
  tls_version: string;
  cipher_suite?: string;
  weakness_type: string;
  description: string;
  severity: string;
}

// TCP flow
export interface TCPFlow {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  retransmissions?: number;
  rtt_ms?: number;
}

// RTT Flow analysis
export interface RTTFlow {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  min_rtt_ms: number;
  max_rtt_ms: number;
  avg_rtt_ms: number;
  sample_size: number;
}

// Traffic flow
export interface TrafficFlow {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  total_bytes: number;
  percentage: number;
}

// TLS certificate info
export interface TLSCertInfo {
  server_ip: string;
  server_port: number;
  server_name?: string;
  version: string;
  cipher_suite: string;
  subject?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  is_expired?: boolean;
  is_self_signed?: boolean;
}

// Bandwidth report
export interface BandwidthReport {
  top_conversations_by_bytes?: TrafficFlowSummary[];
  top_conversations_by_packets?: TrafficFlowSummary[];
}

// Traffic flow summary
export interface TrafficFlowSummary {
  src_ip: string;
  dst_ip: string;
  protocol: string;
  bytes: number;
  packets: number;
}

export interface AnalysisStats {
  total_packets: number;
  total_bytes: number;
  total_traffic: string;
  dns_queries: number;
  dns_anomalies: number;
  tls_certs: number;
  tls_weaknesses: number;
  ddos_attacks: number;
  suspicious_traffic: number;
  failed_handshakes: number;
  retransmissions: number;
  devices_detected: number;
}

export interface DDoSAttack {
  type: string;
  source_ip: string;
  target_ip: string;
  packet_count: number;
  severity: string;
  first_seen: string;
  last_seen: string;
}

export interface DNSAnomaly {
  timestamp: number;
  query: string;
  answer_ip?: string;
  server_ip: string;
  server_mac?: string;
  reason: string;
}

export interface TLSFinding {
  server_ip: string;
  server_name: string;
  version: string;
  cipher_suite: string;
  has_weaknesses: boolean;
  weaknesses: string[];
  certificate?: TLSCertificate;
}

export interface TLSCertificate {
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  is_expired: boolean;
  is_self_signed: boolean;
}

export interface ARPConflict {
  ip_address: string;
  mac_addresses: string[];
  first_seen: string;
  last_seen: string;
}

export interface TCPHandshakeStats {
  syn_flows?: TCPHandshakeFlow[];
  synack_flows?: TCPHandshakeFlow[];
  successful_handshakes?: TCPHandshakeFlow[];
  failed_handshake_attempts?: TCPHandshakeFlow[];
}

export interface TCPHandshakeFlow {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  timestamp: number;
  count: number;
  state: string;
}

export interface RetransmissionStats {
  total: number;
  rate: number;
}

export interface PacketLossStats {
  total_packets_sent: number;
  total_packets_received: number;
  packets_lost: number;
  loss_percentage: number;
  retransmission_rate: number;
  out_of_order_packets: number;
  duplicate_packets: number;
  per_flow_loss?: FlowPacketLoss[];
}

export interface FlowPacketLoss {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packets_sent: number;
  packets_lost: number;
  loss_percentage: number;
}

export interface ProtocolStat {
  protocol: string;
  count: number;
  bytes: number;
  percent: number;
  color: string;
}

// LAN Protocol types
export interface LANProtocols {
  vrrp_sessions?: VRRPSession[];
  cdp_devices?: CDPDevice[];
  lldp_devices?: LLDPDevice[];
  hsrp_groups?: HSRPGroup[];
  stp_bridges?: STPBridge[];
}

export interface VRRPSession {
  virtual_router_id: number;
  priority: number;
  state: string;
  master_ip: string;
  virtual_ips: string[];
  advert_interval: number;
  first_seen: string;
  last_seen: string;
  packet_count: number;
  transition_count: number;
  is_flapping: boolean;
  flapping_reason?: string;
}

export interface CDPDevice {
  device_id: string;
  ip_address: string;
  platform: string;
  capabilities: string;
  software_version: string;
  port_id: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
}

export interface LLDPDevice {
  chassis_id: string;
  port_id: string;
  system_name: string;
  system_desc: string;
  capabilities: string;
  management_ip: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
}

export interface HSRPGroup {
  group_number: number;
  state: string;
  priority: number;
  virtual_ip: string;
  active_router: string;
  standby_router: string;
  first_seen: string;
  last_seen: string;
  packet_count: number;
}

export interface STPBridge {
  bridge_id: string;
  root_bridge_id: string;
  root_cost: number;
  port_id: number;
  first_seen: string;
  last_seen: string;
  packet_count: number;
}

export interface SDWANVendor {
  name: string;
  confidence: string;
  detected_by: string;
  packet_count?: number;
  first_seen?: number;
  last_seen?: number;
}

export interface TunnelFinding {
  type: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  packet_count: number;
  byte_count?: number;
  first_seen: string;
  last_seen: string;
  detection_method?: string;
  confidence?: string;
  protocol_version?: string;
  session_state?: string;
  is_authorized?: boolean;
  sdwan_path?: string;
}

export interface TimelineEvent {
  timestamp: string;
  event_type: string;
  protocol: string;
  severity: string;
  description: string;
  source_ip?: string;
  dest_ip?: string;
}

export interface TopFlow {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  bytes: number;
  packets: number;
  percent: number;
}

export interface DeviceFingerprint {
  ip: string;
  mac?: string;
  os_type: string;
  os_name: string;
  confidence: string;
}

export interface GeoLocation {
  country: string;
  country_code: string;
  ip_count: number;
  bytes: number;
  percent: number;
}

// DHCP finding
export interface DHCPFinding {
  timestamp: number;
  type: string;
  server_ip?: string;
  client_mac?: string;
  offered_ip?: string;
  severity: string;
  description: string;
  packet_count: number;
  server_mac?: string;
  known_servers?: string[];
}

// NTP finding
export interface NTPFinding {
  timestamp: number;
  type: string;
  source_ip: string;
  dest_ip?: string;
  stratum?: number;
  severity: string;
  description: string;
  packet_count: number;
  response_size?: number;
}

// DNS Tunneling finding
export interface DNSTunnelingFinding {
  timestamp: number;
  source_ip: string;
  server_ip: string;
  domain: string;
  severity: string;
  description: string;
  avg_query_length: number;
  query_count: number;
  unique_subdomains: number;
  entropy_score: number;
  sample_queries?: string[];
}

// C2 Beaconing finding
export interface C2BeaconingFinding {
  timestamp: number;
  source_ip: string;
  dest_ip: string;
  dest_port: number;
  protocol: string;
  severity: string;
  description: string;
  beacon_interval_sec: number;
  interval_jitter_pct: number;
  connection_count: number;
  avg_payload_size: number;
  payload_variance: number;
  confidence: string;
}

// TCP Window finding
export interface TCPWindowFinding {
  timestamp: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  type: string;
  window_size: number;
  severity: string;
  description: string;
  count: number;
}

// TCP Out-of-Order flow
export interface TCPOutOfOrderFlow {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  out_of_order_count: number;
  total_packets: number;
  percentage: number;
  severity: string;
}

// VoIP Analysis
export interface VoIPAnalysis {
  sip_calls?: SIPCallInfo[];
  rtp_streams?: RTPStreamInfo[];
  total_calls: number;
  established_calls: number;
  failed_calls: number;
  total_rtp_streams: number;
  avg_jitter_ms: number;
  packet_loss_rate: number;
}

export interface SIPCallInfo {
  call_id: string;
  from_uri: string;
  to_uri: string;
  state: string;
  start_time: number;
  end_time?: number;
  src_ip: string;
  dst_ip: string;
}

export interface RTPStreamInfo {
  ssrc: number;
  src_ip: string;
  dst_ip: string;
  payload_type: string;
  packet_count: number;
  byte_count: number;
  lost_packets: number;
  jitter_ms: number;
}

// ICMP finding
export interface ICMPFinding {
  timestamp: number;
  source_ip: string;
  dest_ip: string;
  icmp_type: number;
  icmp_code: number;
  type_name: string;
  count: number;
  is_anomaly: boolean;
  description?: string;
}

// Plain English Summary
export interface PlainEnglishSummary {
  overall_health: string;
  health_icon: string;
  health_color: string;
  key_findings: string[];
  quick_actions: string[];
  traffic_gaps: string[];
  performance_issues: string[];
  security_alerts: string[];
}

// API Error response
export interface APIError {
  error: string;
  details?: string;
}

// WebSocket message types
export interface WSMessage {
  type: 'progress' | 'complete' | 'error';
  data: AnalysisJob;
}

// ============ Packet Inspection Types ============

// Raw packet for inspection
export interface RawPacket {
  index: number;
  timestamp: string;
  length: number;
  cap_len: number;
  raw_hex: string;
  stream_id: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  is_tcp: boolean;
  is_udp: boolean;
  is_icmp: boolean;
  is_tls: boolean;
  is_http: boolean;
  is_dns: boolean;
  has_payload: boolean;
  link_layer?: LayerInfo;
  network_layer?: LayerInfo;
  transport_layer?: LayerInfo;
  application_layer?: LayerInfo;
}

// Layer info for protocol tree
export interface LayerInfo {
  name: string;
  protocol?: string;
  src?: string;
  dst?: string;
  length: number;
  flags?: Record<string, string>;
  fields?: Record<string, string>;
  summary: string;
  raw_hex?: string;
  payload_hex?: string;
}

// Stream response from API
export interface StreamResponse {
  stream_id: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  application: string;
  packet_count: number;
  total_bytes: number;
  client_data: StreamSegmentView[];
  server_data: StreamSegmentView[];
  packets: PacketSummary[];
  wireshark_filter: string;
}

// Stream segment view
export interface StreamSegmentView {
  packet_index: number;
  timestamp: string;
  length: number;
  data_hex?: string;
  data_ascii?: string;
  summary: string;
}

// Packet summary for list view
export interface PacketSummary {
  index: number;
  timestamp: string;
  length: number;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  summary: string;
}

// Packet detail response
export interface PacketDetailResponse {
  index: number;
  timestamp: string;
  length: number;
  cap_len: number;
  raw_hex: string;
  raw_ascii: string;
  stream_id: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  layers: LayerDetailView[];
  wireshark_filter: string;
}

// Layer detail for packet view
export interface LayerDetailView {
  name: string;
  summary: string;
  fields?: Record<string, string>;
  flags?: Record<string, string>;
  raw_hex?: string;
  payload_hex?: string;
}

// Stream info for list
export interface StreamInfo {
  stream_id: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  application: string;
  packet_count: number;
  total_bytes: number;
}

// Packets list response
export interface PacketsListResponse {
  packets: PacketSummary[];
  total: number;
  offset: number;
  limit: number;
}

// Streams list response
export interface StreamsListResponse {
  streams: StreamInfo[];
  total: number;
}

// ─── PCAP Comparison Types ──────────────────────────────────────

export interface ComparisonReport {
  file_a: string;
  file_b: string;
  total_packets_a: number;
  total_packets_b: number;
  matched_count: number;
  missing_b_count: number;
  missing_a_count: number;
  modified_count: number;
  path_integrity_score: number;
  integrity_rating: string; // "Healthy" | "Degraded" | "Warning" | "Critical"
  discrepancies: Discrepancy[];
  flow_summaries: FlowComparisonSummary[];
  nat_detected: boolean;
  ttl_changes: number;
  dscp_changes: number;
  tunnel_detected: boolean;
  tunnel_types?: string[];
  encapsulated_count: number;
  encrypted_count: number;
  tunnel_breakdown?: Record<string, number>;
  analysis_duration_ms: number;
}

export interface Discrepancy {
  state: 'MISSING_B' | 'MISSING_A' | 'MODIFIED' | 'PRESENT_BOTH';
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_index: number;
  timestamp: string;
  length: number;
  detail: string;
  tcp_flags?: string;
  tunnel_type?: string;
  encrypted?: boolean;
  field_changes?: FieldChange[];
}

export interface FieldChange {
  field: string;
  value_a: string;
  value_b: string;
}

export interface FlowComparisonSummary {
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packets_a: number;
  packets_b: number;
  matched: number;
  missing_b: number;
  missing_a: number;
  modified: number;
  match_rate: number;
  has_nat: boolean;
  tunnel_type?: string;
  encapsulated: boolean;
}

// ─── QoS / DSCP Analysis Types ──────────────────────────────────

export interface QoSReport {
  class_distribution?: Record<string, QoSClassMetrics>;
  total_packets: number;
  mismatched_qos?: QoSMismatch[];
}

export interface QoSClassMetrics {
  class_name: string;
  dscp_value: number;
  packet_count: number;
  byte_count: number;
  percentage: number;
  avg_rtt_ms?: number;
  retransmit_count: number;
  retransmit_rate_percent: number;
}

export interface QoSMismatch {
  flow: string;
  expected_class: string;
  actual_class: string;
  reason: string;
}

// ─── Latency Matrix Types ────────────────────────────────────────

export interface LatencyMatrix {
  subnets: string[];
  cells: Record<string, CellStat>;
  total_flows: number;
  max_rtt_ms: number;
  max_loss_pct: number;
}

export interface CellStat {
  src_subnet: string;
  dst_subnet: string;
  avg_rtt_ms: number;
  min_rtt_ms: number;
  max_rtt_ms: number;
  loss_pct: number;
  flow_count: number;
  total_bytes?: number;
}

// ─── Interface Stability / Flapping Types ─────────────────────────

export interface StabilityFinding {
  type: string;             // "BFD Flapping", "IKE Tunnel Rebuild", "HSRP Flapping", "VRRP Flapping", "STP TCN Storm"
  severity: string;         // "Critical", "High", "Warning"
  identifier: string;       // IP pair, group ID, or bridge ID
  description: string;
  state_changes: number;
  window_seconds: number;
  first_seen: string;
  last_seen: string;
  source_ip?: string;
  peer_ip?: string;
  protocol: string;         // "BFD", "IKE", "HSRP", "VRRP", "STP"
  root_cause_hint: string;
}
