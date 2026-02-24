// Guided Investigation Wizard - Symptom-to-Finding mapping
// Maps user-reported symptoms to relevant finding categories and prioritized troubleshooting steps

import type { AnalysisResults } from '../types';

export interface WizardSymptom {
  id: string;
  label: string;
  icon: string;
  description: string;
  followUpQuestions: WizardFollowUp[];
  relatedFindings: string[];
  priorityOrder: string[];
}

export interface WizardFollowUp {
  id: string;
  question: string;
  options: { label: string; value: string; narrowsTo: string[] }[];
}

export interface WizardResult {
  findingKey: string;
  label: string;
  isRootCause: boolean;
  confidence: 'high' | 'medium' | 'low';
  explanation: string;
  steps: WizardStep[];
}

export interface WizardStep {
  order: number;
  action: string;
  command?: string;
  expectedResult?: string;
  ifFails?: string;
}

export const wizardSymptoms: WizardSymptom[] = [
  {
    id: 'slow_apps',
    label: 'Users reporting slow applications',
    icon: '🐌',
    description: 'Applications are loading slowly, timing out, or feeling sluggish',
    followUpQuestions: [
      {
        id: 'slow_scope',
        question: 'Which applications are affected?',
        options: [
          { label: 'All applications', value: 'all_apps', narrowsTo: ['tcp_retransmission', 'packet_loss', 'high_latency', 'tcp_zero_window', 'tunnel_flapping'] },
          { label: 'Web/cloud apps only', value: 'web_apps', narrowsTo: ['tcp_retransmission', 'high_latency', 'dns_anomaly', 'http_errors', 'tls_weakness'] },
          { label: 'Internal apps only', value: 'internal_apps', narrowsTo: ['tcp_retransmission', 'vrrp_flapping', 'hsrp_instability', 'arp_conflict', 'tcp_zero_window'] },
          { label: 'Not sure', value: 'unknown', narrowsTo: ['tcp_retransmission', 'packet_loss', 'high_latency', 'dns_anomaly', 'tcp_zero_window'] },
        ],
      },
      {
        id: 'slow_timing',
        question: 'When did it start?',
        options: [
          { label: 'Sudden onset', value: 'sudden', narrowsTo: ['tunnel_flapping', 'vrrp_flapping', 'ddos_syn_flood', 'packet_loss'] },
          { label: 'Gradual degradation', value: 'gradual', narrowsTo: ['tcp_retransmission', 'high_latency', 'tcp_small_window', 'tcp_out_of_order'] },
          { label: 'Intermittent', value: 'intermittent', narrowsTo: ['tunnel_flapping', 'vrrp_flapping', 'hsrp_instability', 'packet_loss'] },
          { label: 'Not sure', value: 'unknown', narrowsTo: [] },
        ],
      },
    ],
    relatedFindings: ['tcp_retransmission', 'packet_loss', 'high_latency', 'tcp_zero_window', 'tcp_small_window', 'tcp_out_of_order', 'tunnel_flapping', 'dns_anomaly'],
    priorityOrder: ['packet_loss', 'tcp_retransmission', 'high_latency', 'tunnel_flapping', 'tcp_zero_window', 'dns_anomaly'],
  },
  {
    id: 'voice_drops',
    label: 'Voice calls dropping or poor quality',
    icon: '📞',
    description: 'VoIP calls have choppy audio, one-way audio, or disconnect unexpectedly',
    followUpQuestions: [
      {
        id: 'voice_type',
        question: 'What kind of voice issue?',
        options: [
          { label: 'Choppy/robotic audio', value: 'choppy', narrowsTo: ['voip_quality', 'voip_jitter', 'packet_loss', 'tcp_out_of_order'] },
          { label: 'Calls dropping mid-conversation', value: 'dropping', narrowsTo: ['tunnel_flapping', 'vrrp_flapping', 'packet_loss'] },
          { label: 'One-way audio', value: 'one_way', narrowsTo: ['arp_conflict', 'tunnel_flapping', 'voip_quality'] },
          { label: 'Cannot make calls at all', value: 'no_calls', narrowsTo: ['dns_anomaly', 'tcp_handshake_failure', 'tunnel_flapping'] },
        ],
      },
    ],
    relatedFindings: ['voip_quality', 'voip_jitter', 'packet_loss', 'high_latency', 'tunnel_flapping', 'vrrp_flapping', 'tcp_out_of_order'],
    priorityOrder: ['voip_jitter', 'voip_quality', 'packet_loss', 'high_latency', 'tunnel_flapping'],
  },
  {
    id: 'sites_offline',
    label: 'Sites going offline intermittently',
    icon: '🔌',
    description: 'Branch offices or remote sites lose connectivity periodically',
    followUpQuestions: [
      {
        id: 'offline_pattern',
        question: 'How often does it happen?',
        options: [
          { label: 'Every few minutes', value: 'frequent', narrowsTo: ['tunnel_flapping', 'vrrp_flapping', 'hsrp_instability'] },
          { label: 'A few times per day', value: 'daily', narrowsTo: ['tunnel_flapping', 'packet_loss', 'high_latency'] },
          { label: 'Random/unpredictable', value: 'random', narrowsTo: ['tunnel_flapping', 'vrrp_flapping', 'arp_conflict', 'stp_topology'] },
          { label: 'Currently offline', value: 'now', narrowsTo: ['tunnel_flapping', 'tcp_handshake_failure', 'dns_anomaly'] },
        ],
      },
      {
        id: 'offline_scope',
        question: 'How many sites are affected?',
        options: [
          { label: 'One site', value: 'one', narrowsTo: ['tunnel_flapping', 'packet_loss'] },
          { label: 'Multiple sites', value: 'multiple', narrowsTo: ['vrrp_flapping', 'hsrp_instability', 'dns_anomaly'] },
          { label: 'All sites', value: 'all', narrowsTo: ['ddos_syn_flood', 'ddos_udp_flood', 'dns_anomaly'] },
          { label: 'Not sure', value: 'unknown', narrowsTo: [] },
        ],
      },
    ],
    relatedFindings: ['tunnel_flapping', 'vrrp_flapping', 'hsrp_instability', 'packet_loss', 'arp_conflict', 'stp_topology'],
    priorityOrder: ['tunnel_flapping', 'vrrp_flapping', 'hsrp_instability', 'packet_loss', 'arp_conflict'],
  },
  {
    id: 'security_alert',
    label: 'Security alert triggered',
    icon: '🔒',
    description: 'Security tools flagged suspicious activity or you suspect a breach',
    followUpQuestions: [
      {
        id: 'security_type',
        question: 'What type of alert?',
        options: [
          { label: 'Possible attack/DDoS', value: 'attack', narrowsTo: ['ddos_syn_flood', 'ddos_udp_flood', 'ddos_icmp_flood', 'port_scan'] },
          { label: 'Suspicious outbound traffic', value: 'outbound', narrowsTo: ['c2_beaconing', 'dns_tunneling', 'ioc_match'] },
          { label: 'Unauthorized device/server', value: 'unauthorized', narrowsTo: ['dhcp_rogue_server', 'arp_conflict', 'port_scan'] },
          { label: 'Certificate/encryption issue', value: 'crypto', narrowsTo: ['tls_weakness', 'tls_certificate_issue'] },
        ],
      },
    ],
    relatedFindings: ['ddos_syn_flood', 'ddos_udp_flood', 'port_scan', 'c2_beaconing', 'dns_tunneling', 'ioc_match', 'dhcp_rogue_server', 'tls_weakness'],
    priorityOrder: ['c2_beaconing', 'dns_tunneling', 'ioc_match', 'ddos_syn_flood', 'port_scan', 'dhcp_rogue_server'],
  },
  {
    id: 'show_everything',
    label: "I don't know, show me everything",
    icon: '🔍',
    description: 'Show all findings prioritized by severity',
    followUpQuestions: [],
    relatedFindings: [],
    priorityOrder: [],
  },
];

// Map finding keys to what they check in AnalysisResults
export function getActiveFindings(results: AnalysisResults): Map<string, { count: number; severity: string; label: string }> {
  const active = new Map<string, { count: number; severity: string; label: string }>();

  const ddos = results.security?.ddos_findings || [];
  const synFloods = ddos.filter(d => d.type === 'SYN Flood');
  const udpFloods = ddos.filter(d => d.type === 'UDP Flood');
  const icmpFloods = ddos.filter(d => d.type === 'ICMP Flood');
  if (synFloods.length > 0) active.set('ddos_syn_flood', { count: synFloods.length, severity: 'Critical', label: 'SYN Flood Attack' });
  if (udpFloods.length > 0) active.set('ddos_udp_flood', { count: udpFloods.length, severity: 'Critical', label: 'UDP Flood Attack' });
  if (icmpFloods.length > 0) active.set('ddos_icmp_flood', { count: icmpFloods.length, severity: 'Warning', label: 'ICMP Flood' });

  const portScans = results.security?.port_scan_findings || [];
  if (portScans.length > 0) active.set('port_scan', { count: portScans.length, severity: 'Warning', label: 'Port Scanning' });

  const tls = results.security?.tls_security_findings || [];
  if (tls.length > 0) active.set('tls_weakness', { count: tls.length, severity: 'Warning', label: 'TLS Weaknesses' });

  const ioc = results.security?.ioc_findings || [];
  if (ioc.length > 0) active.set('ioc_match', { count: ioc.length, severity: 'Critical', label: 'IOC Matches' });

  const dns = results.dns_anomalies || [];
  if (dns.length > 0) active.set('dns_anomaly', { count: dns.length, severity: 'Warning', label: 'DNS Anomalies' });

  const arp = results.arp_conflicts || [];
  if (arp.length > 0) active.set('arp_conflict', { count: arp.length, severity: 'Warning', label: 'ARP Conflicts' });

  const retrans = results.tcp_retransmissions || [];
  if (retrans.length > 0) active.set('tcp_retransmission', { count: retrans.length, severity: retrans.length > 500 ? 'Critical' : 'Warning', label: 'TCP Retransmissions' });

  const failedH = results.tcp_handshakes?.failed_handshake_attempts || [];
  if (failedH.length > 0) active.set('tcp_handshake_failure', { count: failedH.length, severity: 'Warning', label: 'TCP Handshake Failures' });

  const loss = results.packet_loss;
  if (loss && loss.packets_lost > 0) active.set('packet_loss', { count: loss.packets_lost, severity: loss.loss_percentage > 5 ? 'Critical' : 'Warning', label: 'Packet Loss' });

  const vrrp = results.lan_protocols?.vrrp_sessions?.filter(s => s.is_flapping) || [];
  if (vrrp.length > 0) active.set('vrrp_flapping', { count: vrrp.length, severity: 'Critical', label: 'VRRP Flapping' });

  const hsrp = results.lan_protocols?.hsrp_groups || [];
  if (hsrp.length > 0) active.set('hsrp_instability', { count: hsrp.length, severity: 'Warning', label: 'HSRP State Changes' });

  const stp = results.lan_protocols?.stp_bridges || [];
  if (stp.length > 0) active.set('stp_topology', { count: stp.length, severity: 'Info', label: 'STP Topology' });

  const tunnels = results.tunnel_analysis || [];
  if (tunnels.length > 0) active.set('tunnel_flapping', { count: tunnels.length, severity: 'Critical', label: 'Tunnel Issues' });

  const dhcp = results.dhcp_findings || [];
  if (dhcp.length > 0) {
    const hasRogue = dhcp.some(d => d.type === 'Rogue Server');
    active.set(hasRogue ? 'dhcp_rogue_server' : 'dhcp_nak_storm', { count: dhcp.length, severity: 'Critical', label: 'DHCP Issues' });
  }

  const ntp = results.ntp_findings || [];
  if (ntp.length > 0) {
    const hasAmp = ntp.some(d => d.type === 'Amplification');
    active.set(hasAmp ? 'ntp_amplification' : 'ntp_stratum_change', { count: ntp.length, severity: hasAmp ? 'Critical' : 'Warning', label: 'NTP Issues' });
  }

  const dnsTunnel = results.dns_tunneling_findings || [];
  if (dnsTunnel.length > 0) active.set('dns_tunneling', { count: dnsTunnel.length, severity: 'Critical', label: 'DNS Tunneling' });

  const c2 = results.c2_beaconing_findings || [];
  if (c2.length > 0) active.set('c2_beaconing', { count: c2.length, severity: 'Critical', label: 'C2 Beaconing' });

  const tcpWin = results.tcp_window_findings || [];
  const zeroWin = tcpWin.filter(w => w.type === 'Zero Window');
  const smallWin = tcpWin.filter(w => w.type === 'Small Window');
  if (zeroWin.length > 0) active.set('tcp_zero_window', { count: zeroWin.length, severity: 'Critical', label: 'TCP Zero Window' });
  if (smallWin.length > 0) active.set('tcp_small_window', { count: smallWin.length, severity: 'Warning', label: 'TCP Small Window' });

  const tcpOoo = results.tcp_out_of_order_flows || [];
  if (tcpOoo.length > 0) active.set('tcp_out_of_order', { count: tcpOoo.length, severity: 'Warning', label: 'TCP Out-of-Order' });

  const voip = results.voip_analysis;
  if (voip && voip.avg_jitter_ms > 30) active.set('voip_jitter', { count: voip.total_rtp_streams, severity: 'Warning', label: 'VoIP Jitter' });
  if (voip && voip.failed_calls > 0) active.set('voip_quality', { count: voip.failed_calls, severity: 'Critical', label: 'VoIP Quality Issues' });

  const http = results.traffic_analysis?.filter(t => t.protocol === 'HTTP') || [];
  if (http.length > 0) active.set('http_errors', { count: http.length, severity: 'Warning', label: 'HTTP Errors' });

  return active;
}

// Determine which wizard results to show based on symptom + follow-up answers
export function computeWizardResults(
  symptom: WizardSymptom,
  answers: Record<string, string>,
  activeFindings: Map<string, { count: number; severity: string; label: string }>
): WizardResult[] {
  // If "show everything", return all active findings sorted by severity
  if (symptom.id === 'show_everything') {
    const sevOrder: Record<string, number> = { Critical: 0, Warning: 1, Info: 2 };
    return Array.from(activeFindings.entries())
      .sort((a, b) => (sevOrder[a[1].severity] ?? 3) - (sevOrder[b[1].severity] ?? 3))
      .map(([key, info], i) => ({
        findingKey: key,
        label: info.label,
        isRootCause: i === 0,
        confidence: info.severity === 'Critical' ? 'high' as const : 'medium' as const,
        explanation: `${info.count} ${info.label.toLowerCase()} detected in this capture.`,
        steps: [],
      }));
  }

  // Collect all narrowed finding keys from follow-up answers
  let narrowedKeys = new Set<string>(symptom.relatedFindings);

  for (const fq of symptom.followUpQuestions) {
    const answer = answers[fq.id];
    if (answer) {
      const option = fq.options.find(o => o.value === answer);
      if (option && option.narrowsTo.length > 0) {
        narrowedKeys = new Set([...narrowedKeys].filter(k => option.narrowsTo.includes(k)));
      }
    }
  }

  // Filter to only findings that are actually present in the results
  const matchedFindings = [...narrowedKeys].filter(k => activeFindings.has(k));

  // Sort by priority order from symptom, then by severity
  const priorityMap = new Map(symptom.priorityOrder.map((k, i) => [k, i]));
  const sevOrder: Record<string, number> = { Critical: 0, Warning: 1, Info: 2 };

  matchedFindings.sort((a, b) => {
    const pa = priorityMap.get(a) ?? 999;
    const pb = priorityMap.get(b) ?? 999;
    if (pa !== pb) return pa - pb;
    const sa = sevOrder[activeFindings.get(a)!.severity] ?? 3;
    const sb = sevOrder[activeFindings.get(b)!.severity] ?? 3;
    return sa - sb;
  });

  return matchedFindings.map((key, i) => {
    const info = activeFindings.get(key)!;
    return {
      findingKey: key,
      label: info.label,
      isRootCause: i === 0,
      confidence: i === 0 ? 'high' as const : i < 3 ? 'medium' as const : 'low' as const,
      explanation: i === 0
        ? `This is the most likely root cause based on your symptoms. ${info.count} ${info.label.toLowerCase()} detected.`
        : `${info.count} ${info.label.toLowerCase()} detected — may be contributing to the issue.`,
      steps: [],
    };
  });
}
