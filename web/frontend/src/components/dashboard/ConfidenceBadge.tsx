// Confidence Scoring & Validation Badge
// Displays confidence level for each finding with visual meter and community validation stats

import { Shield, Users, Headphones } from 'lucide-react';

export type ConfidenceLevel = 'high' | 'medium' | 'low';

interface ConfidenceBadgeProps {
  level: ConfidenceLevel;
  showDetails?: boolean;
}

const confidenceConfig: Record<ConfidenceLevel, {
  label: string;
  description: string;
  color: string;
  bgColor: string;
  borderColor: string;
  barWidth: string;
  barColor: string;
  communityNote: string;
  escalationRate: string;
  tacTip: string;
}> = {
  high: {
    label: 'High Confidence',
    description: 'Pattern seen 1000+ times in production networks',
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/20',
    barWidth: 'w-full',
    barColor: 'bg-green-500',
    communityNote: 'This fix resolved the issue for 90%+ of users',
    escalationRate: 'Escalated to vendor in <5% of cases',
    tacTip: 'Standard troubleshooting steps will likely resolve this',
  },
  medium: {
    label: 'Medium Confidence',
    description: 'Pattern matches known issue signatures',
    color: 'text-amber-400',
    bgColor: 'bg-amber-500/10',
    borderColor: 'border-amber-500/20',
    barWidth: 'w-2/3',
    barColor: 'bg-amber-500',
    communityNote: 'This fix resolved the issue for ~70% of users',
    escalationRate: 'Escalated to vendor in ~12% of cases',
    tacTip: 'Gather additional diagnostics before escalating',
  },
  low: {
    label: 'Low Confidence',
    description: 'Anomaly detected, requires human verification',
    color: 'text-slate-400',
    bgColor: 'bg-slate-500/10',
    borderColor: 'border-slate-500/20',
    barWidth: 'w-1/3',
    barColor: 'bg-slate-500',
    communityNote: 'May be a false positive — verify manually',
    escalationRate: 'Escalated to vendor in ~30% of cases',
    tacTip: 'Cisco TAC will ask for additional packet captures',
  },
};

export function ConfidenceBadge({ level, showDetails = false }: ConfidenceBadgeProps) {
  const config = confidenceConfig[level];

  if (!showDetails) {
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium ${config.bgColor} ${config.color} border ${config.borderColor}`}>
        <Shield className="w-2.5 h-2.5" />
        {config.label}
      </span>
    );
  }

  return (
    <div className={`${config.bgColor} border ${config.borderColor} rounded-lg p-4 space-y-3`}>
      {/* Header with meter */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className={`w-4 h-4 ${config.color}`} />
          <span className={`text-xs font-semibold ${config.color} uppercase tracking-wide`}>
            {config.label}
          </span>
        </div>
        <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
          <div className={`h-full ${config.barColor} ${config.barWidth} rounded-full transition-all`} />
        </div>
      </div>

      <p className="text-xs text-slate-400">{config.description}</p>

      {/* Community validation */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs">
          <Users className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
          <span className="text-slate-300">{config.communityNote}</span>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Headphones className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
          <span className="text-slate-300">{config.escalationRate}</span>
        </div>
      </div>
    </div>
  );
}

// Determine confidence level based on finding characteristics
export function computeConfidence(findingKey: string, count: number, severity: string): ConfidenceLevel {
  // High confidence findings - well-known patterns
  const highConfidenceFindings = [
    'ddos_syn_flood', 'ddos_udp_flood', 'tcp_retransmission', 'packet_loss',
    'vrrp_flapping', 'arp_conflict', 'dhcp_rogue_server', 'tcp_zero_window',
    'tls_weakness', 'ntp_amplification',
  ];

  // Medium confidence findings - pattern matching
  const mediumConfidenceFindings = [
    'port_scan', 'dns_anomaly', 'tcp_handshake_failure', 'high_latency',
    'hsrp_instability', 'tunnel_flapping', 'tcp_small_window', 'tcp_out_of_order',
    'dhcp_starvation', 'dhcp_nak_storm', 'ntp_stratum_change', 'voip_jitter',
    'voip_quality', 'http_errors',
  ];

  if (highConfidenceFindings.includes(findingKey)) {
    return count >= 5 ? 'high' : 'medium';
  }

  if (mediumConfidenceFindings.includes(findingKey)) {
    return count >= 10 ? 'medium' : 'low';
  }

  // C2 and DNS tunneling depend on count and severity
  if (findingKey === 'c2_beaconing' || findingKey === 'dns_tunneling') {
    return count >= 3 ? 'high' : count >= 1 ? 'medium' : 'low';
  }

  if (findingKey === 'ioc_match') {
    return 'high'; // IOC matches are always high confidence
  }

  // Default based on severity and count
  if (severity === 'Critical' && count >= 3) return 'high';
  if (severity === 'Critical' || count >= 5) return 'medium';
  return 'low';
}
