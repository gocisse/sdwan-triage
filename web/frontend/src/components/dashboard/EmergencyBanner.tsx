// Emergency Response Mode - Critical alert banner for active threats
// Displays full-width red banner when critical security findings are detected
// Provides one-click incident report generation and emergency response guidance

import { useState } from 'react';
import { AlertTriangle, Shield, Check, ChevronDown, ChevronUp, FileText, Mail, Clock } from 'lucide-react';
import type { AnalysisResults } from '../../types';

interface EmergencyBannerProps {
  results: AnalysisResults;
}

interface EmergencyAlert {
  type: string;
  title: string;
  description: string;
  immediateActions: string[];
  severity: 'critical' | 'high';
  icon: string;
  evidence: string[];
}

function detectEmergencies(results: AnalysisResults): EmergencyAlert[] {
  const alerts: EmergencyAlert[] = [];

  // Active DDoS attack — trigger on Critical/High severity, OR many concurrent attack patterns
  const ddos = results.security?.ddos_findings || [];
  const criticalDdos = ddos.filter(d => d.severity === 'Critical' || d.severity === 'High');
  const activeDdos = criticalDdos.length > 0 ? criticalDdos : (ddos.length >= 10 ? ddos : []);
  if (activeDdos.length > 0) {
    const totalPackets = activeDdos.reduce((sum, d) => sum + d.packet_count, 0);
    alerts.push({
      type: 'ddos',
      title: 'Active DDoS Attack Detected',
      description: `${activeDdos.length} DDoS attack pattern${activeDdos.length > 1 ? 's' : ''} detected with ${totalPackets.toLocaleString()} attack packets.`,
      immediateActions: [
        'Enable rate limiting on affected interfaces immediately',
        'Block source IPs at the perimeter firewall',
        'Contact your ISP for upstream filtering if attack exceeds your bandwidth',
        'Enable DDoS mitigation service (Cloudflare, Akamai, etc.) if available',
      ],
      severity: 'critical',
      icon: '🔴',
      evidence: activeDdos.slice(0, 10).map(d => `${d.type}: ${d.source_ip} → ${d.target_ip || 'multiple targets'} (${d.packet_count.toLocaleString()} packets)`),
    });
  }

  // C2 Beaconing
  const c2 = results.c2_beaconing_findings || [];
  if (c2.length > 0) {
    alerts.push({
      type: 'c2',
      title: 'Command & Control Beaconing Detected',
      description: `${c2.length} host${c2.length > 1 ? 's' : ''} communicating with suspected C2 infrastructure at regular intervals.`,
      immediateActions: [
        'ISOLATE affected host(s) from the network immediately — do NOT power off',
        'Block C2 destination IPs/domains at firewall and DNS',
        'Preserve all logs and network captures for forensic analysis',
        'Engage incident response team or MSSP',
        'Check for lateral movement from infected hosts',
      ],
      severity: 'critical',
      icon: '📡',
      evidence: c2.map(b => `${b.source_ip} → ${b.dest_ip}:${b.dest_port} (interval: ${b.beacon_interval_sec}s, ${b.connection_count} connections)`),
    });
  }

  // DNS Tunneling (data exfiltration)
  const dnsTunnel = results.dns_tunneling_findings || [];
  if (dnsTunnel.length > 0) {
    alerts.push({
      type: 'dns_tunnel',
      title: 'DNS Tunneling / Data Exfiltration Suspected',
      description: `${dnsTunnel.length} host${dnsTunnel.length > 1 ? 's' : ''} using DNS queries to potentially exfiltrate data or establish covert channels.`,
      immediateActions: [
        'Block the suspicious base domain(s) at DNS resolver immediately',
        'Investigate source host(s) for malware infection',
        'Check threat intelligence for the suspicious domains',
        'Enable DNS security (Umbrella, Zscaler, Pi-hole)',
        'Review DNS logs for full scope of tunneling activity',
      ],
      severity: 'critical',
      icon: '🕳️',
      evidence: dnsTunnel.map(d => `${d.source_ip} → ${d.domain} (${d.query_count} queries, entropy: ${d.entropy_score.toFixed(2)})`),
    });
  }

  // IOC Matches
  const ioc = results.security?.ioc_findings || [];
  if (ioc.length > 0) {
    alerts.push({
      type: 'ioc',
      title: 'Indicators of Compromise Matched',
      description: `${ioc.length} known malicious indicator${ioc.length > 1 ? 's' : ''} detected in network traffic.`,
      immediateActions: [
        'Isolate all hosts communicating with matched IOCs',
        'Block IOC IPs/domains at all security boundaries',
        'Run full EDR scan on affected endpoints',
        'Verify IOCs in multiple threat intel sources (VirusTotal, AlienVault OTX)',
        'Document timeline for incident response report',
      ],
      severity: 'critical',
      icon: '☠️',
      evidence: ioc.map(i => `${i.type}: ${i.matched_value} (${i.confidence} confidence) — ${i.description}`),
    });
  }

  return alerts;
}

function generateIncidentReport(alerts: EmergencyAlert[], results: AnalysisResults): string {
  const now = new Date().toISOString();
  const lines: string[] = [
    '═══════════════════════════════════════════════════════════',
    '           SECURITY INCIDENT REPORT',
    '═══════════════════════════════════════════════════════════',
    '',
    `Generated: ${now}`,
    `Source File: ${results.file_name}`,
    `Capture Duration: ${results.duration}`,
    `Total Packets: ${results.packet_count?.toLocaleString()}`,
    '',
    '─── ALERTS ───────────────────────────────────────────────',
    '',
  ];

  for (const alert of alerts) {
    lines.push(`[${alert.severity.toUpperCase()}] ${alert.title}`);
    lines.push(`  ${alert.description}`);
    lines.push('');
    lines.push('  Evidence:');
    for (const e of alert.evidence) {
      lines.push(`    - ${e}`);
    }
    lines.push('');
    lines.push('  Immediate Actions Required:');
    for (let i = 0; i < alert.immediateActions.length; i++) {
      lines.push(`    ${i + 1}. ${alert.immediateActions[i]}`);
    }
    lines.push('');
    lines.push('─────────────────────────────────────────────────────────');
    lines.push('');
  }

  lines.push('─── AFFECTED HOSTS ───────────────────────────────────────');
  lines.push('');

  const affectedIPs = new Set<string>();
  for (const alert of alerts) {
    for (const e of alert.evidence) {
      const ips = e.match(/\d+\.\d+\.\d+\.\d+/g);
      if (ips) ips.forEach(ip => affectedIPs.add(ip));
    }
  }
  for (const ip of affectedIPs) {
    lines.push(`  - ${ip}`);
  }

  lines.push('');
  lines.push('─── NEXT STEPS ───────────────────────────────────────────');
  lines.push('');
  lines.push('  1. Contain: Isolate affected systems');
  lines.push('  2. Eradicate: Remove malware/block threat actors');
  lines.push('  3. Recover: Restore systems from clean backups');
  lines.push('  4. Lessons Learned: Document and improve defenses');
  lines.push('');
  lines.push('═══════════════════════════════════════════════════════════');
  lines.push('  This report was generated by SD-WAN Triage v4.3.0');
  lines.push('  Preserve this PCAP file as forensic evidence.');
  lines.push('═══════════════════════════════════════════════════════════');

  return lines.join('\n');
}

export function EmergencyBanner({ results }: EmergencyBannerProps) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [reportCopied, setReportCopied] = useState(false);

  const alerts = detectEmergencies(results);

  if (alerts.length === 0) return null;

  const report = generateIncidentReport(alerts, results);

  const copyReport = () => {
    navigator.clipboard.writeText(report).then(() => {
      setReportCopied(true);
      setTimeout(() => setReportCopied(false), 3000);
    });
  };

  const copyEmailDraft = () => {
    const subject = `[SECURITY INCIDENT] ${alerts.map(a => a.title).join(', ')}`;
    const body = `Security Team,\n\nCritical security findings detected during network analysis.\n\n${alerts.map(a => `- ${a.title}: ${a.description}`).join('\n')}\n\nSee attached incident report for full details.\n\nImmediate action required.`;
    navigator.clipboard.writeText(`Subject: ${subject}\n\n${body}`).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    });
  };

  return (
    <div className="rounded-xl border-2 border-red-500/50 overflow-hidden animate-pulse-slow">
      {/* Main Banner */}
      <div className="bg-gradient-to-r from-red-900/80 to-red-800/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/30 flex items-center justify-center animate-pulse">
              <AlertTriangle className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-red-300">Critical Security Alert</h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/30 text-red-300 border border-red-500/50 uppercase tracking-wider">
                  {alerts.length} threat{alerts.length !== 1 ? 's' : ''}
                </span>
              </div>
              <p className="text-sm text-red-200/80 mt-0.5">
                {alerts.map(a => a.title).join(' | ')}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={copyEmailDraft}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-red-500/20 text-red-300 border border-red-500/30 hover:bg-red-500/30 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Mail className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Email Draft'}
            </button>
            <button
              onClick={copyReport}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-red-500/20 text-red-300 border border-red-500/30 hover:bg-red-500/30 transition-colors"
            >
              {reportCopied ? <Check className="w-3.5 h-3.5" /> : <FileText className="w-3.5 h-3.5" />}
              {reportCopied ? 'Copied' : 'Incident Report'}
            </button>
            <button
              onClick={() => setExpanded(!expanded)}
              className="p-2 rounded-lg hover:bg-red-500/20 transition-colors"
            >
              {expanded ? <ChevronUp className="w-5 h-5 text-red-400" /> : <ChevronDown className="w-5 h-5 text-red-400" />}
            </button>
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {expanded && (
        <div className="bg-slate-900/80 border-t border-red-500/30 divide-y divide-red-500/10">
          {alerts.map((alert, i) => (
            <div key={i} className="px-6 py-4">
              <div className="flex items-start gap-3">
                <span className="text-xl">{alert.icon}</span>
                <div className="flex-1 min-w-0">
                  <h3 className="font-semibold text-red-300 text-sm">{alert.title}</h3>
                  <p className="text-xs text-slate-400 mt-1">{alert.description}</p>

                  {/* Evidence */}
                  <div className="mt-3">
                    <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Evidence</h4>
                    <div className="space-y-1">
                      {alert.evidence.slice(0, 5).map((e, j) => (
                        <div key={j} className="flex items-start gap-2">
                          <Shield className="w-3 h-3 text-red-400 flex-shrink-0 mt-0.5" />
                          <code className="text-[11px] text-red-200/80 font-mono break-all">{e}</code>
                        </div>
                      ))}
                      {alert.evidence.length > 5 && (
                        <p className="text-[10px] text-slate-500 ml-5">+{alert.evidence.length - 5} more...</p>
                      )}
                    </div>
                  </div>

                  {/* Immediate Actions */}
                  <div className="mt-3">
                    <h4 className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Immediate Actions</h4>
                    <ol className="space-y-1.5">
                      {alert.immediateActions.map((action, j) => (
                        <li key={j} className="flex items-start gap-2 text-xs">
                          <span className="w-4 h-4 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center flex-shrink-0 text-[10px] font-bold">
                            {j + 1}
                          </span>
                          <span className="text-slate-300">{action}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                </div>
              </div>
            </div>
          ))}

          {/* Timeline Note */}
          <div className="px-6 py-3 bg-red-500/5">
            <div className="flex items-center gap-2 text-xs text-red-300/70">
              <Clock className="w-3.5 h-3.5" />
              <span>Preserve this PCAP file as forensic evidence. Do not modify or delete it.</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
