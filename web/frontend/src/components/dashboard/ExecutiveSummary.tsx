import { Shield, Activity, AlertTriangle, CheckCircle, Info, TrendingUp } from 'lucide-react';
import type { AnalysisResults } from '../../types';
import { getSeverityConfig } from '../../data/knowledgeBase';

interface ExecutiveSummaryProps {
  results: AnalysisResults;
}

interface IssueSummary {
  label: string;
  count: number;
  severity: string;
  icon: React.ElementType;
}

function computeIssues(results: AnalysisResults): IssueSummary[] {
  const issues: IssueSummary[] = [];

  const ddos = results.security?.ddos_findings?.length || 0;
  if (ddos > 0) issues.push({ label: 'DDoS Attacks', count: ddos, severity: 'Critical', icon: AlertTriangle });

  const portScans = results.security?.port_scan_findings?.length || 0;
  if (portScans > 0) issues.push({ label: 'Port Scans', count: portScans, severity: 'Warning', icon: Shield });

  const tls = results.security?.tls_security_findings?.length || 0;
  if (tls > 0) issues.push({ label: 'TLS Weaknesses', count: tls, severity: 'Warning', icon: Shield });

  const dns = results.dns_anomalies?.length || 0;
  if (dns > 0) issues.push({ label: 'DNS Anomalies', count: dns, severity: 'Warning', icon: Info });

  const retrans = results.tcp_retransmissions?.length || 0;
  if (retrans > 0) issues.push({ label: 'TCP Retransmissions', count: retrans, severity: retrans > 500 ? 'Critical' : 'Warning', icon: Activity });

  const failedHandshakes = results.tcp_handshakes?.failed_handshake_attempts?.length || 0;
  if (failedHandshakes > 0) issues.push({ label: 'Failed TCP Handshakes', count: failedHandshakes, severity: 'Warning', icon: Activity });

  const arp = results.arp_conflicts?.length || 0;
  if (arp > 0) issues.push({ label: 'ARP Conflicts', count: arp, severity: 'Warning', icon: AlertTriangle });

  const vrrpFlapping = results.lan_protocols?.vrrp_sessions?.filter(s => s.is_flapping)?.length || 0;
  if (vrrpFlapping > 0) issues.push({ label: 'VRRP Flapping', count: vrrpFlapping, severity: 'Critical', icon: AlertTriangle });

  const dhcp = results.dhcp_findings?.length || 0;
  if (dhcp > 0) issues.push({ label: 'DHCP Issues', count: dhcp, severity: 'Critical', icon: AlertTriangle });

  const ntp = results.ntp_findings?.length || 0;
  if (ntp > 0) issues.push({ label: 'NTP Issues', count: ntp, severity: 'Warning', icon: Info });

  const dnsTunnel = results.dns_tunneling_findings?.length || 0;
  if (dnsTunnel > 0) issues.push({ label: 'DNS Tunneling', count: dnsTunnel, severity: 'Critical', icon: AlertTriangle });

  const c2 = results.c2_beaconing_findings?.length || 0;
  if (c2 > 0) issues.push({ label: 'C2 Beaconing', count: c2, severity: 'Critical', icon: AlertTriangle });

  const tcpWindow = results.tcp_window_findings?.length || 0;
  if (tcpWindow > 0) issues.push({ label: 'TCP Window Issues', count: tcpWindow, severity: 'Warning', icon: Activity });

  const tcpOoo = results.tcp_out_of_order_flows?.length || 0;
  if (tcpOoo > 0) issues.push({ label: 'TCP Out-of-Order', count: tcpOoo, severity: 'Warning', icon: Activity });

  const pktLoss = results.packet_loss;
  if (pktLoss && pktLoss.packets_lost > 0) {
    issues.push({ label: 'Packet Loss', count: pktLoss.packets_lost, severity: pktLoss.loss_percentage > 5 ? 'Critical' : 'Warning', icon: AlertTriangle });
  }

  return issues.sort((a, b) => {
    const order: Record<string, number> = { Critical: 0, Warning: 1, Info: 2 };
    return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
  });
}

function generateSummary(results: AnalysisResults, issues: IssueSummary[]): string {
  if (issues.length === 0) {
    return 'No significant issues detected in this capture. The network appears healthy.';
  }

  const critical = issues.filter(i => i.severity === 'Critical');
  const warnings = issues.filter(i => i.severity === 'Warning');

  const parts: string[] = [];

  if (critical.length > 0) {
    const top = critical[0];
    parts.push(`${top.count} ${top.label.toLowerCase()} detected requiring immediate attention`);
  }

  if (warnings.length > 0) {
    parts.push(`${warnings.length} warning-level issue${warnings.length > 1 ? 's' : ''} found`);
  }

  const retrans = results.tcp_retransmissions?.length || 0;
  const successH = results.tcp_handshakes?.successful_handshakes?.length || 0;
  const failedH = results.tcp_handshakes?.failed_handshake_attempts?.length || 0;
  const totalH = successH + failedH;
  if (totalH > 0 && failedH > 0) {
    const failRate = ((failedH / totalH) * 100).toFixed(1);
    parts.push(`${failRate}% TCP handshake failure rate`);
  }

  if (retrans > 100) {
    parts.push(`${retrans.toLocaleString()} retransmissions indicating packet loss`);
  }

  return parts.join('. ') + '.';
}

export function ExecutiveSummary({ results }: ExecutiveSummaryProps) {
  const issues = computeIssues(results);
  const summary = generateSummary(results, issues);
  const criticalCount = issues.filter(i => i.severity === 'Critical').length;
  const warningCount = issues.filter(i => i.severity === 'Warning').length;
  const infoCount = issues.filter(i => i.severity === 'Info').length;

  const riskScore = results.risk_score ?? 0;
  const riskLevel = results.risk_level || 'Low';

  return (
    <div className="space-y-4">
      {/* Network Health Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0 ${
              riskScore >= 70 ? 'bg-red-500/20' : riskScore >= 40 ? 'bg-amber-500/20' : 'bg-green-500/20'
            }`}>
              <span className={`text-2xl font-bold ${
                riskScore >= 70 ? 'text-red-400' : riskScore >= 40 ? 'text-amber-400' : 'text-green-400'
              }`}>
                {riskScore}
              </span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h2 className="text-lg font-semibold text-white">Network Health Assessment</h2>
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getSeverityConfig(riskLevel).bg} ${getSeverityConfig(riskLevel).text}`}>
                  {riskLevel} Risk
                </span>
              </div>
              <p className="text-slate-300 text-sm leading-relaxed">{summary}</p>
              {results.top_issue && (
                <div className="mt-3 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-amber-400 flex-shrink-0" />
                  <span className="text-sm text-amber-400">Top Issue: {results.top_issue}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
          <h3 className="text-sm font-medium text-slate-400 mb-4">Issue Breakdown</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
                <span className="text-sm text-slate-300">Critical</span>
              </div>
              <span className="text-lg font-bold text-red-400">{criticalCount}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <span className="text-sm text-slate-300">Warning</span>
              </div>
              <span className="text-lg font-bold text-amber-400">{warningCount}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-blue-500" />
                <span className="text-sm text-slate-300">Info</span>
              </div>
              <span className="text-lg font-bold text-blue-400">{infoCount}</span>
            </div>
          </div>

          {issues.length === 0 && (
            <div className="mt-4 flex items-center gap-2 text-green-400">
              <CheckCircle className="w-5 h-5" />
              <span className="text-sm font-medium">All Clear</span>
            </div>
          )}
        </div>
      </div>

      {/* Top Issues Cards */}
      {issues.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {issues.slice(0, 4).map((issue, i) => {
            const sev = getSeverityConfig(issue.severity);
            const Icon = issue.icon;
            return (
              <div key={i} className={`${sev.bg} border ${sev.border} rounded-xl p-4`}>
                <div className="flex items-center justify-between mb-2">
                  <Icon className={`w-5 h-5 ${sev.text}`} />
                  <span className={`text-2xl font-bold ${sev.text}`}>{issue.count}</span>
                </div>
                <p className="text-sm font-medium text-white">{issue.label}</p>
                <p className={`text-xs ${sev.text} mt-0.5`}>{issue.severity}</p>
              </div>
            );
          })}
        </div>
      )}

      {/* Quick Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/30">
          <p className="text-2xl font-bold text-white">{results.packet_count?.toLocaleString() || '0'}</p>
          <p className="text-xs text-slate-400 mt-1">Packets Analyzed</p>
        </div>
        <div className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/30">
          <p className="text-2xl font-bold text-white">{results.device_fingerprinting?.length || 0}</p>
          <p className="text-xs text-slate-400 mt-1">Devices Detected</p>
        </div>
        <div className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/30">
          <p className="text-2xl font-bold text-white">{results.sdwan_vendors?.length || 0}</p>
          <p className="text-xs text-slate-400 mt-1">SD-WAN Vendors</p>
        </div>
        <div className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/30">
          <p className="text-2xl font-bold text-white">{results.tunnel_analysis?.length || 0}</p>
          <p className="text-xs text-slate-400 mt-1">Tunnels Found</p>
        </div>
      </div>
    </div>
  );
}
