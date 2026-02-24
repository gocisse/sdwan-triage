import { Shield, Activity, Zap, Network, Server, Globe, Eye, Info } from 'lucide-react';
import type { AnalysisResults } from '../../types';

export type CategoryId = 'all' | 'security' | 'performance' | 'stability' | 'sdwan' | 'infrastructure' | 'application';

interface CategoryItem {
  id: CategoryId;
  label: string;
  icon: React.ElementType;
  count: number;
  infoCount: number;
  color: string;
}

interface IssueSidebarProps {
  results: AnalysisResults;
  activeCategory: CategoryId;
  onCategoryChange: (category: CategoryId) => void;
}

function computeCategories(results: AnalysisResults): CategoryItem[] {
  const securityCount =
    (results.security?.ddos_findings?.length || 0) +
    (results.security?.port_scan_findings?.length || 0) +
    (results.security?.tls_security_findings?.length || 0) +
    (results.security?.ioc_findings?.length || 0) +
    (results.dns_anomalies?.length || 0) +
    (results.arp_conflicts?.length || 0) +
    (results.dns_tunneling_findings?.length || 0) +
    (results.c2_beaconing_findings?.length || 0);

  const performanceCount =
    (results.tcp_retransmissions?.length || 0) +
    (results.tcp_handshakes?.failed_handshake_attempts?.length || 0) +
    (results.tcp_window_findings?.length || 0) +
    (results.tcp_out_of_order_flows?.length || 0) +
    (results.packet_loss && results.packet_loss.packets_lost > 0 ? 1 : 0);

  const stabilityCount =
    (results.lan_protocols?.vrrp_sessions?.filter(s => s.is_flapping)?.length || 0) +
    (results.lan_protocols?.hsrp_groups?.length || 0);

  // SD-WAN: vendors are informational, tunnels could be either
  const sdwanIssueCount = 0; // Tunnel flapping would be counted here if severity > Info
  const sdwanInfoCount =
    (results.sdwan_vendors?.length || 0) +
    (results.tunnel_analysis?.length || 0);

  // Infrastructure: split into actionable issues vs informational insights
  // Issues (Warning/Critical): DHCP, NTP, ICMP anomalies
  const infraIssueCount =
    (results.dhcp_findings?.length || 0) +
    (results.ntp_findings?.length || 0) +
    (results.icmp_analysis?.filter(i => i.is_anomaly)?.length || 0);
  // Info/Insights: CDP, LLDP, STP discovery (not actionable issues)
  const infraInfoCount =
    (results.lan_protocols?.cdp_devices?.length || 0) +
    (results.lan_protocols?.lldp_devices?.length || 0) +
    (results.lan_protocols?.stp_bridges?.length || 0);

  const appCount =
    (results.tls_certs?.length || 0) +
    (results.voip_analysis?.total_rtp_streams || 0);

  const totalIssues = securityCount + performanceCount + stabilityCount + sdwanIssueCount + infraIssueCount + appCount;
  const totalInfo = sdwanInfoCount + infraInfoCount;

  return [
    { id: 'all', label: 'All Findings', icon: Eye, count: totalIssues, infoCount: totalInfo, color: 'text-slate-400' },
    { id: 'security', label: 'Security', icon: Shield, count: securityCount, infoCount: 0, color: 'text-red-400' },
    { id: 'performance', label: 'Performance', icon: Activity, count: performanceCount, infoCount: 0, color: 'text-amber-400' },
    { id: 'stability', label: 'Stability', icon: Zap, count: stabilityCount, infoCount: 0, color: 'text-purple-400' },
    { id: 'sdwan', label: 'SD-WAN', icon: Globe, count: sdwanIssueCount, infoCount: sdwanInfoCount, color: 'text-cyan-400' },
    { id: 'infrastructure', label: 'Infrastructure', icon: Network, count: infraIssueCount, infoCount: infraInfoCount, color: 'text-blue-400' },
    { id: 'application', label: 'Application', icon: Server, count: appCount, infoCount: 0, color: 'text-green-400' },
  ];
}

export function IssueSidebar({ results, activeCategory, onCategoryChange }: IssueSidebarProps) {
  const categories = computeCategories(results);

  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700/50">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Categories</h3>
      </div>
      <nav className="p-2 space-y-0.5">
        {categories.map((cat) => {
          const Icon = cat.icon;
          const isActive = activeCategory === cat.id;
          const hasIssues = cat.count > 0;
          const hasInfo = cat.infoCount > 0;
          // Hide categories with zero issues AND zero info (nothing to show)
          if (!hasIssues && !hasInfo && cat.id !== 'all') return null;
          return (
            <button
              key={cat.id}
              onClick={() => onCategoryChange(cat.id)}
              className={`
                w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all
                ${isActive
                  ? 'bg-slate-700/80 text-white'
                  : 'text-slate-400 hover:bg-slate-700/40 hover:text-white'
                }
              `}
            >
              <Icon className={`w-4 h-4 flex-shrink-0 ${isActive ? cat.color : ''}`} />
              <span className="flex-1 text-left font-medium">{cat.label}</span>
              <div className="flex items-center gap-1">
                {hasIssues && (
                  <span className={`
                    px-2 py-0.5 rounded-full text-xs font-medium
                    ${isActive ? 'bg-slate-600 text-white' : 'bg-slate-700/60 text-slate-400'}
                  `}>
                    {cat.count}
                  </span>
                )}
                {hasInfo && (
                  <span
                    className="px-1.5 py-0.5 rounded-full text-xs text-slate-500 bg-slate-800/60 cursor-help"
                    title={`${cat.infoCount} insight${cat.infoCount > 1 ? 's' : ''} — passive observations, not errors. No action required.`}
                  >
                    +{cat.infoCount}
                  </span>
                )}
              </div>
            </button>
          );
        })}
      </nav>

      {/* Insight Legend */}
      {categories.some(c => c.infoCount > 0) && (
        <div className="mx-3 mb-2 px-3 py-2 rounded-lg bg-slate-800/40 border border-slate-700/30">
          <div className="flex items-center gap-1.5 mb-1">
            <Info className="w-3 h-3 text-slate-500" />
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Insights (+N)</span>
          </div>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            Passive observations about your network — not errors or issues. These help you understand what&apos;s running, but require no action.
          </p>
        </div>
      )}

      {/* Capture Info */}
      <div className="border-t border-slate-700/50 p-4 space-y-2">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Capture Info</h3>
        <div className="space-y-2 text-xs">
          <div className="flex justify-between">
            <span className="text-slate-500">File</span>
            <span className="text-slate-300 truncate ml-2 max-w-[140px]" title={results.file_name}>{results.file_name}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Size</span>
            <span className="text-slate-300">{results.file_size}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Packets</span>
            <span className="text-slate-300">{results.packet_count?.toLocaleString()}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Duration</span>
            <span className="text-slate-300">{results.duration}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
