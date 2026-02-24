// Results summary card component

import { 
  AlertTriangle, 
  AlertCircle, 
  Activity, 
  Server
} from 'lucide-react';
import type { AnalysisResults } from '../types';
import { formatNumber } from '../utils';

interface ResultsCardProps {
  results: AnalysisResults;
}

export function ResultsCard({ results }: ResultsCardProps) {
  // Calculate summary counts using correct backend field names
  const criticalCount = (results.security?.ddos_findings?.length || 0) + 
    (results.security?.tls_security_findings?.length || 0);
  
  const warningCount = (results.dns_anomalies?.length || 0) + 
    (results.arp_conflicts?.length || 0) +
    (results.lan_protocols?.vrrp_sessions?.filter(v => v.is_flapping)?.length || 0);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Packets Analyzed */}
      <StatCard
        icon={Activity}
        label="Packets Analyzed"
        value={formatNumber(results.packet_count || 0)}
        color="blue"
      />

      {/* Critical Issues */}
      <StatCard
        icon={AlertTriangle}
        label="Critical Issues"
        value={criticalCount.toString()}
        color={criticalCount > 0 ? 'red' : 'green'}
      />

      {/* Warnings */}
      <StatCard
        icon={AlertCircle}
        label="Warnings"
        value={warningCount.toString()}
        color={warningCount > 0 ? 'yellow' : 'green'}
      />

      {/* Devices Detected */}
      <StatCard
        icon={Server}
        label="Devices Found"
        value={(results.device_fingerprinting?.length || 0).toString()}
        color="purple"
      />
    </div>
  );
}

interface StatCardProps {
  icon: React.ElementType;
  label: string;
  value: string;
  color: 'blue' | 'red' | 'yellow' | 'green' | 'purple';
}

function StatCard({ icon: Icon, label, value, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    red: 'bg-red-500/20 text-red-400 border-red-500/30',
    yellow: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    green: 'bg-green-500/20 text-green-400 border-green-500/30',
    purple: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  };

  const iconColorClasses = {
    blue: 'bg-blue-500/30 text-blue-400',
    red: 'bg-red-500/30 text-red-400',
    yellow: 'bg-yellow-500/30 text-yellow-400',
    green: 'bg-green-500/30 text-green-400',
    purple: 'bg-purple-500/30 text-purple-400',
  };

  return (
    <div className={`card p-4 border ${colorClasses[color]}`}>
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${iconColorClasses[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <p className="text-2xl font-bold text-white">{value}</p>
          <p className="text-xs text-slate-400">{label}</p>
        </div>
      </div>
    </div>
  );
}
