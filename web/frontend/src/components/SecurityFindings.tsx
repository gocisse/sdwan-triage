// Security findings display component

import { Shield, AlertTriangle, Globe, Network } from 'lucide-react';
import type { DDoSFinding, DNSAnomaly, TLSSecurityFinding, ARPConflict } from '../types';
import { getSeverityColor } from '../utils';

interface SecurityFindingsProps {
  ddosFindings?: DDoSFinding[];
  dnsAnomalies?: DNSAnomaly[];
  tlsFindings?: TLSSecurityFinding[];
  arpConflicts?: ARPConflict[];
}

export function SecurityFindings({
  ddosFindings = [],
  dnsAnomalies = [],
  tlsFindings = [],
  arpConflicts = [],
}: SecurityFindingsProps) {
  // Ensure arrays are valid
  const safeDdos = ddosFindings || [];
  const safeDns = dnsAnomalies || [];
  const safeTls = tlsFindings || [];
  const safeArp = arpConflicts || [];

  const hasFindings = safeDdos.length > 0 || safeDns.length > 0 || safeTls.length > 0 || safeArp.length > 0;

  if (!hasFindings) {
    return (
      <div className="card p-8 text-center">
        <Shield className="w-12 h-12 text-green-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">No Security Issues Found</h3>
        <p className="text-slate-400 text-sm">
          The analysis did not detect any security threats in this capture.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* DDoS Attacks */}
      {safeDdos.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-red-500/20 border-b border-red-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="font-semibold text-red-400">
                DDoS Attacks ({safeDdos.length})
              </h3>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Type</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Source</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Target</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Packets</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {safeDdos.map((finding, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 text-white font-medium">{finding.type}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{finding.source_ip}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{finding.target_ip}</td>
                    <td className="px-4 py-3 text-slate-300">{finding.packet_count}</td>
                    <td className="px-4 py-3">
                      <span className={`badge ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* DNS Anomalies */}
      {safeDns.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-yellow-500/20 border-b border-yellow-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-yellow-400" />
              <h3 className="font-semibold text-yellow-400">
                DNS Anomalies ({safeDns.length})
              </h3>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Query</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Server</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Answer</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {safeDns.map((anomaly, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 font-mono text-slate-300 max-w-xs truncate">
                      {anomaly.query}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">{anomaly.server_ip}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{anomaly.answer_ip || '-'}</td>
                    <td className="px-4 py-3 text-slate-400 text-xs">{anomaly.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TLS Findings */}
      {safeTls.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-orange-500/20 border-b border-orange-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-orange-400" />
              <h3 className="font-semibold text-orange-400">
                TLS Weaknesses ({safeTls.length})
              </h3>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Server</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Version</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Severity</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Issue</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {safeTls.map((finding, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3">
                      <div className="font-mono text-slate-300">{finding.server_ip}:{finding.server_port}</div>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{finding.tls_version}</td>
                    <td className="px-4 py-3">
                      <span className={`badge ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs max-w-xs">
                      {finding.description}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ARP Conflicts */}
      {safeArp.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-purple-500/20 border-b border-purple-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-purple-400" />
              <h3 className="font-semibold text-purple-400">
                ARP Conflicts ({safeArp.length})
              </h3>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">IP Address</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">MAC Addresses</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">First Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {safeArp.map((conflict, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 font-mono text-white">{conflict.ip_address}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {conflict.mac_addresses.map((mac, j) => (
                          <span key={j} className="font-mono text-xs bg-slate-700 px-2 py-1 rounded">
                            {mac}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {conflict.first_seen || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
