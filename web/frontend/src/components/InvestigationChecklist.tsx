import React, { useState } from 'react';
import {
  ClipboardCheck,
  CheckCircle2,
  Circle,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Shield,
} from 'lucide-react';
import type { ComparisonReport } from '../types';

interface InvestigationChecklistProps {
  report: ComparisonReport;
}

interface ChecklistStep {
  id: string;
  title: string;
  description: string;
  status: 'pass' | 'warning' | 'critical' | 'info';
  metric?: string;
  action?: string;
  icon: React.ReactNode;
}

export const InvestigationChecklist: React.FC<InvestigationChecklistProps> = ({ report }) => {
  const [collapsed, setCollapsed] = useState(false);
  const [checkedSteps, setCheckedSteps] = useState<Set<string>>(new Set());

  const toggleStep = (stepId: string) => {
    setCheckedSteps(prev => {
      const next = new Set(prev);
      if (next.has(stepId)) next.delete(stepId);
      else next.add(stepId);
      return next;
    });
  };

  const steps = generateChecklistSteps(report);
  const completedCount = checkedSteps.size;
  const totalCount = steps.length;
  const progressPercent = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-slate-700/30 transition-colors"
      >
        <div className="flex items-center gap-2.5">
          <ClipboardCheck className="w-4.5 h-4.5 text-blue-400" />
          <span className="text-sm font-medium text-slate-300">Junior Engineer Checklist</span>
          <span className="px-2 py-0.5 text-[10px] font-medium bg-blue-500/15 text-blue-400 rounded-full">
            {completedCount}/{totalCount}
          </span>
        </div>
        {collapsed ? (
          <ChevronDown className="w-4 h-4 text-slate-500" />
        ) : (
          <ChevronUp className="w-4 h-4 text-slate-500" />
        )}
      </button>

      {!collapsed && (
        <div className="px-5 pb-5 border-t border-slate-700/30">
          {/* Progress Bar */}
          <div className="mt-3 mb-4">
            <div className="flex items-center justify-between text-xs text-slate-500 mb-1.5">
              <span>Investigation Progress</span>
              <span>{Math.round(progressPercent)}%</span>
            </div>
            <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>

          {/* Checklist Steps */}
          <div className="space-y-2">
            {steps.map((step, index) => {
              const isChecked = checkedSteps.has(step.id);
              const statusColors = {
                pass: 'border-green-500/30 bg-green-500/5',
                warning: 'border-yellow-500/30 bg-yellow-500/5',
                critical: 'border-red-500/30 bg-red-500/5',
                info: 'border-slate-500/30 bg-slate-500/5',
              };

              return (
                <div
                  key={step.id}
                  className={`border rounded-lg p-3 transition-all ${
                    isChecked ? 'opacity-60' : ''
                  } ${statusColors[step.status]}`}
                >
                  <div className="flex items-start gap-3">
                    {/* Checkbox */}
                    <button
                      onClick={() => toggleStep(step.id)}
                      className="flex-shrink-0 mt-0.5 hover:scale-110 transition-transform"
                    >
                      {isChecked ? (
                        <CheckCircle2 className="w-5 h-5 text-green-400" />
                      ) : (
                        <Circle className="w-5 h-5 text-slate-500" />
                      )}
                    </button>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <div className="flex-shrink-0">{step.icon}</div>
                        <span className="text-sm font-semibold text-white">
                          Step {index + 1}: {step.title}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed mb-2">
                        {step.description}
                      </p>
                      {step.metric && (
                        <div className="text-xs font-mono text-slate-300 bg-slate-900/50 rounded px-2 py-1 mb-2">
                          {step.metric}
                        </div>
                      )}
                      {step.action && (
                        <div className="text-xs text-blue-400 flex items-center gap-1.5">
                          <Info className="w-3 h-3" />
                          <span>{step.action}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Footer Tip */}
          <div className="mt-4 pt-3 border-t border-slate-700/30">
            <p className="text-xs text-slate-500 leading-relaxed">
              💡 <span className="text-slate-400 font-medium">Pro Tip:</span> Check off each step as you complete it
              to track your investigation progress. This workflow follows the same steps a senior engineer would take.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

// ─── Checklist Step Generator ─────────────────────────────────────

function generateChecklistSteps(report: ComparisonReport): ChecklistStep[] {
  const steps: ChecklistStep[] = [];

  // Step 1: Path Integrity Score
  const scoreStatus =
    report.path_integrity_score >= 90
      ? 'pass'
      : report.path_integrity_score >= 80
      ? 'warning'
      : 'critical';

  steps.push({
    id: 'path-integrity',
    title: 'Check Path Integrity Score',
    description:
      'The Path Integrity Score shows what percentage of user traffic successfully transited the SD-WAN device. 90%+ is healthy, 80-90% is degraded, <80% indicates significant packet loss.',
    status: scoreStatus,
    metric: `Current Score: ${report.path_integrity_score.toFixed(1)}% (${report.integrity_rating})`,
    action:
      scoreStatus === 'pass'
        ? 'Score is healthy. No action required.'
        : scoreStatus === 'warning'
        ? 'Score is degraded. Review dropped packets and policy drops below.'
        : 'Score is critical. Immediate investigation required. Check firewall rules and interface status.',
    icon:
      scoreStatus === 'pass' ? (
        <CheckCircle className="w-4 h-4 text-green-400" />
      ) : scoreStatus === 'warning' ? (
        <AlertTriangle className="w-4 h-4 text-yellow-400" />
      ) : (
        <XCircle className="w-4 h-4 text-red-400" />
      ),
  });

  // Step 2: Policy Drops
  const policyDropStatus =
    report.policy_drop_count === 0
      ? 'pass'
      : report.policy_drop_count < 100
      ? 'warning'
      : 'critical';

  if (report.policy_drop_count > 0 || policyDropStatus !== 'pass') {
    steps.push({
      id: 'policy-drops',
      title: 'Review Policy Drops',
      description:
        'Policy drops are TCP SYN packets that were blocked by the SD-WAN device. These indicate firewall rules or ACLs preventing new connections.',
      status: policyDropStatus,
      metric: `Found ${report.policy_drop_count} policy drops`,
      action:
        policyDropStatus === 'pass'
          ? 'No policy drops detected.'
          : policyDropStatus === 'warning'
          ? 'Review Zone-Based Firewall (ZBFW) and ACL configurations. Check if these blocks are intentional.'
          : 'High number of policy drops. Check firewall rules immediately. Users may be unable to access critical services.',
      icon:
        policyDropStatus === 'pass' ? (
          <CheckCircle className="w-4 h-4 text-green-400" />
        ) : policyDropStatus === 'warning' ? (
          <AlertTriangle className="w-4 h-4 text-yellow-400" />
        ) : (
          <XCircle className="w-4 h-4 text-red-400" />
        ),
    });
  }

  // Step 3: Dropped Packets (MISSING_B)
  const droppedStatus =
    report.missing_b_count === 0
      ? 'pass'
      : report.missing_b_count < 50
      ? 'warning'
      : 'critical';

  steps.push({
    id: 'dropped-packets',
    title: 'Investigate Dropped Packets',
    description:
      'Dropped packets (MISSING_B) entered the LAN interface but never exited the WAN interface. These could be firewall blocks, MTU issues, or routing problems.',
    status: droppedStatus,
    metric: `${report.missing_b_count} packets dropped`,
    action:
      droppedStatus === 'pass'
        ? 'No dropped packets. Excellent forwarding performance.'
        : droppedStatus === 'warning'
        ? 'Some packets dropped. Review the Discrepancies table to identify patterns (specific IPs, ports, or protocols).'
        : 'High packet drop rate. Check interface utilization, QoS policies, and firewall rules. Review MTU settings if large packets are being dropped.',
    icon:
      droppedStatus === 'pass' ? (
        <CheckCircle className="w-4 h-4 text-green-400" />
      ) : droppedStatus === 'warning' ? (
        <AlertTriangle className="w-4 h-4 text-yellow-400" />
      ) : (
        <XCircle className="w-4 h-4 text-red-400" />
      ),
  });

  // Step 4: Control Plane Health
  const controlPlaneStatus = report.ignored_control_plane_count > 0 ? 'info' : 'info';

  steps.push({
    id: 'control-plane',
    title: 'Verify Control Plane Health',
    description:
      'Control plane traffic (BFD, OMP, DTLS keepalives) is generated by the SD-WAN device itself to maintain tunnel health and exchange routing information. These packets are excluded from the Path Integrity Score.',
    status: controlPlaneStatus,
    metric: `${report.ignored_control_plane_count} control plane packets detected (BFD/OMP/keepalive)`,
    action:
      'Control plane traffic is normal. Verify BFD and OMP peer status on the device: show bfd summary, show sdwan omp peers',
    icon: <Shield className="w-4 h-4 text-cyan-400" />,
  });

  // Step 5: Encrypted Tunnel Transit
  if (report.verified_encrypted_count > 0) {
    steps.push({
      id: 'encrypted-transit',
      title: 'Verify Encrypted Tunnel Transit',
      description:
        'Verified Encrypted Transit shows packets that were correlated by time and size through the encrypted tunnel. We cannot see inside (ESP-encrypted), but correlation proves they transited successfully.',
      status: 'pass',
      metric: `${report.verified_encrypted_count} packets verified through encrypted tunnel`,
      action:
        'Encrypted tunnel is functioning correctly. These packets count as "successfully transited" in the score.',
      icon: <CheckCircle className="w-4 h-4 text-green-400" />,
    });
  }

  // Step 6: Asymmetric Routing
  const asymmetricStatus =
    report.missing_a_count === 0
      ? 'pass'
      : report.missing_a_count < 20
      ? 'info'
      : 'warning';

  if (report.missing_a_count > 0) {
    steps.push({
      id: 'asymmetric-routing',
      title: 'Review Asymmetric Routing',
      description:
        'Asymmetric routing (MISSING_A) means packets appeared on the WAN but not on the LAN. This is often normal for return traffic using a different path or traffic from remote sites.',
      status: asymmetricStatus,
      metric: `${report.missing_a_count} asymmetric packets detected`,
      action:
        asymmetricStatus === 'pass'
          ? 'No asymmetric routing detected.'
          : asymmetricStatus === 'info'
          ? 'Small number of asymmetric packets is normal. These are likely return traffic or remote site traffic.'
          : 'Higher than normal asymmetric routing. Check if this is expected (DIA policy, remote site traffic) or indicates a routing loop.',
      icon:
        asymmetricStatus === 'pass' ? (
          <CheckCircle className="w-4 h-4 text-green-400" />
        ) : (
          <Info className="w-4 h-4 text-purple-400" />
        ),
    });
  }

  // Step 7: Tunnel Encapsulation
  if (report.tunnel_detected) {
    steps.push({
      id: 'tunnel-encapsulation',
      title: 'Verify Tunnel Encapsulation',
      description:
        'The SD-WAN device is encapsulating traffic in tunnels for transport across the WAN. Verify the tunnel types match your design.',
      status: 'info',
      metric: `Tunnel Types: ${report.tunnel_types?.join(', ') || 'Unknown'} (${report.encapsulated_count} packets encapsulated)`,
      action:
        'Tunnel encapsulation is active. Verify tunnel health: show sdwan ipsec outbound-connections, show sdwan bfd sessions',
      icon: <Info className="w-4 h-4 text-cyan-400" />,
    });
  }

  // Step 8: Modified Packets (NAT/QoS)
  if (report.modified_count > 0) {
    const modifiedStatus = 'info';
    steps.push({
      id: 'modified-packets',
      title: 'Review Modified Packets',
      description:
        'Modified packets had fields changed by the SD-WAN device (NAT, QoS remarking, TTL decrement). This is usually expected behavior.',
      status: modifiedStatus,
      metric: `${report.modified_count} packets modified (NAT: ${report.nat_detected ? 'Yes' : 'No'}, DSCP changes: ${report.dscp_changes})`,
      action:
        'Packet modifications are normal. Verify NAT and QoS policies match your design. TTL changes are expected (each hop decrements TTL by 1).',
      icon: <Info className="w-4 h-4 text-blue-400" />,
    });
  }

  // Step 9: Final Recommendation
  const finalStatus =
    report.path_integrity_score >= 90 && report.policy_drop_count === 0
      ? 'pass'
      : report.path_integrity_score >= 80
      ? 'warning'
      : 'critical';

  steps.push({
    id: 'final-recommendation',
    title: 'Final Recommendation',
    description:
      'Based on the analysis above, determine if the SD-WAN device is functioning correctly or if further investigation is required.',
    status: finalStatus,
    metric:
      finalStatus === 'pass'
        ? 'Device is healthy. No issues detected.'
        : finalStatus === 'warning'
        ? 'Device is functional but has some issues that should be investigated.'
        : 'Device has critical issues requiring immediate attention.',
    action:
      finalStatus === 'pass'
        ? 'No action required. Continue monitoring.'
        : finalStatus === 'warning'
        ? 'Review the discrepancies table and address any policy drops or dropped packets. Document findings for future reference.'
        : 'Escalate to senior engineer or vendor support. Provide this report and the original PCAP files for analysis.',
    icon:
      finalStatus === 'pass' ? (
        <CheckCircle className="w-4 h-4 text-green-400" />
      ) : finalStatus === 'warning' ? (
        <AlertTriangle className="w-4 h-4 text-yellow-400" />
      ) : (
        <XCircle className="w-4 h-4 text-red-400" />
      ),
  });

  return steps;
}
