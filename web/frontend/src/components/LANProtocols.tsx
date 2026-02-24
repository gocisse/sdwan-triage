// LAN Protocols display component

import { Network, Server, AlertTriangle, CheckCircle } from 'lucide-react';
import type { LANProtocols as LANProtocolsType } from '../types';

interface LANProtocolsProps {
  data?: LANProtocolsType;
}

export function LANProtocols({ data }: LANProtocolsProps) {
  if (!data) {
    return (
      <div className="card p-8 text-center">
        <Network className="w-12 h-12 text-slate-500 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">No LAN Protocols Detected</h3>
        <p className="text-slate-400 text-sm">
          This capture does not contain VRRP, CDP, LLDP, HSRP, or STP traffic.
        </p>
      </div>
    );
  }

  const hasData = (data.vrrp_sessions?.length || 0) > 0 ||
    (data.cdp_devices?.length || 0) > 0 ||
    (data.lldp_devices?.length || 0) > 0 ||
    (data.hsrp_groups?.length || 0) > 0 ||
    (data.stp_bridges?.length || 0) > 0;

  if (!hasData) {
    return (
      <div className="card p-8 text-center">
        <Network className="w-12 h-12 text-slate-500 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">No LAN Protocols Detected</h3>
        <p className="text-slate-400 text-sm">
          This capture does not contain VRRP, CDP, LLDP, HSRP, or STP traffic.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* VRRP Sessions */}
      {data.vrrp_sessions && data.vrrp_sessions.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-purple-500/20 border-b border-purple-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-purple-400" />
              <h3 className="font-semibold text-purple-400">
                VRRP Sessions ({data.vrrp_sessions.length})
              </h3>
            </div>
            <p className="text-xs text-purple-400/70 mt-1">
              Virtual Router Redundancy Protocol - High availability monitoring
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">VRID</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Priority</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">State</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Master IP</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Packets</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {data.vrrp_sessions.map((session, i) => (
                  <tr 
                    key={i} 
                    className={`hover:bg-slate-800/50 ${session.is_flapping ? 'bg-red-500/10' : ''}`}
                  >
                    <td className="px-4 py-3">
                      <span className="bg-purple-500 text-white px-2 py-1 rounded text-xs font-bold">
                        {session.virtual_router_id}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{session.priority}</td>
                    <td className="px-4 py-3">
                      <span className="badge badge-success">{session.state}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">{session.master_ip}</td>
                    <td className="px-4 py-3 text-slate-300">{session.packet_count}</td>
                    <td className="px-4 py-3">
                      {session.is_flapping ? (
                        <div className="flex items-center gap-2">
                          <span className="badge badge-danger flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            FLAPPING
                          </span>
                          <span className="text-xs text-red-400">
                            {session.transition_count} transitions
                          </span>
                        </div>
                      ) : (
                        <span className="badge badge-success flex items-center gap-1">
                          <CheckCircle className="w-3 h-3" />
                          Stable
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* CDP Devices */}
      {data.cdp_devices && data.cdp_devices.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-cyan-500/20 border-b border-cyan-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Server className="w-5 h-5 text-cyan-400" />
              <h3 className="font-semibold text-cyan-400">
                CDP Devices ({data.cdp_devices.length})
              </h3>
            </div>
            <p className="text-xs text-cyan-400/70 mt-1">
              Cisco Discovery Protocol - Network device inventory
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Device ID</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">IP Address</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Platform</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Capabilities</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Port</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {data.cdp_devices.map((device, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 text-white font-medium">{device.device_id}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{device.ip_address}</td>
                    <td className="px-4 py-3 text-slate-300">{device.platform}</td>
                    <td className="px-4 py-3">
                      <span className="badge badge-info">{device.capabilities}</span>
                    </td>
                    <td className="px-4 py-3 text-slate-300">{device.port_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* LLDP Devices */}
      {data.lldp_devices && data.lldp_devices.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-green-500/20 border-b border-green-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-green-400" />
              <h3 className="font-semibold text-green-400">
                LLDP Devices ({data.lldp_devices.length})
              </h3>
            </div>
            <p className="text-xs text-green-400/70 mt-1">
              Link Layer Discovery Protocol - Multi-vendor device discovery
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">System Name</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Chassis ID</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Management IP</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Capabilities</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {data.lldp_devices.map((device, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 text-white font-medium">{device.system_name}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{device.chassis_id}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{device.management_ip}</td>
                    <td className="px-4 py-3">
                      <span className="badge badge-success">{device.capabilities}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* HSRP Groups */}
      {data.hsrp_groups && data.hsrp_groups.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-red-500/20 border-b border-red-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-red-400" />
              <h3 className="font-semibold text-red-400">
                HSRP Groups ({data.hsrp_groups.length})
              </h3>
            </div>
            <p className="text-xs text-red-400/70 mt-1">
              Hot Standby Router Protocol - Gateway redundancy
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Group</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">State</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Virtual IP</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Active Router</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Standby Router</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {data.hsrp_groups.map((group, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3">
                      <span className="bg-red-500 text-white px-2 py-1 rounded text-xs font-bold">
                        {group.group_number}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="badge badge-success">{group.state}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300">{group.virtual_ip}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{group.active_router}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{group.standby_router}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* STP Bridges */}
      {data.stp_bridges && data.stp_bridges.length > 0 && (
        <div className="card overflow-hidden">
          <div className="bg-orange-500/20 border-b border-orange-500/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <Network className="w-5 h-5 text-orange-400" />
              <h3 className="font-semibold text-orange-400">
                STP Bridges ({data.stp_bridges.length})
              </h3>
            </div>
            <p className="text-xs text-orange-400/70 mt-1">
              Spanning Tree Protocol - Layer 2 topology
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Bridge ID</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Root Bridge</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Root Cost</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Port ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {data.stp_bridges.map((bridge, i) => (
                  <tr key={i} className="hover:bg-slate-800/50">
                    <td className="px-4 py-3 font-mono text-slate-300">{bridge.bridge_id}</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{bridge.root_bridge_id}</td>
                    <td className="px-4 py-3 text-slate-300">{bridge.root_cost}</td>
                    <td className="px-4 py-3 text-slate-300">{bridge.port_id}</td>
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
