// Interactive Network Topology Map
// Auto-generates a topology diagram from PCAP data showing devices, links, and issues
// Uses HTML5 Canvas for rendering (handles 1000s of nodes without DOM bloat)
// Force-directed layout simulation runs in requestAnimationFrame

import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { ZoomIn, ZoomOut, Maximize2, X, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import type { AnalysisResults } from '../../types';

interface NetworkTopologyProps {
  results: AnalysisResults;
}

interface TopoNode {
  id: string;
  ip: string;
  label: string;
  type: 'router' | 'switch' | 'firewall' | 'server' | 'client' | 'unknown';
  x: number;
  y: number;
  vx: number;
  vy: number;
  issues: string[];
  severity: 'healthy' | 'warning' | 'critical';
  bytesTotal: number;
}

interface TopoLink {
  source: string;
  target: string;
  bytes: number;
  protocol: string;
  health: 'healthy' | 'warning' | 'critical';
  issues: string[];
}

function inferDeviceType(ip: string, results: AnalysisResults): 'router' | 'switch' | 'firewall' | 'server' | 'client' | 'unknown' {
  // Check CDP/LLDP for device type
  const cdp = results.lan_protocols?.cdp_devices || [];
  const cdpDevice = cdp.find(d => d.ip_address === ip);
  if (cdpDevice) {
    const caps = cdpDevice.capabilities.toLowerCase();
    if (caps.includes('router')) return 'router';
    if (caps.includes('switch')) return 'switch';
  }

  const lldp = results.lan_protocols?.lldp_devices || [];
  const lldpDevice = lldp.find(d => d.management_ip === ip);
  if (lldpDevice) {
    const caps = lldpDevice.capabilities.toLowerCase();
    if (caps.includes('router')) return 'router';
    if (caps.includes('bridge') || caps.includes('switch')) return 'switch';
  }

  // Check VRRP/HSRP (routers)
  const vrrp = results.lan_protocols?.vrrp_sessions || [];
  if (vrrp.some(s => s.master_ip === ip)) return 'router';

  // Check device fingerprinting
  const devices = results.device_fingerprinting || [];
  const device = devices.find(d => d.ip === ip);
  if (device) {
    const os = device.os_name.toLowerCase();
    if (os.includes('cisco') || os.includes('juniper') || os.includes('router')) return 'router';
    if (os.includes('windows server') || os.includes('linux')) return 'server';
    if (os.includes('windows') || os.includes('macos') || os.includes('android') || os.includes('ios')) return 'client';
  }

  // Check if it's a private IP (likely internal device)
  if (ip.startsWith('10.') || ip.startsWith('172.') || ip.startsWith('192.168.')) {
    return 'client';
  }

  return 'server'; // External IPs are likely servers
}

function getDeviceIssues(ip: string, results: AnalysisResults): { issues: string[]; severity: 'healthy' | 'warning' | 'critical' } {
  const issues: string[] = [];
  let severity: 'healthy' | 'warning' | 'critical' = 'healthy';

  // Check DDoS
  const ddos = results.security?.ddos_findings || [];
  if (ddos.some(d => d.source_ip === ip)) { issues.push('DDoS source'); severity = 'critical'; }
  if (ddos.some(d => d.target_ip === ip)) { issues.push('DDoS target'); severity = 'critical'; }

  // Check C2
  const c2 = results.c2_beaconing_findings || [];
  if (c2.some(b => b.source_ip === ip)) { issues.push('C2 beaconing'); severity = 'critical'; }
  if (c2.some(b => b.dest_ip === ip)) { issues.push('C2 server'); severity = 'critical'; }

  // Check DNS tunneling
  const tunnel = results.dns_tunneling_findings || [];
  if (tunnel.some(t => t.source_ip === ip)) { issues.push('DNS tunneling'); severity = 'critical'; }

  // Check ARP conflicts
  const arp = results.arp_conflicts || [];
  if (arp.some(a => a.ip_address === ip)) {
    issues.push('ARP conflict');
    if (severity !== 'critical') severity = 'warning';
  }

  // Check VRRP flapping
  const vrrp = results.lan_protocols?.vrrp_sessions || [];
  if (vrrp.some(s => s.master_ip === ip && s.is_flapping)) {
    issues.push('VRRP flapping');
    if (severity !== 'critical') severity = 'warning';
  }

  // Check port scans
  const scans = results.security?.port_scan_findings || [];
  if (scans.some(s => s.source_ip === ip)) {
    issues.push('Port scanning');
    if (severity !== 'critical') severity = 'warning';
  }

  // Check DHCP
  const dhcp = results.dhcp_findings || [];
  if (dhcp.some(d => d.server_ip === ip && d.type === 'Rogue Server')) {
    issues.push('Rogue DHCP');
    severity = 'critical';
  }

  return { issues, severity };
}

function buildTopology(results: AnalysisResults): { nodes: TopoNode[]; links: TopoLink[] } {
  const nodeMap = new Map<string, TopoNode>();
  const linkMap = new Map<string, TopoLink>();

  // Collect IPs from traffic analysis
  const flows = results.traffic_analysis || [];
  const topFlows = flows.slice(0, 100); // Canvas can handle more flows than SVG

  for (const flow of topFlows) {
    // Add source node
    if (!nodeMap.has(flow.src_ip)) {
      const { issues, severity } = getDeviceIssues(flow.src_ip, results);
      nodeMap.set(flow.src_ip, {
        id: flow.src_ip,
        ip: flow.src_ip,
        label: flow.src_ip,
        type: inferDeviceType(flow.src_ip, results),
        x: 0, y: 0, vx: 0, vy: 0,
        issues,
        severity,
        bytesTotal: 0,
      });
    }
    nodeMap.get(flow.src_ip)!.bytesTotal += flow.total_bytes;

    // Add dest node
    if (!nodeMap.has(flow.dst_ip)) {
      const { issues, severity } = getDeviceIssues(flow.dst_ip, results);
      nodeMap.set(flow.dst_ip, {
        id: flow.dst_ip,
        ip: flow.dst_ip,
        label: flow.dst_ip,
        type: inferDeviceType(flow.dst_ip, results),
        x: 0, y: 0, vx: 0, vy: 0,
        issues,
        severity,
        bytesTotal: 0,
      });
    }
    nodeMap.get(flow.dst_ip)!.bytesTotal += flow.total_bytes;

    // Add link
    const linkKey = [flow.src_ip, flow.dst_ip].sort().join('-');
    if (!linkMap.has(linkKey)) {
      linkMap.set(linkKey, {
        source: flow.src_ip,
        target: flow.dst_ip,
        bytes: 0,
        protocol: flow.protocol,
        health: 'healthy',
        issues: [],
      });
    }
    linkMap.get(linkKey)!.bytes += flow.total_bytes;
  }

  // Add retransmission info to links
  const retrans = results.tcp_retransmissions || [];
  for (const r of retrans) {
    const linkKey = [r.src_ip, r.dst_ip].sort().join('-');
    const link = linkMap.get(linkKey);
    if (link) {
      link.health = (r.retransmissions || 0) > 100 ? 'critical' : 'warning';
      link.issues.push(`${r.retransmissions} retransmissions`);
    }
  }

  // Layout nodes in a circular pattern, grouped by type
  const nodes = Array.from(nodeMap.values());
  const limitedNodes = nodes.sort((a, b) => b.bytesTotal - a.bytesTotal).slice(0, 50);

  const centerX = 400;
  const centerY = 300;
  const radius = 220;

  // Group by type for better layout
  const routers = limitedNodes.filter(n => n.type === 'router');
  const switches = limitedNodes.filter(n => n.type === 'switch');
  const servers = limitedNodes.filter(n => n.type === 'server');
  const clients = limitedNodes.filter(n => n.type === 'client' || n.type === 'unknown');

  const groups = [routers, switches, servers, clients].filter(g => g.length > 0);
  let angleOffset = 0;

  for (const group of groups) {
    const angleStep = (2 * Math.PI) / Math.max(limitedNodes.length, 1);
    for (let i = 0; i < group.length; i++) {
      const angle = angleOffset + i * angleStep;
      const r = group[0].type === 'router' ? radius * 0.4 : radius;
      group[i].x = centerX + r * Math.cos(angle);
      group[i].y = centerY + r * Math.sin(angle);
    }
    angleOffset += group.length * ((2 * Math.PI) / Math.max(limitedNodes.length, 1));
  }

  // Filter links to only include visible nodes
  const visibleIPs = new Set(limitedNodes.map(n => n.id));
  const filteredLinks = Array.from(linkMap.values()).filter(
    l => visibleIPs.has(l.source) && visibleIPs.has(l.target)
  );

  return { nodes: limitedNodes, links: filteredLinks };
}

const deviceTypeColors: Record<string, string> = {
  router: '#60a5fa',
  switch: '#34d399',
  firewall: '#f87171',
  server: '#a78bfa',
  client: '#94a3b8',
  unknown: '#64748b',
};

const healthColors: Record<string, string> = {
  healthy: '#22c55e',
  warning: '#f59e0b',
  critical: '#ef4444',
};

// ─── Force simulation (pure JS, no d3 dependency) ──────────
const FORCE_ITERATIONS = 120;
const REPULSION = 8000;
const ATTRACTION = 0.005;
const DAMPING = 0.85;
const CENTER_GRAVITY = 0.01;

function runForceSimulation(nodes: TopoNode[], links: TopoLink[], width: number, height: number) {
  const cx = width / 2;
  const cy = height / 2;
  const nodeById = new Map(nodes.map(n => [n.id, n]));

  for (let iter = 0; iter < FORCE_ITERATIONS; iter++) {
    // Repulsion between all node pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = REPULSION / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }

    // Attraction along links
    for (const link of links) {
      const s = nodeById.get(link.source);
      const t = nodeById.get(link.target);
      if (!s || !t) continue;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const force = dist * ATTRACTION;
      const fx = (dx / Math.max(dist, 1)) * force;
      const fy = (dy / Math.max(dist, 1)) * force;
      s.vx += fx; s.vy += fy;
      t.vx -= fx; t.vy -= fy;
    }

    // Center gravity
    for (const n of nodes) {
      n.vx += (cx - n.x) * CENTER_GRAVITY;
      n.vy += (cy - n.y) * CENTER_GRAVITY;
    }

    // Apply velocities with damping
    for (const n of nodes) {
      n.vx *= DAMPING;
      n.vy *= DAMPING;
      n.x += n.vx;
      n.y += n.vy;
      // Clamp to bounds
      n.x = Math.max(40, Math.min(width - 40, n.x));
      n.y = Math.max(40, Math.min(height - 40, n.y));
    }
  }
}

// ─── Canvas draw function ──────────────────────────────────
function drawTopology(
  ctx: CanvasRenderingContext2D,
  nodes: TopoNode[],
  links: TopoLink[],
  selectedId: string | null,
  width: number,
  height: number,
  dpr: number,
  tick: number,
) {
  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  // Background
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, width, height);

  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const maxBytes = Math.max(...links.map(l => l.bytes), 1);

  // Draw links
  for (const link of links) {
    const s = nodeById.get(link.source);
    const t = nodeById.get(link.target);
    if (!s || !t) continue;

    const lw = 1 + (link.bytes / maxBytes) * 4;
    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);
    ctx.strokeStyle = healthColors[link.health] || healthColors.healthy;
    ctx.globalAlpha = 0.35;
    ctx.lineWidth = lw;
    ctx.lineCap = 'round';
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Animated flow dot along link
    const progress = ((tick * 0.008) + links.indexOf(link) * 0.17) % 1;
    const dotX = s.x + (t.x - s.x) * progress;
    const dotY = s.y + (t.y - s.y) * progress;
    ctx.beginPath();
    ctx.arc(dotX, dotY, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = healthColors[link.health] || healthColors.healthy;
    ctx.globalAlpha = 0.7;
    ctx.fill();
    ctx.globalAlpha = 1;
  }

  // Draw nodes
  const nodeRadius = 18;
  for (const node of nodes) {
    const isSelected = node.id === selectedId;
    const color = deviceTypeColors[node.type] || deviceTypeColors.unknown;
    const borderColor = node.severity === 'critical' ? healthColors.critical
      : node.severity === 'warning' ? healthColors.warning : '#334155';

    // Pulsing glow for critical nodes
    if (node.severity === 'critical') {
      const pulse = 0.3 + 0.2 * Math.sin(tick * 0.05);
      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeRadius + 8, 0, Math.PI * 2);
      ctx.strokeStyle = healthColors.critical;
      ctx.globalAlpha = pulse;
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    // Selection ring
    if (isSelected) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, nodeRadius + 5, 0, Math.PI * 2);
      ctx.strokeStyle = '#3b82f6';
      ctx.lineWidth = 2;
      ctx.setLineDash([4, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Node circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, nodeRadius, 0, Math.PI * 2);
    ctx.fillStyle = '#1e293b';
    ctx.fill();
    ctx.strokeStyle = borderColor;
    ctx.lineWidth = isSelected ? 2.5 : 1.5;
    ctx.stroke();

    // Device type icon (simple symbol)
    ctx.fillStyle = color;
    ctx.font = 'bold 11px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    const typeLabel = node.type === 'router' ? 'R' : node.type === 'switch' ? 'SW'
      : node.type === 'firewall' ? 'FW' : node.type === 'server' ? 'S' : 'C';
    ctx.fillText(typeLabel, node.x, node.y);

    // Issue count badge
    if (node.issues.length > 0) {
      const bx = node.x + 13, by = node.y - 13;
      ctx.beginPath();
      ctx.arc(bx, by, 7, 0, Math.PI * 2);
      ctx.fillStyle = healthColors[node.severity] || healthColors.warning;
      ctx.fill();
      ctx.fillStyle = '#fff';
      ctx.font = 'bold 8px sans-serif';
      ctx.fillText(String(node.issues.length), bx, by + 0.5);
    }

    // Label
    ctx.fillStyle = '#94a3b8';
    ctx.font = '9px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(node.label, node.x, node.y + nodeRadius + 4);
  }

  ctx.restore();
}

// ─── Hit test: find node under mouse ───────────────────────
function hitTestNode(nodes: TopoNode[], mx: number, my: number): TopoNode | null {
  const r = 18;
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    const dx = mx - n.x, dy = my - n.y;
    if (dx * dx + dy * dy <= r * r) return n;
  }
  return null;
}

export function NetworkTopology({ results }: NetworkTopologyProps) {
  const [selectedNode, setSelectedNode] = useState<TopoNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const tickRef = useRef(0);

  const { nodes, links } = useMemo(() => {
    const topo = buildTopology(results);
    // Run force simulation to compute positions
    runForceSimulation(topo.nodes, topo.links, 800, 600);
    return topo;
  }, [results]);

  // Canvas animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || nodes.length === 0) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const w = 800, h = 600;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;

    let running = true;
    const animate = () => {
      if (!running) return;
      tickRef.current++;
      drawTopology(ctx, nodes, links, selectedNode?.id ?? null, w, h, dpr, tickRef.current);
      animRef.current = requestAnimationFrame(animate);
    };
    animate();

    return () => {
      running = false;
      cancelAnimationFrame(animRef.current);
    };
  }, [nodes, links, selectedNode]);

  // Handle click on canvas
  const handleCanvasClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const scaleX = 800 / rect.width;
    const scaleY = 600 / rect.height;
    const mx = (e.clientX - rect.left) * scaleX;
    const my = (e.clientY - rect.top) * scaleY;
    const hit = hitTestNode(nodes, mx, my);
    setSelectedNode(prev => (prev?.id === hit?.id ? null : hit));
  }, [nodes]);

  const handleExportPNG = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const a = document.createElement('a');
    a.href = canvas.toDataURL('image/png');
    a.download = `topology-${results.file_name || 'network'}.png`;
    a.click();
  }, [results.file_name]);

  if (nodes.length === 0) {
    return (
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-8 text-center">
        <Info className="w-8 h-8 text-slate-500 mx-auto mb-2" />
        <p className="text-sm text-slate-400">No topology data available. Upload a PCAP with more traffic flows to generate a network map.</p>
      </div>
    );
  }

  const containerClass = isFullscreen
    ? 'fixed inset-0 z-50 bg-slate-900 flex flex-col'
    : 'bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden';

  return (
    <div className={containerClass}>
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/50">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-white">Network Topology</h3>
          <span className="text-[10px] text-slate-500">{nodes.length} devices, {links.length} links</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Canvas</span>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={() => setZoom(z => Math.min(z + 0.2, 2))} className="p-1.5 rounded hover:bg-slate-700 transition-colors" title="Zoom in">
            <ZoomIn className="w-4 h-4 text-slate-400" />
          </button>
          <button onClick={() => setZoom(z => Math.max(z - 0.2, 0.5))} className="p-1.5 rounded hover:bg-slate-700 transition-colors" title="Zoom out">
            <ZoomOut className="w-4 h-4 text-slate-400" />
          </button>
          <div className="w-px h-4 bg-slate-700 mx-1" />
          <button onClick={handleExportPNG} className="p-1.5 rounded hover:bg-slate-700 transition-colors text-[10px] text-slate-400" title="Export PNG">
            PNG
          </button>
          <div className="w-px h-4 bg-slate-700 mx-1" />
          <button onClick={() => { setIsFullscreen(!isFullscreen); setSelectedNode(null); }} className="p-1.5 rounded hover:bg-slate-700 transition-colors">
            {isFullscreen ? <X className="w-4 h-4 text-slate-400" /> : <Maximize2 className="w-4 h-4 text-slate-400" />}
          </button>
        </div>
      </div>

      {/* Canvas */}
      <div className={`relative ${isFullscreen ? 'flex-1' : 'h-[400px]'} overflow-hidden`}>
        <canvas
          ref={canvasRef}
          onClick={handleCanvasClick}
          className="w-full h-full cursor-crosshair"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center' }}
        />

        {/* Selected Node Details Panel */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-64 bg-slate-800/95 border border-slate-700/50 rounded-xl p-4 shadow-xl backdrop-blur-sm">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                {selectedNode.severity === 'critical' ? (
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                ) : selectedNode.severity === 'warning' ? (
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                ) : (
                  <CheckCircle className="w-4 h-4 text-green-400" />
                )}
                <span className="text-sm font-semibold text-white">{selectedNode.ip}</span>
              </div>
              <button onClick={() => setSelectedNode(null)} className="p-1 rounded hover:bg-slate-700">
                <X className="w-3.5 h-3.5 text-slate-400" />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-400">Type</span>
                <span className="text-slate-200 capitalize">{selectedNode.type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Traffic</span>
                <span className="text-slate-200">{(selectedNode.bytesTotal / 1024 / 1024).toFixed(1)} MB</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Status</span>
                <span className={`capitalize ${
                  selectedNode.severity === 'critical' ? 'text-red-400' :
                  selectedNode.severity === 'warning' ? 'text-amber-400' : 'text-green-400'
                }`}>
                  {selectedNode.severity}
                </span>
              </div>

              {selectedNode.issues.length > 0 && (
                <div className="pt-2 border-t border-slate-700/50">
                  <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Issues</span>
                  <ul className="mt-1 space-y-1">
                    {selectedNode.issues.map((issue, i) => (
                      <li key={i} className="flex items-center gap-1.5 text-red-300">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0" />
                        {issue}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-slate-800/90 border border-slate-700/50 rounded-lg px-3 py-2 backdrop-blur-sm">
          <div className="flex items-center gap-4 text-[10px]">
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
              <span className="text-slate-400">Healthy</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-slate-400">Warning</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span className="text-slate-400">Critical</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
