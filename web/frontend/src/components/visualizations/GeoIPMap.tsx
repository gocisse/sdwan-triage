import { useMemo, useState, useEffect } from 'react';  // useEffect used by FitBounds
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup, Tooltip, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import type { GeoIPDetail, TrafficFlow, TimelineEvent } from '../../types';
import { Globe, ArrowRight, MapPin } from 'lucide-react';
import { useTimeRangeOptional } from '../../contexts/TimeRangeContext';

// ─── Props ──────────────────────────────────────────────────────

interface GeoIPMapProps {
  details: GeoIPDetail[];
  trafficFlows?: TrafficFlow[];
  timeline?: TimelineEvent[];
}

// ─── Internal Types ─────────────────────────────────────────────

type IPRole = 'source' | 'destination' | 'both';

interface MarkerPoint {
  ip: string;
  lat: number;
  lng: number;
  country: string;
  countryCode: string;
  city?: string;
  role: IPRole;
  packetCount: number;
  byteCount: number;
}

interface ArcLine {
  srcIp: string;
  dstIp: string;
  srcLat: number;
  srcLng: number;
  dstLat: number;
  dstLng: number;
  srcLabel: string;
  dstLabel: string;
  totalBytes: number;
  flowCount: number;
}

// ─── Helpers ────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function locationLabel(d: GeoIPDetail | MarkerPoint): string {
  return d.city ? `${d.city}, ${d.country}` : d.country || 'Unknown';
}

/** Generate N intermediate points along a great-circle arc for smooth curves */
function greatCircleArc(
  lat1: number, lng1: number,
  lat2: number, lng2: number,
  segments: number = 30,
): [number, number][] {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const toDeg = (r: number) => (r * 180) / Math.PI;

  const phi1 = toRad(lat1);
  const lam1 = toRad(lng1);
  const phi2 = toRad(lat2);
  const lam2 = toRad(lng2);

  const d = 2 * Math.asin(
    Math.sqrt(
      Math.pow(Math.sin((phi1 - phi2) / 2), 2) +
      Math.cos(phi1) * Math.cos(phi2) * Math.pow(Math.sin((lam1 - lam2) / 2), 2),
    ),
  );

  if (d < 1e-10) return [[lat1, lng1], [lat2, lng2]];

  const points: [number, number][] = [];
  for (let i = 0; i <= segments; i++) {
    const f = i / segments;
    const A = Math.sin((1 - f) * d) / Math.sin(d);
    const B = Math.sin(f * d) / Math.sin(d);
    const x = A * Math.cos(phi1) * Math.cos(lam1) + B * Math.cos(phi2) * Math.cos(lam2);
    const y = A * Math.cos(phi1) * Math.sin(lam1) + B * Math.cos(phi2) * Math.sin(lam2);
    const z = A * Math.sin(phi1) + B * Math.sin(phi2);
    points.push([toDeg(Math.atan2(z, Math.sqrt(x * x + y * y))), toDeg(Math.atan2(y, x))]);
  }
  return points;
}

/** Color scale: bytes → opacity (more traffic = more opaque) */
function arcOpacity(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0) return 0.4;
  return 0.2 + 0.6 * Math.sqrt(bytes / maxBytes);
}

function arcWeight(bytes: number, maxBytes: number): number {
  if (maxBytes <= 0) return 1.5;
  return 1.5 + 3 * Math.sqrt(bytes / maxBytes);
}

const SRC_COLOR = '#22c55e';  // green-500
const DST_COLOR = '#ef4444';  // red-500
const BOTH_COLOR = '#f59e0b'; // amber-500
const ARC_COLOR = '#818cf8';  // indigo-400

// ─── Auto-Fit Bounds Component ──────────────────────────────────

function FitBounds({ markers }: { markers: MarkerPoint[] }) {
  const map = useMap();

  useEffect(() => {
    if (markers.length === 0) return;
    if (markers.length === 1) {
      map.setView([markers[0].lat, markers[0].lng], 5);
      return;
    }
    const lats = markers.map(m => m.lat);
    const lngs = markers.map(m => m.lng);
    map.fitBounds(
      [[Math.min(...lats), Math.min(...lngs)], [Math.max(...lats), Math.max(...lngs)]],
      { padding: [40, 40], maxZoom: 8 },
    );
  }, [markers, map]);

  return null;
}

// ─── Main Component ─────────────────────────────────────────────

export function GeoIPMap({ details, trafficFlows, timeline }: GeoIPMapProps) {
  const [selectedArc, setSelectedArc] = useState<ArcLine | null>(null);
  const timeCtx = useTimeRangeOptional();

  // When a time range is active, filter to only IPs that appear in timeline events within the range
  const activeIps = useMemo(() => {
    if (!timeCtx?.isTimeFiltered || !timeline || timeline.length === 0) return null; // null = show all
    const { start, end } = timeCtx.timeRange;
    const ips = new Set<string>();
    for (const ev of timeline) {
      const ts = new Date(ev.timestamp).getTime() / 1000;
      if (!ts || !isFinite(ts)) continue;
      if (ts >= start && ts <= end) {
        if (ev.source_ip) ips.add(ev.source_ip);
        if (ev.dest_ip) ips.add(ev.dest_ip);
      }
    }
    return ips;
  }, [timeCtx?.isTimeFiltered, timeCtx?.timeRange, timeline]);

  // Filter details and flows by active IPs when time-filtered
  const filteredDetails = useMemo(() => {
    if (!activeIps) return details;
    return details.filter(d => activeIps.has(d.ip));
  }, [details, activeIps]);

  const filteredFlows = useMemo(() => {
    if (!activeIps || !trafficFlows) return trafficFlows;
    return trafficFlows.filter(f => activeIps.has(f.src_ip) || activeIps.has(f.dst_ip));
  }, [trafficFlows, activeIps]);

  // Build IP → GeoIPDetail lookup
  const ipGeoMap = useMemo(() => {
    const m = new Map<string, GeoIPDetail>();
    for (const d of filteredDetails) {
      if (d.latitude !== 0 || d.longitude !== 0) {
        m.set(d.ip, d);
      }
    }
    return m;
  }, [filteredDetails]);

  // Classify IPs as source/destination using traffic flows
  const { markers, arcs, countryStats } = useMemo(() => {
    const srcIps = new Set<string>();
    const dstIps = new Set<string>();
    const ipBytes = new Map<string, number>();
    // Accumulate per-IP traffic from flows
    const arcMap = new Map<string, ArcLine>();

    if (filteredFlows && filteredFlows.length > 0) {
      for (const flow of filteredFlows) {
        srcIps.add(flow.src_ip);
        dstIps.add(flow.dst_ip);
        ipBytes.set(flow.src_ip, (ipBytes.get(flow.src_ip) ?? 0) + flow.total_bytes);
        ipBytes.set(flow.dst_ip, (ipBytes.get(flow.dst_ip) ?? 0) + flow.total_bytes);

        // Build arcs between geolocated IP pairs
        const srcGeo = ipGeoMap.get(flow.src_ip);
        const dstGeo = ipGeoMap.get(flow.dst_ip);
        if (srcGeo && dstGeo && srcGeo.ip !== dstGeo.ip) {
          // Normalize arc key so A→B and B→A merge
          const key = [flow.src_ip, flow.dst_ip].sort().join('↔');
          const existing = arcMap.get(key);
          if (existing) {
            existing.totalBytes += flow.total_bytes;
            existing.flowCount += 1;
          } else {
            arcMap.set(key, {
              srcIp: flow.src_ip,
              dstIp: flow.dst_ip,
              srcLat: srcGeo.latitude,
              srcLng: srcGeo.longitude,
              dstLat: dstGeo.latitude,
              dstLng: dstGeo.longitude,
              srcLabel: locationLabel(srcGeo),
              dstLabel: locationLabel(dstGeo),
              totalBytes: flow.total_bytes,
              flowCount: 1,
            });
          }
        }
      }
    }

    // Build markers from all geolocated IPs
    const markerList: MarkerPoint[] = [];
    for (const d of filteredDetails) {
      if (d.latitude === 0 && d.longitude === 0) continue;
      const isSrc = srcIps.has(d.ip);
      const isDst = dstIps.has(d.ip);
      const role: IPRole = isSrc && isDst ? 'both' : isSrc ? 'source' : isDst ? 'destination' : 'both';
      markerList.push({
        ip: d.ip,
        lat: d.latitude,
        lng: d.longitude,
        country: d.country,
        countryCode: d.country_code,
        city: d.city,
        role,
        byteCount: ipBytes.get(d.ip) ?? 0,
        packetCount: 0, // Packet count not directly available per-IP; leave 0
      });
    }

    // Country stats for sidebar
    const cStats = new Map<string, { country: string; code: string; ips: number; bytes: number }>();
    for (const m of markerList) {
      const key = m.countryCode || m.country;
      const existing = cStats.get(key);
      if (existing) {
        existing.ips += 1;
        existing.bytes += m.byteCount;
      } else {
        cStats.set(key, { country: m.country, code: m.countryCode, ips: 1, bytes: m.byteCount });
      }
    }

    return {
      markers: markerList,
      arcs: Array.from(arcMap.values()),
      countryStats: Array.from(cStats.values()).sort((a, b) => b.bytes - a.bytes),
    };
  }, [filteredDetails, filteredFlows, ipGeoMap]);

  const maxArcBytes = useMemo(() => Math.max(...arcs.map(a => a.totalBytes), 1), [arcs]);

  // ─── Empty State ──────────────────────────────────────────────

  if (filteredDetails.length === 0) {
    const isTimeFiltered = timeCtx?.isTimeFiltered && details.length > 0;
    return (
      <div className="rounded-xl border border-slate-700/50 bg-slate-800/60 p-8 text-center">
        <Globe className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 className="text-sm font-semibold text-slate-300 mb-1">
          {isTimeFiltered ? 'No GeoIP Data in Selected Time Range' : 'No GeoIP Data Available'}
        </h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          {isTimeFiltered
            ? 'Adjust the timeline scrubber or press Esc to reset the time range.'
            : <>Install a MaxMind GeoLite2 database (GeoLite2-City.mmdb) for automatic IP geolocation. Place it in <code className="text-slate-400">./data/</code> or <code className="text-slate-400">/usr/share/GeoIP/</code>.</>
          }
        </p>
      </div>
    );
  }

  // ─── Render ───────────────────────────────────────────────────

  const validMarkers = markers.filter(m => !(m.lat === 0 && m.lng === 0));

  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/60 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-white">GeoIP Traffic Map</h3>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span>{validMarkers.length} IP{validMarkers.length !== 1 ? 's' : ''}</span>
          {arcs.length > 0 && (
            <span>{arcs.length} traffic flow{arcs.length !== 1 ? 's' : ''}</span>
          )}
        </div>
      </div>

      <div className="flex">
        {/* Map */}
        <div className="flex-1" style={{ height: 480 }}>
          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom={true}
            style={{ height: '100%', width: '100%', background: '#0f172a' }}
          >
            <TileLayer
              attribution='&copy; <a href="https://carto.com/">CARTO</a>'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            />

            <FitBounds markers={validMarkers} />

            {/* Great-circle arc lines */}
            {arcs.map((arc, i) => {
              const positions = greatCircleArc(arc.srcLat, arc.srcLng, arc.dstLat, arc.dstLng);
              const isSelected = selectedArc?.srcIp === arc.srcIp && selectedArc?.dstIp === arc.dstIp;
              return (
                <Polyline
                  key={`arc-${i}`}
                  positions={positions}
                  pathOptions={{
                    color: isSelected ? '#c084fc' : ARC_COLOR,
                    weight: isSelected ? arcWeight(arc.totalBytes, maxArcBytes) + 1 : arcWeight(arc.totalBytes, maxArcBytes),
                    opacity: isSelected ? 0.9 : arcOpacity(arc.totalBytes, maxArcBytes),
                    dashArray: undefined,
                    lineCap: 'round',
                    lineJoin: 'round',
                  }}
                  eventHandlers={{
                    click: () => setSelectedArc(isSelected ? null : arc),
                  }}
                >
                  <Tooltip sticky>
                    <div className="text-xs space-y-0.5 min-w-[160px]">
                      <div className="font-semibold text-slate-800">{arc.srcLabel} → {arc.dstLabel}</div>
                      <div className="text-slate-600 font-mono">{arc.srcIp} → {arc.dstIp}</div>
                      <div className="text-slate-500">{formatBytes(arc.totalBytes)} across {arc.flowCount} flow{arc.flowCount !== 1 ? 's' : ''}</div>
                    </div>
                  </Tooltip>
                </Polyline>
              );
            })}

            {/* IP markers */}
            {validMarkers.map((m) => {
              const color = m.role === 'source' ? SRC_COLOR : m.role === 'destination' ? DST_COLOR : BOTH_COLOR;
              const radius = Math.min(5 + Math.sqrt(m.byteCount / 1024) * 0.3, 18);
              return (
                <CircleMarker
                  key={m.ip}
                  center={[m.lat, m.lng]}
                  radius={radius}
                  pathOptions={{
                    color,
                    fillColor: color,
                    fillOpacity: 0.6,
                    weight: 1.5,
                  }}
                >
                  <Tooltip>
                    <div className="text-xs space-y-0.5">
                      <div className="font-semibold text-slate-800">{m.ip}</div>
                      <div className="text-slate-600">{locationLabel(m)}</div>
                      <div className="text-slate-500">
                        {m.role === 'source' ? 'Source' : m.role === 'destination' ? 'Destination' : 'Source & Destination'}
                        {m.byteCount > 0 && ` · ${formatBytes(m.byteCount)}`}
                      </div>
                    </div>
                  </Tooltip>
                  <Popup>
                    <div className="text-xs space-y-1">
                      <div className="font-bold text-slate-800">{m.ip}</div>
                      <div className="text-slate-600">{locationLabel(m)}</div>
                      <div className="text-slate-500">
                        Role: {m.role === 'source' ? 'Source' : m.role === 'destination' ? 'Destination' : 'Both'}
                      </div>
                      {m.byteCount > 0 && (
                        <div className="text-slate-500">Traffic: {formatBytes(m.byteCount)}</div>
                      )}
                      {m.countryCode && (
                        <div className="text-slate-500">Country Code: {m.countryCode}</div>
                      )}
                    </div>
                  </Popup>
                </CircleMarker>
              );
            })}
          </MapContainer>
        </div>

        {/* Sidebar — Legend + Country Stats */}
        <div className="w-56 border-l border-slate-700/50 bg-slate-900/50 flex flex-col" style={{ height: 480 }}>
          {/* Legend */}
          <div className="px-3 py-2.5 border-b border-slate-700/30 space-y-1.5">
            <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Legend</div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: SRC_COLOR }} />
              Source IP
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: DST_COLOR }} />
              Destination IP
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: BOTH_COLOR }} />
              Both (src & dst)
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-5 h-0.5 rounded" style={{ background: ARC_COLOR }} />
              Traffic flow
            </div>
          </div>

          {/* Country breakdown */}
          <div className="flex-1 overflow-y-auto px-3 py-2.5 space-y-1.5">
            <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1">
              Countries ({countryStats.length})
            </div>
            {countryStats.map((cs) => (
              <div key={cs.code || cs.country} className="flex items-center justify-between py-1 border-b border-slate-800/50 last:border-0">
                <div className="flex items-center gap-1.5 min-w-0">
                  <MapPin className="w-3 h-3 text-slate-600 shrink-0" />
                  <span className="text-xs text-slate-300 truncate">{cs.country || cs.code}</span>
                </div>
                <div className="text-right shrink-0 ml-2">
                  <div className="text-[10px] text-slate-500">{cs.ips} IP{cs.ips !== 1 ? 's' : ''}</div>
                  {cs.bytes > 0 && (
                    <div className="text-[10px] text-slate-600">{formatBytes(cs.bytes)}</div>
                  )}
                </div>
              </div>
            ))}
            {countryStats.length === 0 && (
              <div className="text-xs text-slate-600 text-center py-4">No country data</div>
            )}
          </div>

          {/* Selected arc detail */}
          {selectedArc && (
            <div className="px-3 py-2.5 border-t border-slate-700/30 bg-indigo-500/5">
              <div className="text-[10px] font-semibold text-indigo-400 uppercase tracking-wider mb-1">Selected Flow</div>
              <div className="text-xs text-slate-300 flex items-center gap-1">
                <span className="font-mono truncate">{selectedArc.srcIp}</span>
                <ArrowRight className="w-3 h-3 text-slate-500 shrink-0" />
                <span className="font-mono truncate">{selectedArc.dstIp}</span>
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">
                {selectedArc.srcLabel} → {selectedArc.dstLabel}
              </div>
              <div className="text-[10px] text-slate-500">
                {formatBytes(selectedArc.totalBytes)} · {selectedArc.flowCount} flow{selectedArc.flowCount !== 1 ? 's' : ''}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
