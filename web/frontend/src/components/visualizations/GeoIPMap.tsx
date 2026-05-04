import { useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import type { GeoIPDetail } from '../../types';

interface GeoIPMapProps {
  details: GeoIPDetail[];
}

/** Cluster nearby IPs by rounding lat/lng to 1 decimal place */
interface ClusterPoint {
  lat: number;
  lng: number;
  ips: GeoIPDetail[];
}

export function GeoIPMap({ details }: GeoIPMapProps) {
  const clusters = useMemo(() => {
    const map = new Map<string, ClusterPoint>();
    for (const d of details) {
      const key = `${d.latitude.toFixed(1)},${d.longitude.toFixed(1)}`;
      const existing = map.get(key);
      if (existing) {
        existing.ips.push(d);
      } else {
        map.set(key, { lat: d.latitude, lng: d.longitude, ips: [d] });
      }
    }
    return Array.from(map.values());
  }, [details]);

  if (details.length === 0) {
    return (
      <div className="rounded-xl border border-slate-700/50 bg-slate-800/60 p-6 text-center text-slate-400 text-sm">
        No GeoIP data available. Install a MaxMind GeoLite2 database for IP geolocation.
      </div>
    );
  }

  // Compute center from the average of all points
  const center = useMemo(() => {
    const avgLat = details.reduce((s, d) => s + d.latitude, 0) / details.length;
    const avgLng = details.reduce((s, d) => s + d.longitude, 0) / details.length;
    return [avgLat, avgLng] as [number, number];
  }, [details]);

  return (
    <div className="rounded-xl border border-slate-700/50 bg-slate-800/60 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">GeoIP Traffic Map</h3>
        <span className="text-xs text-slate-400">
          {details.length} public IP{details.length !== 1 ? 's' : ''} mapped
        </span>
      </div>
      <div style={{ height: 420 }}>
        <MapContainer
          center={center}
          zoom={2}
          scrollWheelZoom={true}
          style={{ height: '100%', width: '100%', background: '#0f172a' }}
        >
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          />
          {clusters.map((cluster, i) => {
            const radius = Math.min(6 + cluster.ips.length * 2, 20);
            return (
              <CircleMarker
                key={i}
                center={[cluster.lat, cluster.lng]}
                radius={radius}
                pathOptions={{
                  color: '#3b82f6',
                  fillColor: '#3b82f6',
                  fillOpacity: 0.5,
                  weight: 1,
                }}
              >
                <Popup>
                  <div className="text-xs space-y-1 max-h-40 overflow-y-auto">
                    <div className="font-semibold text-slate-800">
                      {cluster.ips[0].city
                        ? `${cluster.ips[0].city}, ${cluster.ips[0].country}`
                        : cluster.ips[0].country}
                    </div>
                    <div className="text-slate-600">
                      {cluster.ips.length} IP{cluster.ips.length !== 1 ? 's' : ''}
                    </div>
                    {cluster.ips.slice(0, 10).map((ip) => (
                      <div key={ip.ip} className="font-mono text-slate-700">
                        {ip.ip}
                      </div>
                    ))}
                    {cluster.ips.length > 10 && (
                      <div className="text-slate-500">
                        +{cluster.ips.length - 10} more
                      </div>
                    )}
                  </div>
                </Popup>
              </CircleMarker>
            );
          })}
        </MapContainer>
      </div>
    </div>
  );
}
