// AnalysisBadges — Wireshark-style TCP analysis flag badges.
//
// Renders colored pill badges for the four analysis flags attached to a
// Discrepancy: Retransmission, Duplicate ACK, Zero Window, Keep-Alive.
// Used in the Discrepancies Table and the Packet Dissector.
//
// Keep the rendered markup very small — these badges sit inside dense table
// rows where vertical space is scarce.

import type { Discrepancy } from '../types';
import { RefreshCw, Copy, MinusCircle, Heart } from 'lucide-react';

interface AnalysisBadgesProps {
  d: Discrepancy;
  /** When true, shows a tooltip explaining each badge. Defaults to true. */
  tooltips?: boolean;
  /** Compact mode renders icons only (no labels). Defaults to false. */
  compact?: boolean;
  /** Optional class appended to the outer container. */
  className?: string;
}

export function AnalysisBadges({
  d,
  tooltips = true,
  compact = false,
  className = '',
}: AnalysisBadgesProps) {
  const badges: Array<{
    key: string;
    label: string;
    icon: React.ReactNode;
    color: string;
    tooltip: string;
  }> = [];

  if (d.is_retransmission) {
    badges.push({
      key: 'retx',
      label: 'Retx',
      icon: <RefreshCw className="w-3 h-3" />,
      color: 'bg-red-500/15 text-red-400 border-red-500/40',
      tooltip:
        'Retransmission — the sender re-sent a segment that had already been transmitted. Usually indicates packet loss or delayed ACK.',
    });
  }
  if (d.is_duplicate_ack) {
    const n = d.duplicate_ack_count ?? 2;
    badges.push({
      key: 'dup-ack',
      label: `Dup ACK #${n}`,
      icon: <Copy className="w-3 h-3" />,
      color: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
      tooltip:
        `Duplicate ACK #${n} — the receiver re-sent the same ACK without progressing. Three or more duplicates triggers Fast Retransmit.`,
    });
  }
  if (d.is_zero_window) {
    badges.push({
      key: 'zw',
      label: 'Zero Win',
      icon: <MinusCircle className="w-3 h-3" />,
      color: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
      tooltip:
        'Zero Window — the receiver is advertising a window size of 0, meaning its receive buffer is full and the sender must stop sending data.',
    });
  }
  if (d.is_keep_alive) {
    badges.push({
      key: 'ka',
      label: 'Keep-Alive',
      icon: <Heart className="w-3 h-3" />,
      color: 'bg-purple-500/15 text-purple-400 border-purple-500/40',
      tooltip:
        'Keep-Alive — a probe segment sent on an idle connection to confirm the peer is still reachable. Seq = (next-expected − 1), payload ≤ 1 byte.',
    });
  }

  if (badges.length === 0) return null;

  return (
    <span className={`inline-flex items-center gap-1 flex-wrap ${className}`}>
      {badges.map(b => (
        <span
          key={b.key}
          title={tooltips ? b.tooltip : undefined}
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-medium ${b.color}`}
        >
          {b.icon}
          {!compact && <span>{b.label}</span>}
        </span>
      ))}
    </span>
  );
}
