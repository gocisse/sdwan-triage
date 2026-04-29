// useKeyboardNavigation.tsx — Global keyboard shortcuts for packet navigation (U3)
//
// Provides:
// - j/k or Arrow Up/Down: Navigate packet rows
// - Enter: Expand selected row / Open Dissector
// - Esc: Close modal
// - /: Focus filter input

import { useEffect, useCallback } from 'react';

export interface KeyboardNavigationOptions {
  /** Total number of navigable items */
  itemCount: number;
  /** Currently selected index */
  selectedIndex: number;
  /** Callback when selection changes */
  onSelectionChange: (index: number) => void;
  /** Callback when Enter is pressed on selected item */
  onEnter?: (index: number) => void;
  /** Callback when Escape is pressed */
  onEscape?: () => void;
  /** Ref to the filter input for / shortcut */
  filterInputRef?: React.RefObject<HTMLInputElement>;
  /** Whether navigation is enabled (disable when modal is open) */
  enabled?: boolean;
}

export function useKeyboardNavigation({
  itemCount,
  selectedIndex,
  onSelectionChange,
  onEnter,
  onEscape,
  filterInputRef,
  enabled = true,
}: KeyboardNavigationOptions) {
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (!enabled) return;
    
    // Don't capture if user is typing in an input/textarea
    const target = e.target as HTMLElement;
    const isInputFocused = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;
    
    // Allow Escape to work even in inputs
    if (e.key === 'Escape') {
      if (isInputFocused) {
        (target as HTMLInputElement).blur();
      }
      onEscape?.();
      return;
    }
    
    // / to focus filter (unless already in input)
    if (e.key === '/' && !isInputFocused) {
      e.preventDefault();
      filterInputRef?.current?.focus();
      return;
    }
    
    // Navigation keys only work when not in input
    if (isInputFocused) return;
    
    switch (e.key) {
      case 'j':
      case 'ArrowDown':
        e.preventDefault();
        if (itemCount > 0) {
          onSelectionChange(Math.min(selectedIndex + 1, itemCount - 1));
        }
        break;
        
      case 'k':
      case 'ArrowUp':
        e.preventDefault();
        if (itemCount > 0) {
          onSelectionChange(Math.max(selectedIndex - 1, 0));
        }
        break;
        
      case 'Enter':
        e.preventDefault();
        if (selectedIndex >= 0 && selectedIndex < itemCount) {
          onEnter?.(selectedIndex);
        }
        break;
        
      case 'g':
        // gg to go to top (vim-style)
        if (e.repeat) return;
        e.preventDefault();
        onSelectionChange(0);
        break;
        
      case 'G':
        // G to go to bottom
        e.preventDefault();
        onSelectionChange(Math.max(0, itemCount - 1));
        break;
    }
  }, [enabled, itemCount, selectedIndex, onSelectionChange, onEnter, onEscape, filterInputRef]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return { selectedIndex };
}

// ─── Packet Colorization Utilities (U2) ───────────────────────────

export interface PacketColorInfo {
  rowClass: string;
  cellClass: string;
  priority: number; // Higher = more important (used when multiple conditions match)
}

export interface ColorablePacket {
  tcp_flags?: string;
  is_retransmission?: boolean;
  is_duplicate_ack?: boolean;
  is_zero_window?: boolean;
  is_keep_alive?: boolean;
  state?: string;
}

/**
 * Returns CSS classes for packet row colorization based on packet characteristics.
 * Priority order (highest to lowest):
 * 1. RST packets (red)
 * 2. SYN drops (cyan)
 * 3. FIN packets (purple)
 * 4. Retransmissions (orange)
 * 5. Duplicate ACKs (yellow)
 * 6. Zero window (amber)
 * 7. Keep-alive (slate)
 */
export function getPacketRowColor(packet: ColorablePacket): PacketColorInfo {
  const flags = packet.tcp_flags?.toUpperCase() || '';
  
  // RST packets — highest priority, indicates connection reset
  if (flags.includes('RST')) {
    return {
      rowClass: 'bg-red-900/30 hover:bg-red-900/40 border-l-2 border-red-500',
      cellClass: '',
      priority: 100,
    };
  }
  
  // SYN drops — policy blocks, very important
  if (packet.state === 'MISSING_B' && flags.includes('SYN') && !flags.includes('ACK')) {
    return {
      rowClass: 'bg-cyan-900/30 hover:bg-cyan-900/40 border-l-2 border-cyan-500',
      cellClass: '',
      priority: 95,
    };
  }
  
  // FIN packets — connection termination
  if (flags.includes('FIN')) {
    return {
      rowClass: 'bg-purple-900/20 hover:bg-purple-900/30 border-l-2 border-purple-500',
      cellClass: '',
      priority: 80,
    };
  }
  
  // Retransmissions — network issues
  if (packet.is_retransmission) {
    return {
      rowClass: 'bg-orange-900/25 hover:bg-orange-900/35 border-l-2 border-orange-500',
      cellClass: '',
      priority: 70,
    };
  }
  
  // Duplicate ACKs — potential packet loss
  if (packet.is_duplicate_ack) {
    return {
      rowClass: 'bg-yellow-900/20 hover:bg-yellow-900/30 border-l-2 border-yellow-500',
      cellClass: '',
      priority: 60,
    };
  }
  
  // Zero window — receiver buffer full
  if (packet.is_zero_window) {
    return {
      rowClass: 'bg-amber-900/20 hover:bg-amber-900/30 border-l-2 border-amber-500',
      cellClass: '',
      priority: 50,
    };
  }
  
  // Keep-alive — informational
  if (packet.is_keep_alive) {
    return {
      rowClass: 'bg-slate-700/30 hover:bg-slate-700/40 border-l-2 border-slate-500',
      cellClass: '',
      priority: 20,
    };
  }
  
  // Default — no special coloring
  return {
    rowClass: 'hover:bg-slate-700/20',
    cellClass: '',
    priority: 0,
  };
}

/**
 * Returns a color legend for the packet table
 */
export const PACKET_COLOR_LEGEND = [
  { color: 'bg-red-500', label: 'RST', description: 'Connection reset' },
  { color: 'bg-cyan-500', label: 'SYN Drop', description: 'Blocked connection attempt' },
  { color: 'bg-purple-500', label: 'FIN', description: 'Connection close' },
  { color: 'bg-orange-500', label: 'Retransmission', description: 'Packet resent' },
  { color: 'bg-yellow-500', label: 'Dup ACK', description: 'Duplicate acknowledgment' },
  { color: 'bg-amber-500', label: 'Zero Window', description: 'Receiver buffer full' },
];

// ─── Color Legend Component ───────────────────────────────────────

export function PacketColorLegend({ className = '' }: { className?: string }) {
  return (
    <div className={`flex items-center gap-3 flex-wrap text-[10px] ${className}`}>
      <span className="text-slate-500">Colors:</span>
      {PACKET_COLOR_LEGEND.map(item => (
        <div key={item.label} className="flex items-center gap-1" title={item.description}>
          <div className={`w-2 h-2 rounded-sm ${item.color}`} />
          <span className="text-slate-400">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
