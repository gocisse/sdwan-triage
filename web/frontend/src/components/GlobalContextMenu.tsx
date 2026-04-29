import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Filter, Plus, Copy, Check } from 'lucide-react';
import { useFilterContext } from './FilterContext';

// GlobalContextMenu — Wireshark-style right-click menu with three actions:
//
//   "Apply as Filter"       Replace scratchpad with `field == value`.
//   "…and Filter"           Append ` && field == value` to scratchpad.
//   "Copy Value"            Copy the raw value to the clipboard.
//
// Usage:
//
//   <GlobalContextMenuProvider>           // mount once at comparison view root
//     ...
//   </GlobalContextMenuProvider>
//
//   const { onContextMenu } = useContextMenu();
//
//   <span onContextMenu={onContextMenu({ field: 'ip.src', value: d.src_ip })}>
//     {d.src_ip}
//   </span>
//
// The provider owns a single floating menu that positions itself at the
// pointer. Close-on-outside-click and Escape-key dismissal are handled
// automatically.

export interface ContextMenuTarget {
  /** Wireshark-style field name (e.g. `ip.src`, `tcp.dstport`). */
  field: string;
  /** The displayed value — used verbatim for both "Copy" and filter construction. */
  value: string | number;
  /** Optional label shown in the header of the menu; defaults to the field name. */
  label?: string;
}

interface ContextMenuState {
  x: number;
  y: number;
  target: ContextMenuTarget;
}

interface ContextMenuControls {
  /**
   * Returns a React onContextMenu handler that opens the global menu at
   * the pointer for the provided target. Example:
   *
   *   <td onContextMenu={onContextMenu({ field: 'ip.src', value: row.src_ip })}>
   */
  onContextMenu: (target: ContextMenuTarget) => React.MouseEventHandler;
  /** Imperatively open the menu (useful for keyboard-driven opens). */
  open: (ev: React.MouseEvent | { clientX: number; clientY: number }, target: ContextMenuTarget) => void;
  /** Close the menu programmatically. */
  close: () => void;
}

const noopHandler: React.MouseEventHandler = () => {};

const defaultControls: ContextMenuControls = {
  onContextMenu: () => noopHandler,
  open: () => {},
  close: () => {},
};

const ContextMenuContext = createContext<ContextMenuControls>(defaultControls);

/**
 * useContextMenu — opens the shared right-click menu. Safe outside the
 * provider: returns no-op handlers.
 */
export function useContextMenu(): ContextMenuControls {
  return useContext(ContextMenuContext);
}

/**
 * GlobalContextMenuProvider — must wrap any subtree that wants to use
 * useContextMenu(). Typically mounted once near the top of ComparisonView.
 * The provider also requires an enclosing FilterProvider so the menu can
 * dispatch filter updates.
 */
export const GlobalContextMenuProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<ContextMenuState | null>(null);

  const close = useCallback(() => setState(null), []);

  const open = useCallback((ev: React.MouseEvent | { clientX: number; clientY: number }, target: ContextMenuTarget) => {
    if ('preventDefault' in ev) {
      ev.preventDefault();
    }
    setState({ x: ev.clientX, y: ev.clientY, target });
  }, []);

  const onContextMenu = useCallback(
    (target: ContextMenuTarget): React.MouseEventHandler =>
      ev => {
        ev.preventDefault();
        ev.stopPropagation();
        setState({ x: ev.clientX, y: ev.clientY, target });
      },
    [],
  );

  // Close on Escape / window blur so we never get a stuck menu.
  useEffect(() => {
    if (!state) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('blur', close);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('blur', close);
    };
  }, [state, close]);

  const controls = useMemo<ContextMenuControls>(
    () => ({ onContextMenu, open, close }),
    [onContextMenu, open, close],
  );

  return (
    <ContextMenuContext.Provider value={controls}>
      {children}
      {state && <ContextMenuPopover state={state} onClose={close} />}
    </ContextMenuContext.Provider>
  );
};

// ─── Popover ────────────────────────────────────────────────────────

const MENU_WIDTH = 220;
const MENU_HEIGHT = 150; // used only for edge-of-screen clamping

const ContextMenuPopover: React.FC<{ state: ContextMenuState; onClose: () => void }> = ({ state, onClose }) => {
  const ref = useRef<HTMLDivElement>(null);
  const { applyAsFilter, appendFilter } = useFilterContext();
  const [copied, setCopied] = useState(false);

  // Close when the user clicks anywhere outside the menu.
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    };
    // Listen on the next tick to avoid instantly closing from the same
    // contextmenu event that opened us.
    const id = window.setTimeout(() => document.addEventListener('mousedown', onDown), 0);
    return () => {
      window.clearTimeout(id);
      document.removeEventListener('mousedown', onDown);
    };
  }, [onClose]);

  // Clamp to viewport so the menu never clips off-screen.
  const clampedX = Math.min(state.x, window.innerWidth - MENU_WIDTH - 8);
  const clampedY = Math.min(state.y, window.innerHeight - MENU_HEIGHT - 8);

  const { field, value, label } = state.target;

  const handleApply = () => {
    applyAsFilter(field, value);
    onClose();
  };
  const handleAppend = () => {
    appendFilter(field, value);
    onClose();
  };
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(String(value));
      setCopied(true);
      window.setTimeout(() => {
        setCopied(false);
        onClose();
      }, 600);
    } catch {
      onClose();
    }
  };

  return (
    <div
      ref={ref}
      role="menu"
      style={{
        position: 'fixed',
        top: clampedY,
        left: clampedX,
        width: MENU_WIDTH,
        zIndex: 10000,
      }}
      className="bg-slate-900 border border-slate-700 rounded-lg shadow-2xl overflow-hidden text-xs"
      // Prevent a browser native context menu on top of our own.
      onContextMenu={e => e.preventDefault()}
    >
      <div className="px-3 py-2 border-b border-slate-700/70 bg-slate-800/80">
        <div className="text-[10px] uppercase tracking-wide text-slate-500">
          {label ?? field}
        </div>
        <div className="text-slate-200 font-mono truncate" title={String(value)}>
          {String(value)}
        </div>
      </div>
      <button
        role="menuitem"
        onClick={handleApply}
        className="w-full px-3 py-2 text-left flex items-center gap-2 text-slate-300 hover:bg-slate-700/60 transition-colors"
      >
        <Filter className="w-3.5 h-3.5 text-cyan-400" />
        <span>Apply as Filter</span>
      </button>
      <button
        role="menuitem"
        onClick={handleAppend}
        className="w-full px-3 py-2 text-left flex items-center gap-2 text-slate-300 hover:bg-slate-700/60 transition-colors"
      >
        <Plus className="w-3.5 h-3.5 text-cyan-400" />
        <span>…and Filter (append)</span>
      </button>
      <button
        role="menuitem"
        onClick={handleCopy}
        className="w-full px-3 py-2 text-left flex items-center gap-2 text-slate-300 hover:bg-slate-700/60 transition-colors border-t border-slate-700/50"
      >
        {copied ? (
          <Check className="w-3.5 h-3.5 text-green-400" />
        ) : (
          <Copy className="w-3.5 h-3.5 text-slate-400" />
        )}
        <span>{copied ? 'Copied!' : 'Copy Value'}</span>
      </button>
    </div>
  );
};

export default GlobalContextMenuProvider;
