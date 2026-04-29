import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';

// FilterContext — shared filter-text state that bridges the FilterBuilder
// scratchpad with the rest of the Comparison view (Discrepancies table,
// Packet Dissector, etc.).
//
// Previously the scratchpad owned its own local `filterText` state and had
// no way to receive filters from elsewhere. With this context:
//
//   • Right-click → "Apply as Filter"  →  filterContext.applyAsFilter(...)
//                   replaces the scratchpad with a fresh "field == value".
//   • Right-click → "...and Filter"    →  filterContext.appendFilter(...)
//                   appends " && field == value".
//   • Right-click → "Copy Value"       →  navigator.clipboard.writeText(...)
//                   (handled by the context menu itself — no state change).
//
// Consumers call useFilterContext() to access the filter string and helper
// setters. If no provider is mounted (e.g. component used in isolation),
// the hook returns a no-op fallback so components still render without
// throwing.

interface FilterContextValue {
  /** Current scratchpad filter text (controlled). */
  filterText: string;
  /** Replace the scratchpad text wholesale. */
  setFilterText: (next: string) => void;
  /** Replace the scratchpad with `field == value` (overwriting prior content). */
  applyAsFilter: (field: string, value: string | number) => void;
  /** Append ` && field == value` to the current scratchpad. If empty, acts like applyAsFilter. */
  appendFilter: (field: string, value: string | number) => void;
}

const noop = () => {};

const defaultValue: FilterContextValue = {
  filterText: '',
  setFilterText: noop,
  applyAsFilter: noop,
  appendFilter: noop,
};

const FilterContext = createContext<FilterContextValue>(defaultValue);

/**
 * useFilterContext — hook for consumers of the filter-bridge.
 * Safe to call outside a provider: returns no-op defaults.
 */
export function useFilterContext(): FilterContextValue {
  return useContext(FilterContext);
}

/**
 * FilterProvider — wrap the comparison view (or any subtree) with this to
 * enable the right-click → filter workflow.
 */
export const FilterProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [filterText, setFilterText] = useState('');

  const applyAsFilter = useCallback((field: string, value: string | number) => {
    setFilterText(formatClause(field, value));
  }, []);

  const appendFilter = useCallback((field: string, value: string | number) => {
    setFilterText(prev => {
      const trimmed = prev.trim();
      const clause = formatClause(field, value);
      return trimmed.length === 0 ? clause : `${trimmed} && ${clause}`;
    });
  }, []);

  const ctx = useMemo<FilterContextValue>(
    () => ({ filterText, setFilterText, applyAsFilter, appendFilter }),
    [filterText, applyAsFilter, appendFilter],
  );

  return <FilterContext.Provider value={ctx}>{children}</FilterContext.Provider>;
};

// formatClause produces the scratchpad-friendly equality expression used by
// our Wireshark-lite filter parser. Strings are quoted; numbers are left
// bare so they look like genuine numeric comparisons.
function formatClause(field: string, value: string | number): string {
  if (typeof value === 'number') {
    return `${field} == ${value}`;
  }
  // IP addresses, MAC addresses, protocol names etc. are bare tokens in
  // Wireshark's display-filter grammar; quoting them would break parsing.
  if (isBareToken(value)) {
    return `${field} == ${value}`;
  }
  // Everything else gets quoted.
  return `${field} == "${value.replace(/"/g, '\\"')}"`;
}

// isBareToken returns true when the value can appear unquoted in a filter
// expression — IPv4 addresses, IPv6 addresses, hex bytes, MACs, protocol
// names, etc. The parser tolerates these without quotes, so skipping the
// quotes keeps the UI visually identical to Wireshark.
function isBareToken(s: string): boolean {
  // Empty strings must be quoted.
  if (s.length === 0) return false;
  // Pure identifier (e.g. "TCP", "MISSING_B").
  if (/^[A-Za-z][A-Za-z0-9_]*$/.test(s)) return true;
  // IPv4 or IPv4 with CIDR.
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true;
  // IPv6 — generous match that covers compressed forms.
  if (/^[0-9a-fA-F:]+$/.test(s) && s.includes(':')) return true;
  // MAC address.
  if (/^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(s)) return true;
  return false;
}
