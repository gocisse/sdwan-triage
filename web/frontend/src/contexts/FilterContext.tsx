// FilterContext — Global IP/port/protocol filter state for the Results Page.
// Equivalent of CLI flags: -src-ip, -dst-ip, -port, -protocol

import { createContext, useContext, useState, useCallback, useMemo } from 'react';
import type { ReactNode } from 'react';

export interface GlobalFilters {
  srcIP: string;
  dstIP: string;
  port: string;
  protocol: 'all' | 'tcp' | 'udp';
}

export interface FilterContextValue {
  /** Current filter values (may not yet be applied) */
  draft: GlobalFilters;
  /** Currently applied filters */
  filters: GlobalFilters;
  /** Whether any filter is active */
  isActive: boolean;
  /** Update a draft field */
  setDraftField: (field: keyof GlobalFilters, value: string) => void;
  /** Apply current draft as active filters */
  applyFilters: () => void;
  /** Clear all filters */
  clearFilters: () => void;
}

const EMPTY_FILTERS: GlobalFilters = { srcIP: '', dstIP: '', port: '', protocol: 'all' };

const FilterContext = createContext<FilterContextValue | null>(null);

export function useGlobalFilter(): FilterContextValue {
  const ctx = useContext(FilterContext);
  if (!ctx) throw new Error('useGlobalFilter must be used within a FilterProvider');
  return ctx;
}

export function useGlobalFilterOptional(): FilterContextValue | null {
  return useContext(FilterContext);
}

interface FilterProviderProps {
  children: ReactNode;
}

export function FilterProvider({ children }: FilterProviderProps) {
  const [draft, setDraft] = useState<GlobalFilters>({ ...EMPTY_FILTERS });
  const [filters, setFilters] = useState<GlobalFilters>({ ...EMPTY_FILTERS });

  const isActive = useMemo(
    () => filters.srcIP !== '' || filters.dstIP !== '' || filters.port !== '' || filters.protocol !== 'all',
    [filters]
  );

  const setDraftField = useCallback((field: keyof GlobalFilters, value: string) => {
    setDraft(prev => ({ ...prev, [field]: value }));
  }, []);

  const applyFilters = useCallback(() => {
    setFilters({ ...draft });
  }, [draft]);

  const clearFilters = useCallback(() => {
    setDraft({ ...EMPTY_FILTERS });
    setFilters({ ...EMPTY_FILTERS });
  }, []);

  const value = useMemo<FilterContextValue>(
    () => ({ draft, filters, isActive, setDraftField, applyFilters, clearFilters }),
    [draft, filters, isActive, setDraftField, applyFilters, clearFilters]
  );

  return <FilterContext.Provider value={value}>{children}</FilterContext.Provider>;
}
