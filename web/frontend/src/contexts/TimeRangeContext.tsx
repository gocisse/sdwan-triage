// TimeRangeContext — Global time-range state that syncs IO Graph, Findings,
// Expert Info, and Conversations panels. Keyboard shortcuts: [ ] Esc

import { createContext, useContext, useState, useCallback, useEffect, useMemo } from 'react';
import type { ReactNode } from 'react';

export interface TimeRange {
  start: number; // Unix epoch seconds
  end: number;   // Unix epoch seconds
}

export interface TimeRangeContextValue {
  /** Full span of the capture (immutable after init) */
  captureRange: TimeRange;
  /** Current user-selected range (defaults to captureRange) */
  timeRange: TimeRange;
  /** Whether the range has been narrowed from the full capture */
  isTimeFiltered: boolean;
  /** Set an arbitrary range */
  setTimeRange: (range: TimeRange) => void;
  /** Reset to full capture span */
  resetTimeRange: () => void;
  /** Nudge start forward/backward by delta seconds */
  nudgeStart: (deltaSec: number) => void;
  /** Nudge end forward/backward by delta seconds */
  nudgeEnd: (deltaSec: number) => void;
}

const TimeRangeContext = createContext<TimeRangeContextValue | null>(null);

export function useTimeRange(): TimeRangeContextValue {
  const ctx = useContext(TimeRangeContext);
  if (!ctx) throw new Error('useTimeRange must be used within a TimeRangeProvider');
  return ctx;
}

export function useTimeRangeOptional(): TimeRangeContextValue | null {
  return useContext(TimeRangeContext);
}

interface TimeRangeProviderProps {
  captureStart: number;
  captureEnd: number;
  children: ReactNode;
}

export function TimeRangeProvider({ captureStart, captureEnd, children }: TimeRangeProviderProps) {
  const captureRange = useMemo<TimeRange>(
    () => ({ start: captureStart, end: captureEnd }),
    [captureStart, captureEnd],
  );

  const [timeRange, setTimeRangeRaw] = useState<TimeRange>(captureRange);

  // Re-sync when capture range changes (new analysis loaded)
  useEffect(() => {
    setTimeRangeRaw(captureRange);
  }, [captureRange]);

  const setTimeRange = useCallback((range: TimeRange) => {
    setTimeRangeRaw({
      start: Math.max(range.start, captureRange.start),
      end: Math.min(range.end, captureRange.end),
    });
  }, [captureRange]);

  const resetTimeRange = useCallback(() => {
    setTimeRangeRaw(captureRange);
  }, [captureRange]);

  const nudgeStart = useCallback((deltaSec: number) => {
    setTimeRangeRaw(prev => ({
      start: Math.max(prev.start + deltaSec, captureRange.start),
      end: prev.end,
    }));
  }, [captureRange]);

  const nudgeEnd = useCallback((deltaSec: number) => {
    setTimeRangeRaw(prev => ({
      start: prev.start,
      end: Math.min(prev.end + deltaSec, captureRange.end),
    }));
  }, [captureRange]);

  const isTimeFiltered = timeRange.start > captureRange.start + 0.01 ||
                         timeRange.end < captureRange.end - 0.01;

  // Keyboard shortcuts: [ nudge start, ] nudge end, Esc reset
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      if (e.key === '[') {
        e.preventDefault();
        nudgeStart(1);
      } else if (e.key === ']') {
        e.preventDefault();
        nudgeEnd(-1);
      } else if (e.key === 'Escape' && isTimeFiltered) {
        // Only reset time range; don't intercept Escape for other modals
        // We only handle if time is actually filtered
        e.preventDefault();
        resetTimeRange();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [nudgeStart, nudgeEnd, resetTimeRange, isTimeFiltered]);

  const value = useMemo<TimeRangeContextValue>(() => ({
    captureRange,
    timeRange,
    isTimeFiltered,
    setTimeRange,
    resetTimeRange,
    nudgeStart,
    nudgeEnd,
  }), [captureRange, timeRange, isTimeFiltered, setTimeRange, resetTimeRange, nudgeStart, nudgeEnd]);

  return (
    <TimeRangeContext.Provider value={value}>
      {children}
    </TimeRangeContext.Provider>
  );
}
