// useTimeFilteredData — Filters an array of items by a timestamp key
// using the global TimeRangeContext. Returns the subset within the active range.

import { useMemo } from 'react';
import { useTimeRangeOptional } from '../contexts/TimeRangeContext';

/**
 * Filter a data array to items whose timestamp falls within the current time range.
 *
 * @param data       Array of items to filter
 * @param getTimestamp  Function that extracts an epoch-second timestamp from each item.
 *                      Return NaN or 0 to skip filtering for that item (always included).
 * @returns filtered array (same reference if no time filter is active)
 */
export function useTimeFilteredData<T>(
  data: T[] | undefined | null,
  getTimestamp: (item: T) => number,
): T[] {
  const ctx = useTimeRangeOptional();

  return useMemo(() => {
    if (!data) return [];
    if (!ctx || !ctx.isTimeFiltered) return data;

    const { start, end } = ctx.timeRange;
    return data.filter(item => {
      const ts = getTimestamp(item);
      // If timestamp is 0 or NaN, include the item (no timestamp to filter on)
      if (!ts || !isFinite(ts)) return true;
      return ts >= start && ts <= end;
    });
  }, [data, ctx, getTimestamp]);
}
