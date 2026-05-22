// TimelineScrubber — Minimal SVG time-range brush rendered above the tab bar.
// Users drag to select a sub-range; all panels sync via TimeRangeContext.

import React, { useRef, useState, useCallback, useMemo, useEffect } from 'react';
import { Clock, X } from 'lucide-react';
import { useTimeRange } from '../../contexts/TimeRangeContext';
import type { AnalysisResults } from '../../types';

interface TimelineScrubberProps {
  results: AnalysisResults;
}

const BAR_H = 32;
const HANDLE_W = 6;

function formatTime(epoch: number): string {
  const d = new Date(epoch * 1000);
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
}

function formatDuration(sec: number): string {
  if (sec < 1) return `${(sec * 1000).toFixed(0)}ms`;
  if (sec < 60) return `${sec.toFixed(1)}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m${Math.floor(sec % 60)}s`;
  return `${Math.floor(sec / 3600)}h${Math.floor((sec % 3600) / 60)}m`;
}

export function TimelineScrubber({ results }: TimelineScrubberProps) {
  const { captureRange, timeRange, isTimeFiltered, setTimeRange, resetTimeRange } = useTimeRange();
  const containerRef = useRef<HTMLDivElement>(null);
  const [dragging, setDragging] = useState<'left' | 'right' | 'region' | null>(null);
  const [dragStartX, setDragStartX] = useState(0);
  const [dragStartRange, setDragStartRange] = useState(timeRange);

  // Build mini density sparkline from timeline events
  const sparkBuckets = useMemo(() => {
    const events = results.timeline || [];
    const BUCKETS = 80;
    const span = captureRange.end - captureRange.start;
    if (span <= 0 || events.length === 0) return new Array(BUCKETS).fill(0);

    const buckets = new Array(BUCKETS).fill(0);
    for (const ev of events) {
      const ts = new Date(ev.timestamp).getTime() / 1000;
      if (!ts || !isFinite(ts)) continue;
      const idx = Math.min(Math.floor(((ts - captureRange.start) / span) * BUCKETS), BUCKETS - 1);
      if (idx >= 0) buckets[idx]++;
    }
    return buckets;
  }, [results.timeline, captureRange]);

  const maxBucket = Math.max(...sparkBuckets, 1);

  // Convert epoch to x-fraction [0..1]
  const toFrac = useCallback((epoch: number) => {
    const span = captureRange.end - captureRange.start;
    if (span <= 0) return 0;
    return (epoch - captureRange.start) / span;
  }, [captureRange]);

  // Convert x-pixel to epoch
  const toEpoch = useCallback((clientX: number) => {
    if (!containerRef.current) return captureRange.start;
    const rect = containerRef.current.getBoundingClientRect();
    const frac = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    return captureRange.start + frac * (captureRange.end - captureRange.start);
  }, [captureRange]);

  const handleMouseDown = useCallback((e: React.MouseEvent, type: 'left' | 'right' | 'region') => {
    e.preventDefault();
    e.stopPropagation();
    setDragging(type);
    setDragStartX(e.clientX);
    setDragStartRange({ ...timeRange });
  }, [timeRange]);

  // Brush: click on empty area to start a fresh selection
  const handleBarMouseDown = useCallback((e: React.MouseEvent) => {
    if (dragging) return;
    const epoch = toEpoch(e.clientX);
    // If clicking within the selection, start region drag
    if (epoch >= timeRange.start && epoch <= timeRange.end && isTimeFiltered) {
      handleMouseDown(e, 'region');
      return;
    }
    // Start fresh selection
    setTimeRange({ start: epoch, end: epoch });
    setDragging('right');
    setDragStartX(e.clientX);
    setDragStartRange({ start: epoch, end: epoch });
  }, [dragging, toEpoch, timeRange, isTimeFiltered, setTimeRange, handleMouseDown]);

  useEffect(() => {
    if (!dragging) return;

    const handleMove = (e: MouseEvent) => {
      const span = captureRange.end - captureRange.start;
      if (!containerRef.current || span <= 0) return;
      const rect = containerRef.current.getBoundingClientRect();
      const dx = e.clientX - dragStartX;
      const dFrac = dx / rect.width;
      const dEpoch = dFrac * span;

      if (dragging === 'left') {
        const newStart = Math.max(captureRange.start, Math.min(dragStartRange.start + dEpoch, dragStartRange.end - 0.1));
        setTimeRange({ start: newStart, end: dragStartRange.end });
      } else if (dragging === 'right') {
        const newEnd = Math.min(captureRange.end, Math.max(dragStartRange.end + dEpoch, dragStartRange.start + 0.1));
        setTimeRange({ start: dragStartRange.start, end: newEnd });
      } else if (dragging === 'region') {
        const rangeLen = dragStartRange.end - dragStartRange.start;
        let newStart = dragStartRange.start + dEpoch;
        let newEnd = dragStartRange.end + dEpoch;
        if (newStart < captureRange.start) { newStart = captureRange.start; newEnd = newStart + rangeLen; }
        if (newEnd > captureRange.end) { newEnd = captureRange.end; newStart = newEnd - rangeLen; }
        setTimeRange({ start: newStart, end: newEnd });
      }
    };

    const handleUp = () => setDragging(null);

    window.addEventListener('mousemove', handleMove);
    window.addEventListener('mouseup', handleUp);
    return () => {
      window.removeEventListener('mousemove', handleMove);
      window.removeEventListener('mouseup', handleUp);
    };
  }, [dragging, dragStartX, dragStartRange, captureRange, setTimeRange]);

  const leftFrac = toFrac(timeRange.start);
  const rightFrac = toFrac(timeRange.end);
  const selectionDuration = timeRange.end - timeRange.start;

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-lg px-3 py-2">
      {/* Label row */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5">
          <Clock className="w-3 h-3 text-purple-400" />
          <span className="text-[10px] font-medium text-slate-400">Timeline Scrubber</span>
          {isTimeFiltered && (
            <span className="text-[10px] text-purple-300 bg-purple-500/10 px-1.5 py-0.5 rounded">
              {formatTime(timeRange.start)} – {formatTime(timeRange.end)} ({formatDuration(selectionDuration)})
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {isTimeFiltered && (
            <button
              onClick={resetTimeRange}
              className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
              title="Reset to full capture (Esc)"
            >
              <X className="w-3 h-3" />
              Reset
            </button>
          )}
          <span className="text-[10px] text-slate-600 font-mono">
            {formatTime(captureRange.start)} → {formatTime(captureRange.end)}
          </span>
        </div>
      </div>

      {/* SVG bar */}
      <div
        ref={containerRef}
        className="relative w-full select-none cursor-crosshair"
        style={{ height: BAR_H }}
        onMouseDown={handleBarMouseDown}
      >
        {/* Background track */}
        <svg className="absolute inset-0 w-full h-full" preserveAspectRatio="none">
          <rect x="0" y="0" width="100%" height="100%" rx="4" fill="#0f172a" />

          {/* Density sparkline */}
          {sparkBuckets.map((v, i) => {
            const bw = 100 / sparkBuckets.length;
            const bh = (v / maxBucket) * (BAR_H - 4);
            return (
              <rect
                key={i}
                x={`${i * bw}%`}
                y={BAR_H - 2 - bh}
                width={`${bw - 0.2}%`}
                height={bh}
                fill="#334155"
                rx={1}
              />
            );
          })}

          {/* Dimmed areas outside selection */}
          {isTimeFiltered && (
            <>
              <rect x="0" y="0" width={`${leftFrac * 100}%`} height={BAR_H} fill="rgba(0,0,0,0.5)" />
              <rect x={`${rightFrac * 100}%`} y="0" width={`${(1 - rightFrac) * 100}%`} height={BAR_H} fill="rgba(0,0,0,0.5)" />
            </>
          )}

          {/* Selected range highlight */}
          <rect
            x={`${leftFrac * 100}%`}
            y="0"
            width={`${(rightFrac - leftFrac) * 100}%`}
            height={BAR_H}
            fill="rgba(139, 92, 246, 0.15)"
            stroke="#8b5cf6"
            strokeWidth={isTimeFiltered ? 1 : 0}
            rx={2}
          />
        </svg>

        {/* Left handle */}
        {isTimeFiltered && (
          <div
            className="absolute top-0 h-full cursor-ew-resize z-10 flex items-center"
            style={{ left: `calc(${leftFrac * 100}% - ${HANDLE_W / 2}px)`, width: HANDLE_W }}
            onMouseDown={(e: React.MouseEvent) => handleMouseDown(e, 'left')}
          >
            <div className="w-1 h-4 bg-purple-400 rounded-full mx-auto" />
          </div>
        )}

        {/* Right handle */}
        {isTimeFiltered && (
          <div
            className="absolute top-0 h-full cursor-ew-resize z-10 flex items-center"
            style={{ left: `calc(${rightFrac * 100}% - ${HANDLE_W / 2}px)`, width: HANDLE_W }}
            onMouseDown={(e: React.MouseEvent) => handleMouseDown(e, 'right')}
          >
            <div className="w-1 h-4 bg-purple-400 rounded-full mx-auto" />
          </div>
        )}

        {/* Region drag area */}
        {isTimeFiltered && (
          <div
            className="absolute top-0 h-full cursor-grab active:cursor-grabbing z-5"
            style={{ left: `${leftFrac * 100}%`, width: `${(rightFrac - leftFrac) * 100}%` }}
            onMouseDown={(e: React.MouseEvent) => handleMouseDown(e, 'region')}
          />
        )}
      </div>

      {/* Keyboard hint */}
      <div className="flex items-center gap-3 mt-1">
        <span className="text-[9px] text-slate-600">
          Drag to select range · <kbd className="px-1 py-0.5 rounded bg-slate-700 text-slate-400 font-mono">[</kbd> nudge start · <kbd className="px-1 py-0.5 rounded bg-slate-700 text-slate-400 font-mono">]</kbd> nudge end · <kbd className="px-1 py-0.5 rounded bg-slate-700 text-slate-400 font-mono">Esc</kbd> reset
        </span>
      </div>
    </div>
  );
}
