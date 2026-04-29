// Reusable skeleton loading components using Tailwind animate-pulse

export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6 animate-pulse">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-10 h-10 bg-slate-700 rounded-xl" />
        <div className="flex-1 space-y-2">
          <div className="h-4 bg-slate-700 rounded w-1/3" />
          <div className="h-3 bg-slate-700/60 rounded w-2/3" />
        </div>
      </div>
      <div className="space-y-2.5">
        {Array.from({ length: lines }).map((_, i) => (
          <div key={i} className="h-3 bg-slate-700/50 rounded" style={{ width: `${85 - i * 12}%` }} />
        ))}
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl overflow-hidden animate-pulse">
      {/* Header */}
      <div className="flex gap-3 px-4 py-3 border-b border-slate-700/50">
        {Array.from({ length: cols }).map((_, i) => (
          <div key={i} className="h-3 bg-slate-700 rounded flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3 px-4 py-2.5 border-b border-slate-700/20">
          {Array.from({ length: cols }).map((_, c) => (
            <div key={c} className="h-3 bg-slate-700/40 rounded flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SummarySkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      {/* Top bar */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <div className="h-5 bg-slate-700 rounded w-48" />
          <div className="h-3 bg-slate-700/50 rounded w-72" />
        </div>
        <div className="flex gap-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-8 w-20 bg-slate-700/60 rounded-lg" />
          ))}
        </div>
      </div>
      {/* Executive summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-4">
            <div className="h-3 bg-slate-700/50 rounded w-16 mb-3" />
            <div className="h-8 bg-slate-700 rounded w-12 mb-1" />
            <div className="h-3 bg-slate-700/30 rounded w-24" />
          </div>
        ))}
      </div>
      {/* Finding cards */}
      <div className="space-y-4">
        <CardSkeleton lines={4} />
        <CardSkeleton lines={3} />
        <CardSkeleton lines={2} />
      </div>
    </div>
  );
}

export function DrillDownSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {/* Tab bar */}
      <div className="flex gap-2 border-b border-slate-700/50 pb-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-8 w-28 bg-slate-700/40 rounded-lg" />
        ))}
      </div>
      {/* Content area */}
      <div className="bg-slate-800/80 border border-slate-700/50 rounded-xl p-6">
        <div className="h-64 bg-slate-700/20 rounded-lg" />
      </div>
    </div>
  );
}
