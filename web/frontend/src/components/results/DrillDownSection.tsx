// DrillDownSection — Forensic Drill-Down panel extracted from ResultsPage.tsx
// Contains the sub-tab bar and all forensic tool panels

import { useState } from 'react';
import type { AnalysisResults } from '../../types';
import type { ParsedFilter } from '../../hooks';
import { ForensicFilterContext, type ForensicFilterContextValue } from '../../hooks';
import { ProtocolStats, ConversationsView, ExpertInfo, IOGraphView, QosDashboard, LatencyMatrix } from '../../components';
import PacketSearchBar from '../../components/PacketSearchBar';
import { DrillDownSkeleton } from '../ui/Skeletons';

type ForensicSubTab = 'iograph' | 'protocols' | 'conversations' | 'expert' | 'qos' | 'latency' | 'search';

export interface DrillDownSectionProps {
  results: AnalysisResults;
  filteredResults: AnalysisResults | null;
  isFiltered: boolean;
  filterCtxValue: ForensicFilterContextValue | null;
  filterText: string;
  parsedFilter: ParsedFilter;
  jobId: string;
  onFilterChange: (text: string) => void;
  onSelectPacket: (packetIndex: number) => void;
  onFollowStream: (streamId: string) => void;
}

export function DrillDownSection({
  results,
  filteredResults,
  isFiltered,
  filterCtxValue,
  jobId,
  onFilterChange,
  onSelectPacket,
  onFollowStream,
}: DrillDownSectionProps) {
  const [forensicSubTab, setForensicSubTab] = useState<ForensicSubTab>('iograph');

  if (!filterCtxValue) return <DrillDownSkeleton />;

  const effectiveResults = isFiltered && filteredResults ? filteredResults : results;

  return (
    <ForensicFilterContext.Provider value={filterCtxValue}>
      <div className="space-y-4" data-tour="drill-down">
        {/* Sub-tabs */}
        <div className="flex items-center gap-1 border-b border-slate-700/50 pb-0">
          {([
            { key: 'iograph' as const, label: 'IO Graph' },
            { key: 'protocols' as const, label: 'Protocol Hierarchy' },
            { key: 'conversations' as const, label: 'Conversations' },
            { key: 'expert' as const, label: 'Expert Info' },
            { key: 'qos' as const, label: 'QoS Analysis' },
            { key: 'latency' as const, label: 'Latency Matrix' },
            { key: 'search' as const, label: 'Packet Search' },
          ]).map(tab => (
            <button
              key={tab.key}
              onClick={() => setForensicSubTab(tab.key)}
              className={`px-4 py-2.5 text-xs font-medium transition-all border-b-2 -mb-[1px] ${
                forensicSubTab === tab.key
                  ? 'border-purple-500 text-purple-400'
                  : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Sub-tab content */}
        {forensicSubTab === 'iograph' && (
          <IOGraphView
            results={effectiveResults}
            onTimeDrillDown={(startEpoch, endEpoch) => {
              onFilterChange(`frame.time_epoch > ${startEpoch.toFixed(1)} && frame.time_epoch < ${endEpoch.toFixed(1)}`);
            }}
          />
        )}
        {forensicSubTab === 'protocols' && (
          <ProtocolStats results={effectiveResults} />
        )}
        {forensicSubTab === 'conversations' && (
          <ConversationsView
            results={effectiveResults}
            onFilterConversation={(srcIp, dstIp) => {
              onFilterChange(`ip.addr == ${srcIp} && ip.addr == ${dstIp}`);
            }}
          />
        )}
        {forensicSubTab === 'expert' && (
          <ExpertInfo
            results={effectiveResults}
            onJumpToPacket={onSelectPacket}
            onFollowStream={onFollowStream}
          />
        )}
        {forensicSubTab === 'qos' && (
          <QosDashboard results={effectiveResults} />
        )}
        {forensicSubTab === 'latency' && (
          <LatencyMatrix
            results={effectiveResults}
            onFilterApply={(expr) => onFilterChange(expr)}
          />
        )}
        {forensicSubTab === 'search' && (
          <PacketSearchBar
            jobId={jobId}
            onSelectPacket={onSelectPacket}
          />
        )}
      </div>
    </ForensicFilterContext.Provider>
  );
}
