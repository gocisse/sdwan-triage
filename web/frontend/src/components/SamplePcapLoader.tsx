// SamplePcapLoader.tsx — Load sample PCAPs for learning
//
// Provides a dropdown to select and load pre-built sample PCAP files
// for training purposes.

import { useState, useEffect } from 'react';
import { ChevronDown, Download, BookOpen, Target, Loader2 } from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────

interface SampleChallenge {
  question: string;
  hint: string;
  answer: string;
}

interface SamplePcap {
  id: string;
  name: string;
  filename: string;
  description: string;
  category: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  learningObjectives: string[];
  challenge: SampleChallenge;
}

interface SamplesManifest {
  samples: SamplePcap[];
  categories: Record<string, { name: string; color: string }>;
  difficulties: Record<string, { name: string; color: string }>;
}

// ─── Component Props ──────────────────────────────────────────────

interface SamplePcapLoaderProps {
  onLoadSample: (file: File, sample: SamplePcap) => void;
  className?: string;
}

// ─── Main Component ───────────────────────────────────────────────

export function SamplePcapLoader({ onLoadSample, className = '' }: SamplePcapLoaderProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [samples, setSamples] = useState<SamplePcap[]>([]);
  const [loadingSample, setLoadingSample] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load samples manifest on mount
  useEffect(() => {
    loadManifest();
  }, []);

  const loadManifest = async () => {
    try {
      const response = await fetch('/samples/samples.json');
      if (!response.ok) throw new Error('Failed to load samples manifest');
      const data: SamplesManifest = await response.json();
      setSamples(data.samples);
    } catch (err) {
      console.error('Failed to load samples:', err);
      setError('Could not load sample library');
    }
  };

  const handleLoadSample = async (sample: SamplePcap) => {
    setLoadingSample(sample.id);
    setError(null);

    try {
      const response = await fetch(`/samples/${sample.filename}`);
      if (!response.ok) throw new Error(`Failed to load ${sample.filename}`);
      
      const blob = await response.blob();
      const file = new File([blob], sample.filename, { type: 'application/vnd.tcpdump.pcap' });
      
      onLoadSample(file, sample);
      setIsOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sample');
    } finally {
      setLoadingSample(null);
    }
  };

  const difficultyColors: Record<string, string> = {
    beginner: 'bg-green-500/20 text-green-400 border-green-500/30',
    intermediate: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    advanced: 'bg-red-500/20 text-red-400 border-red-500/30',
  };

  const categoryColors: Record<string, string> = {
    basics: 'text-blue-400',
    troubleshooting: 'text-orange-400',
    sdwan: 'text-purple-400',
    performance: 'text-green-400',
  };

  return (
    <div className={`relative ${className}`}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600/20 to-blue-600/20 hover:from-purple-600/30 hover:to-blue-600/30 border border-purple-500/30 rounded-lg text-sm font-medium text-purple-300 transition-all"
      >
        <BookOpen className="w-4 h-4" />
        Load Sample PCAP
        <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
          />
          
          {/* Dropdown */}
          <div className="absolute top-full left-0 mt-2 w-96 bg-slate-800 border border-slate-600 rounded-xl shadow-2xl z-50 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-700 bg-slate-800/80">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Target className="w-4 h-4 text-purple-400" />
                Training Sample Library
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Load pre-built scenarios to practice packet analysis
              </p>
            </div>

            <div className="max-h-80 overflow-y-auto">
              {samples.length === 0 && !error && (
                <div className="px-4 py-8 text-center text-slate-500 text-sm">
                  <Loader2 className="w-6 h-6 mx-auto mb-2 animate-spin" />
                  Loading samples...
                </div>
              )}

              {error && (
                <div className="px-4 py-4 text-center text-red-400 text-sm">
                  {error}
                </div>
              )}

              {samples.map((sample) => (
                <button
                  key={sample.id}
                  onClick={() => handleLoadSample(sample)}
                  disabled={loadingSample === sample.id}
                  className="w-full px-4 py-3 text-left hover:bg-slate-700/50 border-b border-slate-700/30 transition-colors disabled:opacity-50"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-white">{sample.name}</span>
                        <span className={`px-1.5 py-0.5 text-[9px] rounded border ${difficultyColors[sample.difficulty]}`}>
                          {sample.difficulty}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-2">{sample.description}</p>
                      <div className="flex items-center gap-2 mt-1.5">
                        <span className={`text-[10px] ${categoryColors[sample.category] || 'text-slate-500'}`}>
                          {sample.category}
                        </span>
                        <span className="text-slate-600">•</span>
                        <span className="text-[10px] text-slate-500">
                          {sample.learningObjectives.length} objectives
                        </span>
                      </div>
                    </div>
                    <div className="flex-shrink-0">
                      {loadingSample === sample.id ? (
                        <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
                      ) : (
                        <Download className="w-5 h-5 text-slate-500" />
                      )}
                    </div>
                  </div>
                </button>
              ))}
            </div>

            <div className="px-4 py-2 border-t border-slate-700 bg-slate-800/50 text-[10px] text-slate-500">
              💡 Enable Challenge Mode in settings to test your skills
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ─── Challenge Mode Component ─────────────────────────────────────

interface ChallengeModeProps {
  sample: SamplePcap;
  onClose: () => void;
}

export function ChallengeMode({ sample, onClose }: ChallengeModeProps) {
  const [showHint, setShowHint] = useState(false);
  const [showAnswer, setShowAnswer] = useState(false);
  const [userNotes, setUserNotes] = useState('');

  return (
    <div className="bg-gradient-to-br from-purple-900/30 to-blue-900/30 border border-purple-500/30 rounded-xl p-6 space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Target className="w-5 h-5 text-purple-400" />
            <h3 className="text-lg font-semibold text-white">Challenge Mode</h3>
          </div>
          <p className="text-sm text-slate-400">{sample.name}</p>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white transition-colors"
        >
          ✕
        </button>
      </div>

      {/* Learning Objectives */}
      <div className="bg-slate-800/50 rounded-lg p-4">
        <h4 className="text-xs font-semibold text-slate-400 mb-2">Learning Objectives</h4>
        <ul className="space-y-1">
          {sample.learningObjectives.map((obj, i) => (
            <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
              <span className="text-green-400 mt-0.5">✓</span>
              {obj}
            </li>
          ))}
        </ul>
      </div>

      {/* Challenge Question */}
      <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4">
        <h4 className="text-xs font-semibold text-yellow-400 mb-2">🎯 Your Challenge</h4>
        <p className="text-sm text-yellow-100">{sample.challenge.question}</p>
      </div>

      {/* User Notes */}
      <div>
        <label className="text-xs font-semibold text-slate-400 block mb-2">
          Your Analysis Notes
        </label>
        <textarea
          value={userNotes}
          onChange={(e) => setUserNotes(e.target.value)}
          placeholder="Write your findings here before revealing the answer..."
          className="w-full h-24 px-3 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 resize-none"
        />
      </div>

      {/* Hint */}
      {!showHint ? (
        <button
          onClick={() => setShowHint(true)}
          className="w-full py-2 text-sm bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors"
        >
          💡 Show Hint
        </button>
      ) : (
        <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-4">
          <h4 className="text-xs font-semibold text-blue-400 mb-1">💡 Hint</h4>
          <p className="text-sm text-blue-100">{sample.challenge.hint}</p>
        </div>
      )}

      {/* Answer */}
      {!showAnswer ? (
        <button
          onClick={() => setShowAnswer(true)}
          className="w-full py-2.5 text-sm bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white font-medium rounded-lg transition-all"
        >
          ✅ Show Answer
        </button>
      ) : (
        <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-4">
          <h4 className="text-xs font-semibold text-green-400 mb-2">✅ Root Cause Analysis</h4>
          <p className="text-sm text-green-100 leading-relaxed">{sample.challenge.answer}</p>
          
          {userNotes && (
            <div className="mt-4 pt-4 border-t border-green-500/20">
              <h5 className="text-xs font-semibold text-slate-400 mb-1">Your Notes:</h5>
              <p className="text-sm text-slate-300 italic">{userNotes}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Challenge Mode Settings ──────────────────────────────────────

interface ChallengeModeToggleProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
}

export function ChallengeModeToggle({ enabled, onChange }: ChallengeModeToggleProps) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <div className="relative">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onChange(e.target.checked)}
          className="sr-only"
        />
        <div className={`w-10 h-5 rounded-full transition-colors ${
          enabled ? 'bg-purple-600' : 'bg-slate-600'
        }`}>
          <div className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full transition-transform ${
            enabled ? 'translate-x-5' : ''
          }`} />
        </div>
      </div>
      <div>
        <span className="text-sm font-medium text-white">Challenge Mode</span>
        <p className="text-xs text-slate-400">Hide root cause until you analyze</p>
      </div>
    </label>
  );
}

export default SamplePcapLoader;
