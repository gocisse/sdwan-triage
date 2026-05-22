// Keyboard shortcuts help modal — toggled with '?' key

import { useEffect } from 'react';
import { X, Keyboard } from 'lucide-react';

interface KeyboardShortcutsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const shortcuts: { key: string; label: string; description: string }[] = [
  { key: 'j', label: 'j', description: 'Move to next finding / packet row' },
  { key: 'k', label: 'k', description: 'Move to previous finding / packet row' },
  { key: 'Enter', label: 'Enter', description: 'Open / expand selected item' },
  { key: 'Escape', label: 'Esc', description: 'Close modal / reset time range' },
  { key: '/', label: '/', description: 'Focus the filter bar' },
  { key: '?', label: '?', description: 'Toggle this help overlay' },
  { key: 'f', label: 'f', description: 'Switch to Findings view' },
  { key: 'd', label: 'd', description: 'Switch to Forensic Drill-Down view' },
  { key: '[', label: '[', description: 'Nudge time range start forward 1s' },
  { key: ']', label: ']', description: 'Nudge time range end backward 1s' },
];

export function KeyboardShortcutsModal({ isOpen, onClose }: KeyboardShortcutsModalProps) {
  // Close on Escape
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === '?') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-slate-800 border border-slate-700 rounded-2xl shadow-2xl max-w-md w-full mx-4"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700">
          <div className="flex items-center gap-2">
            <Keyboard className="w-5 h-5 text-purple-400" />
            <h2 className="text-lg font-semibold text-white">Keyboard Shortcuts</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg hover:bg-slate-700 transition-colors"
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Shortcuts list */}
        <div className="px-6 py-4 space-y-1">
          {shortcuts.map((s) => (
            <div key={s.key} className="flex items-center justify-between py-2">
              <span className="text-sm text-slate-300">{s.description}</span>
              <kbd className="px-2.5 py-1 rounded-md bg-slate-700 border border-slate-600 text-xs font-mono text-slate-200 min-w-[2.5rem] text-center">
                {s.label}
              </kbd>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-700/50 text-center">
          <p className="text-xs text-slate-500">Press <kbd className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 font-mono text-[10px]">?</kbd> or <kbd className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 font-mono text-[10px]">Esc</kbd> to close</p>
        </div>
      </div>
    </div>
  );
}
