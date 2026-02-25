// Display Filter bar — Wireshark-like syntax for forensic drill-down

import { useState, useRef, useCallback, useEffect } from 'react';
import { Search, X, AlertCircle, CheckCircle2, ChevronDown } from 'lucide-react';
import { getFieldSuggestions, type ParsedFilter } from '../hooks/useForensicFilter';

interface FilterBarProps {
  value: string;
  onChange: (value: string) => void;
  parsedFilter: ParsedFilter;
}

export default function FilterBar({ value, onChange, parsedFilter }: FilterBarProps) {
  const [focused, setFocused] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const suggestions = getFieldSuggestions();

  const handleClear = useCallback(() => {
    onChange('');
    inputRef.current?.focus();
  }, [onChange]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      handleClear();
      setShowHelp(false);
    }
    if (e.key === 'Enter') {
      setShowHelp(false);
      inputRef.current?.blur();
    }
  }, [handleClear]);

  const insertField = useCallback((field: string) => {
    const newVal = value ? `${value} && ${field} == ` : `${field} == `;
    onChange(newVal);
    inputRef.current?.focus();
    setShowHelp(false);
  }, [value, onChange]);

  // Close help dropdown on outside click
  useEffect(() => {
    if (!showHelp) return;
    const handler = (e: MouseEvent) => {
      if (!(e.target as Element)?.closest('.filter-bar-container')) {
        setShowHelp(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showHelp]);

  const hasFilter = value.trim().length > 0;
  const isValid = !hasFilter || parsedFilter.valid;
  const tokenCount = parsedFilter.tokens.length;

  return (
    <div className="filter-bar-container relative">
      <div
        className={`flex items-center gap-2 px-3 py-2 rounded-xl border transition-all ${
          focused
            ? isValid
              ? 'border-green-500/50 bg-slate-800/90 shadow-lg shadow-green-500/10'
              : 'border-red-500/50 bg-slate-800/90 shadow-lg shadow-red-500/10'
            : hasFilter
              ? isValid
                ? 'border-green-500/30 bg-green-500/5'
                : 'border-red-500/30 bg-red-500/5'
              : 'border-slate-700/50 bg-slate-800/60'
        }`}
      >
        {/* Status icon */}
        {hasFilter ? (
          isValid ? (
            <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          )
        ) : (
          <Search className="w-4 h-4 text-slate-500 flex-shrink-0" />
        )}

        {/* Input */}
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={handleKeyDown}
          placeholder="Display filter: ip.src == 10.0.0.1 && tcp.port == 443"
          className="flex-1 bg-transparent text-sm text-slate-200 placeholder:text-slate-500 outline-none font-mono"
          spellCheck={false}
          autoComplete="off"
        />

        {/* Token count badge */}
        {hasFilter && isValid && tokenCount > 0 && (
          <span className="text-[10px] font-medium bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded flex-shrink-0">
            {tokenCount} filter{tokenCount > 1 ? 's' : ''}
          </span>
        )}

        {/* Error message */}
        {hasFilter && !isValid && (
          <span className="text-[10px] text-red-400 flex-shrink-0 max-w-[200px] truncate" title={parsedFilter.error}>
            {parsedFilter.error}
          </span>
        )}

        {/* Help toggle */}
        <button
          onClick={() => setShowHelp(!showHelp)}
          className={`p-1 rounded transition-colors flex-shrink-0 ${
            showHelp ? 'bg-blue-500/20 text-blue-400' : 'text-slate-500 hover:text-slate-300 hover:bg-slate-700/50'
          }`}
          title="Show filter syntax help"
        >
          <ChevronDown className={`w-3.5 h-3.5 transition-transform ${showHelp ? 'rotate-180' : ''}`} />
        </button>

        {/* Clear button */}
        {hasFilter && (
          <button
            onClick={handleClear}
            className="p-1 rounded hover:bg-slate-700/50 transition-colors text-slate-500 hover:text-slate-300 flex-shrink-0"
            title="Clear filter"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Help dropdown */}
      {showHelp && (
        <div className="absolute top-full left-0 right-0 mt-1 z-50 bg-slate-800 border border-slate-700/50 rounded-xl shadow-2xl shadow-black/40 overflow-hidden">
          <div className="px-4 py-2.5 border-b border-slate-700/50 bg-slate-800/80">
            <p className="text-xs font-medium text-slate-300">Supported Filter Fields</p>
            <p className="text-[10px] text-slate-500 mt-0.5">Click a field to insert it. Use <code className="text-blue-400">&&</code> to combine filters.</p>
          </div>
          <div className="max-h-[240px] overflow-y-auto p-2">
            <div className="grid grid-cols-2 gap-1">
              {suggestions.map(({ field, help }) => (
                <button
                  key={field}
                  onClick={() => insertField(field)}
                  className="flex items-start gap-2 px-3 py-2 rounded-lg text-left hover:bg-slate-700/50 transition-colors group"
                >
                  <code className="text-xs text-blue-400 font-mono flex-shrink-0 group-hover:text-blue-300">{field}</code>
                  <span className="text-[10px] text-slate-500 leading-snug">{help}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="px-4 py-2 border-t border-slate-700/50 bg-slate-800/80">
            <p className="text-[10px] text-slate-500">
              <span className="text-slate-400 font-medium">Examples:</span>{' '}
              <code className="text-green-400">ip.src == 10.0.0.1</code> · 
              <code className="text-green-400"> tcp.port == 443</code> · 
              <code className="text-green-400"> dns.qry.name contains google</code>
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
