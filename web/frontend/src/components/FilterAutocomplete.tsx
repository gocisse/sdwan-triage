// FilterAutocomplete.tsx — Wireshark-style filter input with autocomplete (U1)
//
// Provides dropdown suggestions for:
// - Field names (ip.src, tcp.port, etc.)
// - Operators (==, !=, contains, etc.)
// - Common values (protocol names, port numbers)

import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Search, X } from 'lucide-react';

// ─── Filter Field Definitions ─────────────────────────────────────

interface FilterField {
  name: string;
  description: string;
  type: 'ip' | 'port' | 'string' | 'number' | 'flags';
  examples?: string[];
}

const FILTER_FIELDS: FilterField[] = [
  // IP fields
  { name: 'ip.src', description: 'Source IP address', type: 'ip', examples: ['192.168.1.1', '10.0.0.0/8'] },
  { name: 'ip.dst', description: 'Destination IP address', type: 'ip', examples: ['192.168.1.1', '10.0.0.0/8'] },
  { name: 'ip.addr', description: 'Source or destination IP', type: 'ip', examples: ['192.168.1.1'] },
  { name: 'ip.ttl', description: 'Time to live', type: 'number', examples: ['64', '128', '255'] },
  { name: 'ip.dscp', description: 'DSCP value', type: 'number', examples: ['0', '46', '34'] },
  
  // TCP fields
  { name: 'tcp.port', description: 'TCP source or destination port', type: 'port', examples: ['80', '443', '22'] },
  { name: 'tcp.srcport', description: 'TCP source port', type: 'port', examples: ['443', '8080'] },
  { name: 'tcp.dstport', description: 'TCP destination port', type: 'port', examples: ['80', '443', '22'] },
  { name: 'tcp.flags', description: 'TCP flags (SYN, ACK, FIN, RST)', type: 'flags', examples: ['SYN', 'ACK', 'FIN', 'RST', 'PSH'] },
  { name: 'tcp.seq', description: 'TCP sequence number', type: 'number' },
  { name: 'tcp.ack', description: 'TCP acknowledgment number', type: 'number' },
  { name: 'tcp.window', description: 'TCP window size', type: 'number' },
  { name: 'tcp.len', description: 'TCP payload length', type: 'number' },
  
  // UDP fields
  { name: 'udp.port', description: 'UDP source or destination port', type: 'port', examples: ['53', '123', '500'] },
  { name: 'udp.srcport', description: 'UDP source port', type: 'port' },
  { name: 'udp.dstport', description: 'UDP destination port', type: 'port' },
  { name: 'udp.length', description: 'UDP datagram length', type: 'number' },
  
  // Frame/packet fields
  { name: 'frame.len', description: 'Frame length', type: 'number' },
  { name: 'frame.protocol', description: 'Protocol name', type: 'string', examples: ['TCP', 'UDP', 'ICMP', 'HTTP', 'DNS'] },
  { name: 'frame.time', description: 'Capture timestamp', type: 'string' },
  
  // Application protocols
  { name: 'http', description: 'HTTP traffic', type: 'string' },
  { name: 'dns', description: 'DNS traffic', type: 'string' },
  { name: 'tls', description: 'TLS/SSL traffic', type: 'string' },
  { name: 'icmp', description: 'ICMP traffic', type: 'string' },
  
  // SD-WAN specific
  { name: 'bfd', description: 'BFD (Bidirectional Forwarding Detection)', type: 'string' },
  { name: 'vxlan', description: 'VXLAN encapsulated traffic', type: 'string' },
  { name: 'gre', description: 'GRE encapsulated traffic', type: 'string' },
  { name: 'esp', description: 'ESP (IPsec) encrypted traffic', type: 'string' },
  
  // Analysis flags
  { name: 'tcp.analysis.retransmission', description: 'TCP retransmission', type: 'string' },
  { name: 'tcp.analysis.duplicate_ack', description: 'Duplicate ACK', type: 'string' },
  { name: 'tcp.analysis.zero_window', description: 'Zero window', type: 'string' },
  { name: 'tcp.analysis.keep_alive', description: 'Keep-alive packet', type: 'string' },
];

const OPERATORS = [
  { op: '==', description: 'Equals' },
  { op: '!=', description: 'Not equals' },
  { op: '>', description: 'Greater than' },
  { op: '<', description: 'Less than' },
  { op: '>=', description: 'Greater or equal' },
  { op: '<=', description: 'Less or equal' },
  { op: 'contains', description: 'Contains substring' },
  { op: 'matches', description: 'Matches regex' },
];

const LOGICAL_OPERATORS = [
  { op: '&&', description: 'AND' },
  { op: '||', description: 'OR' },
  { op: '!', description: 'NOT' },
  { op: '(', description: 'Open group' },
  { op: ')', description: 'Close group' },
];

// ─── Component Props ──────────────────────────────────────────────

interface FilterAutocompleteProps {
  value: string;
  onChange: (value: string) => void;
  onApply?: (value: string) => void;
  placeholder?: string;
  className?: string;
  inputRef?: React.RefObject<HTMLInputElement>;
}

// ─── Suggestion Types ─────────────────────────────────────────────

type SuggestionType = 'field' | 'operator' | 'value' | 'logical';

interface Suggestion {
  type: SuggestionType;
  text: string;
  description: string;
  insertText?: string; // What to actually insert (may differ from display text)
}

// ─── Main Component ───────────────────────────────────────────────

export const FilterAutocomplete: React.FC<FilterAutocompleteProps> = ({
  value,
  onChange,
  onApply,
  placeholder = 'Filter: ip.src == 192.168.1.1 && tcp.port == 443',
  className = '',
  inputRef: externalInputRef,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const internalInputRef = useRef<HTMLInputElement>(null);
  const inputRef = externalInputRef || internalInputRef;
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Determine what kind of suggestions to show based on cursor position and context
  const suggestions = useMemo((): Suggestion[] => {
    if (!value.trim()) {
      // Empty input: show common fields
      return FILTER_FIELDS.slice(0, 10).map(f => ({
        type: 'field',
        text: f.name,
        description: f.description,
      }));
    }

    const trimmed = value.trim();
    const lastToken = trimmed.split(/\s+/).pop() || '';
    const beforeLastToken = trimmed.slice(0, trimmed.length - lastToken.length).trim();

    // Check if we just typed a field name and need an operator
    const lastField = FILTER_FIELDS.find(f => 
      beforeLastToken.endsWith(f.name) || trimmed.endsWith(f.name)
    );
    
    if (lastField && !lastToken) {
      // Just typed a field, suggest operators
      return OPERATORS.map(o => ({
        type: 'operator',
        text: o.op,
        description: o.description,
        insertText: ` ${o.op} `,
      }));
    }

    // Check if we're after an operator and need a value
    const hasOperator = OPERATORS.some(o => trimmed.includes(` ${o.op} `));
    const endsWithOperator = OPERATORS.some(o => trimmed.endsWith(` ${o.op} `) || trimmed.endsWith(` ${o.op}`));
    
    if (endsWithOperator) {
      // Find the field before the operator to suggest appropriate values
      const fieldMatch = FILTER_FIELDS.find(f => trimmed.includes(f.name));
      if (fieldMatch?.examples) {
        return fieldMatch.examples.map(ex => ({
          type: 'value',
          text: ex,
          description: `Example ${fieldMatch.type} value`,
        }));
      }
      return [];
    }

    // Check if we need a logical operator (after a complete expression)
    if (hasOperator && !endsWithOperator && lastToken && !LOGICAL_OPERATORS.some(l => lastToken.startsWith(l.op))) {
      // Might need && or ||
      const logicalSuggestions: Suggestion[] = LOGICAL_OPERATORS.slice(0, 2).map(l => ({
        type: 'logical',
        text: l.op,
        description: l.description,
        insertText: ` ${l.op} `,
      }));
      return logicalSuggestions;
    }

    // Default: filter fields by what user is typing
    const searchTerm = lastToken.toLowerCase();
    const matchingFields = FILTER_FIELDS.filter(f =>
      f.name.toLowerCase().includes(searchTerm) ||
      f.description.toLowerCase().includes(searchTerm)
    ).slice(0, 10);

    return matchingFields.map(f => ({
      type: 'field',
      text: f.name,
      description: f.description,
    }));
  }, [value]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (!isOpen || suggestions.length === 0) {
      if (e.key === 'Enter' && onApply) {
        e.preventDefault();
        onApply(value);
      }
      return;
    }

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex(prev => (prev + 1) % suggestions.length);
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex(prev => (prev - 1 + suggestions.length) % suggestions.length);
        break;
      case 'Tab':
      case 'Enter':
        e.preventDefault();
        insertSuggestion(suggestions[selectedIndex]);
        break;
      case 'Escape':
        e.preventDefault();
        setIsOpen(false);
        break;
    }
  }, [isOpen, suggestions, selectedIndex, value, onApply]);

  // Insert selected suggestion
  const insertSuggestion = useCallback((suggestion: Suggestion) => {
    const trimmed = value.trim();
    const lastToken = trimmed.split(/\s+/).pop() || '';
    const beforeLastToken = trimmed.slice(0, trimmed.length - lastToken.length);
    
    let newValue: string;
    if (suggestion.insertText) {
      newValue = trimmed + suggestion.insertText;
    } else if (suggestion.type === 'field') {
      // Replace the partial token with the full field name
      newValue = beforeLastToken + suggestion.text;
    } else {
      newValue = trimmed + ' ' + suggestion.text;
    }
    
    onChange(newValue);
    setIsOpen(false);
    setSelectedIndex(0);
    inputRef.current?.focus();
  }, [value, onChange, inputRef]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(e.target as Node) &&
        inputRef.current &&
        !inputRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [inputRef]);

  // Reset selection when suggestions change
  useEffect(() => {
    setSelectedIndex(0);
  }, [suggestions]);

  const typeColors: Record<SuggestionType, string> = {
    field: 'text-cyan-400',
    operator: 'text-yellow-400',
    value: 'text-green-400',
    logical: 'text-purple-400',
  };

  const typeBadges: Record<SuggestionType, string> = {
    field: 'bg-cyan-500/20 text-cyan-400',
    operator: 'bg-yellow-500/20 text-yellow-400',
    value: 'bg-green-500/20 text-green-400',
    logical: 'bg-purple-500/20 text-purple-400',
  };

  return (
    <div className={`relative ${className}`}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
            setIsOpen(true);
          }}
          onFocus={() => setIsOpen(true)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          className="w-full pl-10 pr-8 py-2 bg-slate-800 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono"
        />
        {value && (
          <button
            onClick={() => {
              onChange('');
              inputRef.current?.focus();
            }}
            className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-slate-700 rounded transition-colors"
          >
            <X className="w-3.5 h-3.5 text-slate-500" />
          </button>
        )}
      </div>

      {/* Autocomplete Dropdown */}
      {isOpen && suggestions.length > 0 && (
        <div
          ref={dropdownRef}
          className="absolute z-50 w-full mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl max-h-64 overflow-y-auto"
        >
          {suggestions.map((suggestion, index) => (
            <button
              key={`${suggestion.type}-${suggestion.text}`}
              onClick={() => insertSuggestion(suggestion)}
              className={`w-full px-3 py-2 text-left flex items-center gap-3 transition-colors ${
                index === selectedIndex
                  ? 'bg-blue-600/30 border-l-2 border-blue-500'
                  : 'hover:bg-slate-700/50 border-l-2 border-transparent'
              }`}
            >
              <span className={`text-xs px-1.5 py-0.5 rounded ${typeBadges[suggestion.type]}`}>
                {suggestion.type}
              </span>
              <span className={`font-mono text-sm ${typeColors[suggestion.type]}`}>
                {suggestion.text}
              </span>
              <span className="text-xs text-slate-500 ml-auto truncate">
                {suggestion.description}
              </span>
            </button>
          ))}
          
          {/* Help footer */}
          <div className="px-3 py-2 border-t border-slate-700 text-[10px] text-slate-500 flex items-center gap-4">
            <span>↑↓ Navigate</span>
            <span>Tab/Enter Select</span>
            <span>Esc Close</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default FilterAutocomplete;
