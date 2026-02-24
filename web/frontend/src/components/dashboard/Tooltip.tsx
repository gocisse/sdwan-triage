import { useState, useRef } from 'react';
import { HelpCircle } from 'lucide-react';
import { termDefinitions } from '../../data/knowledgeBase';

interface TooltipProps {
  term: string;
  children?: React.ReactNode;
}

export function Tooltip({ term, children }: TooltipProps) {
  const [show, setShow] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>();

  const definition = termDefinitions[term];
  if (!definition) {
    return <>{children || term}</>;
  }

  const handleEnter = () => {
    clearTimeout(timeoutRef.current);
    setShow(true);
  };

  const handleLeave = () => {
    timeoutRef.current = setTimeout(() => setShow(false), 150);
  };

  return (
    <span
      className="relative inline-flex items-center gap-0.5 cursor-help"
      onMouseEnter={handleEnter}
      onMouseLeave={handleLeave}
    >
      <span className="border-b border-dotted border-slate-500 text-slate-200">
        {children || term}
      </span>
      <HelpCircle className="w-3 h-3 text-slate-500" />
      {show && (
        <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-50 w-72 p-3 bg-slate-700 border border-slate-600 rounded-lg shadow-xl text-xs text-slate-200 leading-relaxed">
          <span className="font-semibold text-white block mb-1">{term}</span>
          {definition}
          <span className="absolute top-full left-1/2 -translate-x-1/2 -mt-px w-2 h-2 bg-slate-700 border-r border-b border-slate-600 rotate-45" />
        </span>
      )}
    </span>
  );
}
