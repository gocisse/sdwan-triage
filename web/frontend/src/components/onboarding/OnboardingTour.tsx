// Lightweight onboarding tour — no external dependencies
// Uses localStorage flag 'onboarding_complete' to show only on first visit

import { useState, useEffect, useCallback } from 'react';
import { X, ChevronRight, ChevronLeft, Sparkles } from 'lucide-react';

interface TourStep {
  target: string;      // CSS selector for the target element
  title: string;
  content: string;
  placement: 'top' | 'bottom' | 'left' | 'right';
}

const TOUR_STEPS: TourStep[] = [
  {
    target: '[data-tour="summary"]',
    title: 'Welcome to SD-WAN Triage',
    content: 'This is your executive summary — a quick snapshot of your network health, risk score, and top issues at a glance.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="sidebar"]',
    title: 'Review Critical Findings',
    content: 'Use the issue sidebar to filter by category: Security, Performance, Stability, SD-WAN, and Infrastructure. Red badges = issues, grey = informational.',
    placement: 'right',
  },
  {
    target: '[data-tour="filter-bar"]',
    title: 'Filter Like Wireshark',
    content: 'Type display filters here (e.g. ip.addr == 10.0.0.1 && tcp.port == 443). Supports AND logic, field autocomplete, and instant results.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="drill-down"]',
    title: 'Deep Dive into Streams',
    content: 'Switch to Forensic Drill-Down for IO Graphs, Protocol Hierarchy, Conversations, Expert Info, and Packet Search — just like Wireshark.',
    placement: 'bottom',
  },
  {
    target: '[data-tour="export"]',
    title: 'Export Your Report',
    content: 'Download results as JSON or a styled HTML report. Use the Export PCAP button to carve filtered packets into a new capture file.',
    placement: 'bottom',
  },
];

const STORAGE_KEY = 'onboarding_complete';

export function OnboardingTour() {
  const [currentStep, setCurrentStep] = useState(0);
  const [isActive, setIsActive] = useState(false);
  const [spotlightRect, setSpotlightRect] = useState<DOMRect | null>(null);

  // Show on first visit only
  useEffect(() => {
    const done = localStorage.getItem(STORAGE_KEY);
    if (!done) {
      // Small delay to let page render
      const timer = setTimeout(() => setIsActive(true), 800);
      return () => clearTimeout(timer);
    }
  }, []);

  // Compute spotlight position
  useEffect(() => {
    if (!isActive) return;
    const step = TOUR_STEPS[currentStep];
    const el = document.querySelector(step.target);
    if (el) {
      const rect = el.getBoundingClientRect();
      setSpotlightRect(rect);
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else {
      setSpotlightRect(null);
    }
  }, [currentStep, isActive]);

  const finish = useCallback(() => {
    setIsActive(false);
    localStorage.setItem(STORAGE_KEY, 'true');
  }, []);

  const next = useCallback(() => {
    if (currentStep < TOUR_STEPS.length - 1) {
      setCurrentStep(s => s + 1);
    } else {
      finish();
    }
  }, [currentStep, finish]);

  const prev = useCallback(() => {
    if (currentStep > 0) setCurrentStep(s => s - 1);
  }, [currentStep]);

  // Close on Escape
  useEffect(() => {
    if (!isActive) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') finish();
      if (e.key === 'ArrowRight') next();
      if (e.key === 'ArrowLeft') prev();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isActive, finish, next, prev]);

  if (!isActive) return null;

  const step = TOUR_STEPS[currentStep];
  const isLast = currentStep === TOUR_STEPS.length - 1;

  // Tooltip position
  const tooltipStyle: React.CSSProperties = {};
  if (spotlightRect) {
    const pad = 16;
    switch (step.placement) {
      case 'bottom':
        tooltipStyle.top = spotlightRect.bottom + pad;
        tooltipStyle.left = Math.max(16, spotlightRect.left + spotlightRect.width / 2 - 180);
        break;
      case 'top':
        tooltipStyle.bottom = window.innerHeight - spotlightRect.top + pad;
        tooltipStyle.left = Math.max(16, spotlightRect.left + spotlightRect.width / 2 - 180);
        break;
      case 'right':
        tooltipStyle.top = spotlightRect.top + spotlightRect.height / 2 - 60;
        tooltipStyle.left = spotlightRect.right + pad;
        break;
      case 'left':
        tooltipStyle.top = spotlightRect.top + spotlightRect.height / 2 - 60;
        tooltipStyle.right = window.innerWidth - spotlightRect.left + pad;
        break;
    }
  } else {
    // Fallback: center
    tooltipStyle.top = '50%';
    tooltipStyle.left = '50%';
    tooltipStyle.transform = 'translate(-50%, -50%)';
  }

  return (
    <div className="fixed inset-0 z-[100]" onClick={finish}>
      {/* Overlay with spotlight cutout */}
      <svg className="absolute inset-0 w-full h-full" style={{ pointerEvents: 'none' }}>
        <defs>
          <mask id="tour-mask">
            <rect x="0" y="0" width="100%" height="100%" fill="white" />
            {spotlightRect && (
              <rect
                x={spotlightRect.left - 8}
                y={spotlightRect.top - 8}
                width={spotlightRect.width + 16}
                height={spotlightRect.height + 16}
                rx="12"
                fill="black"
              />
            )}
          </mask>
        </defs>
        <rect
          x="0" y="0" width="100%" height="100%"
          fill="rgba(0,0,0,0.65)"
          mask="url(#tour-mask)"
        />
      </svg>

      {/* Spotlight ring */}
      {spotlightRect && (
        <div
          className="absolute border-2 border-purple-400 rounded-xl shadow-lg shadow-purple-500/30 pointer-events-none"
          style={{
            top: spotlightRect.top - 8,
            left: spotlightRect.left - 8,
            width: spotlightRect.width + 16,
            height: spotlightRect.height + 16,
          }}
        />
      )}

      {/* Tooltip card */}
      <div
        className="absolute w-[360px] bg-slate-800 border border-slate-600 rounded-2xl shadow-2xl shadow-purple-500/10"
        style={tooltipStyle}
        onClick={e => e.stopPropagation()}
      >
        <div className="px-5 py-4">
          <div className="flex items-center gap-2 mb-2">
            <Sparkles className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-bold text-white">{step.title}</h3>
            <button
              onClick={finish}
              className="ml-auto p-1 rounded hover:bg-slate-700 transition-colors"
            >
              <X className="w-3.5 h-3.5 text-slate-400" />
            </button>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">{step.content}</p>
        </div>

        <div className="flex items-center justify-between px-5 py-3 border-t border-slate-700/50">
          <span className="text-xs text-slate-500">{currentStep + 1} / {TOUR_STEPS.length}</span>
          <div className="flex items-center gap-2">
            {currentStep > 0 && (
              <button
                onClick={prev}
                className="flex items-center gap-1 px-3 py-1.5 text-xs text-slate-400 hover:text-white rounded-lg hover:bg-slate-700 transition-colors"
              >
                <ChevronLeft className="w-3 h-3" />
                Back
              </button>
            )}
            <button
              onClick={next}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-purple-600 hover:bg-purple-500 rounded-lg transition-colors"
            >
              {isLast ? 'Finish' : 'Next'}
              {!isLast && <ChevronRight className="w-3 h-3" />}
            </button>
          </div>
        </div>

        {/* Progress dots */}
        <div className="flex justify-center gap-1.5 pb-3">
          {TOUR_STEPS.map((_, i) => (
            <div
              key={i}
              className={`w-1.5 h-1.5 rounded-full transition-colors ${
                i === currentStep ? 'bg-purple-400' : i < currentStep ? 'bg-purple-600' : 'bg-slate-600'
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

// Hook to allow manually restarting the tour
export function useResetOnboarding() {
  return useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    window.location.reload();
  }, []);
}
