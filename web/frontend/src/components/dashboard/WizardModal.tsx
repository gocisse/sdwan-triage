// Guided Investigation Wizard - Interactive troubleshooting guide for junior engineers
// Step 1: Symptom Selection → Step 2: Follow-up Questions → Step 3: Prioritized Findings

import { useState, useCallback } from 'react';
import { X, ChevronRight, ChevronLeft, Sparkles, ArrowRight, CheckCircle2, Terminal, Monitor, Code2 } from 'lucide-react';
import type { AnalysisResults } from '../../types';
import { wizardSymptoms, getActiveFindings, computeWizardResults, type WizardSymptom, type WizardResult } from '../../data/wizardData';
import { issueKnowledgeBase } from '../../data/knowledgeBase';
import { getVendorRunbook, getVendorFindingRunbook } from '../../data/vendorRunbooks';
import type { VendorRunbook as VendorRunbookType, VendorFindingRunbook } from '../../data/vendorRunbooks';

interface WizardModalProps {
  results: AnalysisResults;
  isOpen: boolean;
  onClose: () => void;
  onNavigateToFinding?: (findingKey: string) => void;
  detectedVendors?: string[];
}

type WizardStep = 'symptoms' | 'followup' | 'results';

export function WizardModal({ results, isOpen, onClose, onNavigateToFinding, detectedVendors }: WizardModalProps) {
  const [step, setStep] = useState<WizardStep>('symptoms');
  const [selectedSymptom, setSelectedSymptom] = useState<WizardSymptom | null>(null);
  const [followUpAnswers, setFollowUpAnswers] = useState<Record<string, string>>({});
  const [currentFollowUp, setCurrentFollowUp] = useState(0);
  const [wizardResults, setWizardResults] = useState<WizardResult[]>([]);

  const activeFindings = getActiveFindings(results);

  const reset = useCallback(() => {
    setStep('symptoms');
    setSelectedSymptom(null);
    setFollowUpAnswers({});
    setCurrentFollowUp(0);
    setWizardResults([]);
  }, []);

  const handleSymptomSelect = useCallback((symptom: WizardSymptom) => {
    setSelectedSymptom(symptom);
    setFollowUpAnswers({});
    setCurrentFollowUp(0);

    if (symptom.followUpQuestions.length === 0) {
      // Skip to results for "show everything"
      const results = computeWizardResults(symptom, {}, activeFindings);
      setWizardResults(results);
      setStep('results');
    } else {
      setStep('followup');
    }
  }, [activeFindings]);

  const handleFollowUpAnswer = useCallback((questionId: string, value: string) => {
    const newAnswers = { ...followUpAnswers, [questionId]: value };
    setFollowUpAnswers(newAnswers);

    if (selectedSymptom && currentFollowUp < selectedSymptom.followUpQuestions.length - 1) {
      setCurrentFollowUp(prev => prev + 1);
    } else if (selectedSymptom) {
      const results = computeWizardResults(selectedSymptom, newAnswers, activeFindings);
      setWizardResults(results);
      setStep('results');
    }
  }, [followUpAnswers, selectedSymptom, currentFollowUp, activeFindings]);

  const handleClose = useCallback(() => {
    reset();
    onClose();
  }, [reset, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={handleClose} />

      {/* Modal */}
      <div className="relative bg-slate-800 border border-slate-700/50 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-blue-500 flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Troubleshooting Wizard</h2>
              <p className="text-xs text-slate-400">
                {step === 'symptoms' && 'What problem are you experiencing?'}
                {step === 'followup' && `Question ${currentFollowUp + 1} of ${selectedSymptom?.followUpQuestions.length}`}
                {step === 'results' && `${wizardResults.length} relevant finding${wizardResults.length !== 1 ? 's' : ''} identified`}
              </p>
            </div>
          </div>
          <button onClick={handleClose} className="p-2 rounded-lg hover:bg-slate-700 transition-colors">
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Progress Bar */}
        <div className="px-6 pt-3">
          <div className="flex items-center gap-2">
            {['symptoms', 'followup', 'results'].map((s, i) => (
              <div key={s} className="flex items-center gap-2 flex-1">
                <div className={`h-1.5 rounded-full flex-1 transition-all ${
                  s === step ? 'bg-blue-500' :
                  ['symptoms', 'followup', 'results'].indexOf(step) > i ? 'bg-blue-500/50' : 'bg-slate-700'
                }`} />
              </div>
            ))}
          </div>
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-slate-500">Symptoms</span>
            <span className="text-[10px] text-slate-500">Details</span>
            <span className="text-[10px] text-slate-500">Findings</span>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-4">
          {/* Step 1: Symptom Selection */}
          {step === 'symptoms' && (
            <div className="space-y-3">
              <p className="text-sm text-slate-300 mb-4">Select the symptom that best describes what you're seeing:</p>
              {wizardSymptoms.map(symptom => {
                const matchCount = symptom.relatedFindings.filter(f => activeFindings.has(f)).length;
                return (
                  <button
                    key={symptom.id}
                    onClick={() => handleSymptomSelect(symptom)}
                    className="w-full text-left p-4 rounded-xl border border-slate-700/50 hover:border-blue-500/50 hover:bg-slate-700/30 transition-all group"
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-2xl">{symptom.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <h3 className="font-semibold text-white text-sm group-hover:text-blue-300 transition-colors">
                            {symptom.label}
                          </h3>
                          {matchCount > 0 && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30">
                              {matchCount} match{matchCount !== 1 ? 'es' : ''}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">{symptom.description}</p>
                      </div>
                      <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-blue-400 transition-colors flex-shrink-0 mt-1" />
                    </div>
                  </button>
                );
              })}
            </div>
          )}

          {/* Step 2: Follow-up Questions */}
          {step === 'followup' && selectedSymptom && (
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-2">
                <button
                  onClick={() => {
                    if (currentFollowUp > 0) {
                      setCurrentFollowUp(prev => prev - 1);
                    } else {
                      setStep('symptoms');
                    }
                  }}
                  className="p-1.5 rounded-lg hover:bg-slate-700 transition-colors"
                >
                  <ChevronLeft className="w-4 h-4 text-slate-400" />
                </button>
                <span className="text-sm text-slate-300">
                  {selectedSymptom.followUpQuestions[currentFollowUp]?.question}
                </span>
              </div>

              <div className="space-y-2">
                {selectedSymptom.followUpQuestions[currentFollowUp]?.options.map(option => {
                  const isSelected = followUpAnswers[selectedSymptom.followUpQuestions[currentFollowUp].id] === option.value;
                  return (
                    <button
                      key={option.value}
                      onClick={() => handleFollowUpAnswer(
                        selectedSymptom.followUpQuestions[currentFollowUp].id,
                        option.value
                      )}
                      className={`w-full text-left p-4 rounded-xl border transition-all ${
                        isSelected
                          ? 'border-blue-500 bg-blue-500/10'
                          : 'border-slate-700/50 hover:border-blue-500/30 hover:bg-slate-700/30'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center flex-shrink-0 ${
                          isSelected ? 'border-blue-500 bg-blue-500' : 'border-slate-600'
                        }`}>
                          {isSelected && <div className="w-2 h-2 rounded-full bg-white" />}
                        </div>
                        <span className={`text-sm ${isSelected ? 'text-blue-300' : 'text-slate-300'}`}>
                          {option.label}
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Step 3: Results */}
          {step === 'results' && (
            <div className="space-y-4">
              {wizardResults.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto mb-3" />
                  <h3 className="text-lg font-semibold text-white mb-2">No matching issues found</h3>
                  <p className="text-sm text-slate-400 max-w-md mx-auto">
                    Based on your symptoms, no matching findings were detected in this capture.
                    The issue may not be visible in this PCAP, or it may have resolved.
                  </p>
                </div>
              ) : (
                <>
                  <p className="text-sm text-slate-300">
                    Based on your answers, here are the most likely causes, ordered by relevance:
                  </p>

                  {wizardResults.map((result, i) => {
                    const knowledge = issueKnowledgeBase[result.findingKey];

                    // Priority lookup: vendor-specific runbook first, then generic knowledgeBase
                    const vendorMatch = detectedVendors && detectedVendors.length > 0
                      ? (() => {
                          for (const v of detectedVendors) {
                            const rb = getVendorRunbook(v);
                            const frb = getVendorFindingRunbook(v, result.findingKey);
                            if (rb && frb) return { vendor: rb, finding: frb };
                          }
                          return null;
                        })()
                      : null;

                    return (
                      <div
                        key={result.findingKey}
                        className={`p-4 rounded-xl border transition-all ${
                          result.isRootCause
                            ? 'border-amber-500/50 bg-amber-500/5 ring-1 ring-amber-500/20'
                            : 'border-slate-700/50 bg-slate-800/50'
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                            result.isRootCause ? 'bg-amber-500/20' : 'bg-slate-700/50'
                          }`}>
                            <span className={`text-sm font-bold ${
                              result.isRootCause ? 'text-amber-400' : 'text-slate-400'
                            }`}>
                              {i + 1}
                            </span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <h4 className="font-semibold text-white text-sm">{result.label}</h4>
                              {result.isRootCause && (
                                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 uppercase tracking-wider">
                                  Start Here
                                </span>
                              )}
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                                result.confidence === 'high' ? 'bg-green-500/20 text-green-400 border border-green-500/30' :
                                result.confidence === 'medium' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                'bg-slate-600/20 text-slate-400 border border-slate-500/30'
                              }`}>
                                {result.confidence} confidence
                              </span>
                            </div>
                            <p className="text-xs text-slate-400 mt-1">{result.explanation}</p>

                            {/* ELI5 from knowledgeBase (always shown if available) */}
                            {knowledge?.eli5 && (
                              <p className="text-xs text-slate-300 mt-3">{knowledge.eli5}</p>
                            )}

                            {/* Vendor-specific runbook steps (priority over generic) */}
                            {vendorMatch ? (
                              <WizardVendorSteps vendor={vendorMatch.vendor} finding={vendorMatch.finding} />
                            ) : knowledge ? (
                              <div className="mt-3 space-y-2">
                                <ol className="space-y-2 max-h-64 overflow-y-auto">
                                  {knowledge.how.map((step, j) => (
                                    <li key={j} className="flex items-start gap-2 text-xs">
                                      <span className="w-4 h-4 rounded-full bg-green-500/20 text-green-400 flex items-center justify-center flex-shrink-0 text-[10px] font-bold mt-0.5">
                                        {j + 1}
                                      </span>
                                      <span className="text-slate-300">{step}</span>
                                    </li>
                                  ))}
                                </ol>
                              </div>
                            ) : null}

                            {onNavigateToFinding && (
                              <button
                                onClick={() => {
                                  onNavigateToFinding(result.findingKey);
                                  handleClose();
                                }}
                                className="mt-3 inline-flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                              >
                                View full details
                                <ArrowRight className="w-3 h-3" />
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-700/50 flex items-center justify-between">
          {step !== 'symptoms' ? (
            <button
              onClick={() => {
                if (step === 'results') {
                  if (selectedSymptom && selectedSymptom.followUpQuestions.length > 0) {
                    setStep('followup');
                    setCurrentFollowUp(selectedSymptom.followUpQuestions.length - 1);
                  } else {
                    setStep('symptoms');
                  }
                } else {
                  setStep('symptoms');
                }
              }}
              className="flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
              Back
            </button>
          ) : (
            <div />
          )}

          <div className="flex items-center gap-2">
            {activeFindings.size > 0 && (
              <span className="text-xs text-slate-500">
                {activeFindings.size} total finding{activeFindings.size !== 1 ? 's' : ''} in capture
              </span>
            )}
            <button
              onClick={reset}
              className="text-xs text-slate-400 hover:text-white transition-colors px-3 py-1.5 rounded-lg hover:bg-slate-700"
            >
              Start Over
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Inline Vendor Steps for Wizard Results ──────────────────
// Compact rendering of vendor-specific diagnose → fix → verify steps
function WizardVendorSteps({ vendor, finding }: { vendor: VendorRunbookType; finding: VendorFindingRunbook }) {
  const phases = [
    { key: 'diagnose' as const, label: 'Diagnose', color: 'blue' },
    { key: 'fix' as const, label: 'Fix', color: 'amber' },
    { key: 'verify' as const, label: 'Verify', color: 'green' },
  ];

  const methodIcon = (m: string) => {
    switch (m) {
      case 'cli': return <Terminal className="w-3 h-3" />;
      case 'gui': return <Monitor className="w-3 h-3" />;
      case 'script': return <Code2 className="w-3 h-3" />;
      default: return null;
    }
  };

  return (
    <div className="mt-3 space-y-3">
      <div className="flex items-center gap-2">
        <span className={`text-xs font-bold ${vendor.color}`}>{vendor.logo}</span>
        <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{vendor.vendor} Runbook</span>
      </div>
      {phases.map(({ key, label, color }) => {
        const phase = finding[key];
        const methods = (['cli', 'gui', 'script'] as const).filter(m => phase[m] && phase[m]!.length > 0);
        if (methods.length === 0) return null;
        return (
          <div key={key}>
            <span className={`text-[10px] font-bold uppercase tracking-wider text-${color}-400`}>{label}</span>
            <div className="mt-1 space-y-1">
              {methods.map(method => (
                <div key={method}>
                  {phase[method]!.map((step, j) => (
                    <div key={j} className="flex items-start gap-2 text-xs py-0.5">
                      <span className="flex-shrink-0 mt-0.5 text-slate-500">{methodIcon(method)}</span>
                      <span className="text-slate-300">{step}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        );
      })}
      {finding.warnings.length > 0 && (
        <div className="text-[10px] text-amber-400/80 mt-1">
          ⚠ {finding.warnings[0]}
        </div>
      )}
    </div>
  );
}
