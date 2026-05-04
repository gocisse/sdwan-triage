package analyzer

import (
	"fmt"
	"os"
	"runtime/debug"
	"sync"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
)

// PacketAnalyzer is the common interface for all packet detectors.
// Detectors that implement this interface can be registered in the DetectorRegistry
// and run in parallel or sequentially depending on their classification.
type PacketAnalyzer interface {
	// Name returns a human-readable name for the detector (used in logs and panic recovery)
	Name() string
	// Analyze processes a single packet, updating state and report as needed.
	// Implementations MUST be safe for concurrent reads on packet.
	// Writes to state and report are protected by their respective mutexes.
	Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport)
}

// DetectorRegistry holds two groups of detectors:
//   - IndependentAnalyzers: stateless or internally-synchronized detectors that can run in parallel.
//   - StatefulAnalyzers: detectors that share mutable state (e.g., SecurityState maps) and must run sequentially.
type DetectorRegistry struct {
	IndependentAnalyzers []PacketAnalyzer
	StatefulAnalyzers    []PacketAnalyzer
	verbose              bool
}

// NewDetectorRegistry creates an empty registry.
func NewDetectorRegistry(verbose bool) *DetectorRegistry {
	return &DetectorRegistry{
		verbose: verbose,
	}
}

// RegisterIndependent adds a detector to the parallel-safe group.
func (r *DetectorRegistry) RegisterIndependent(analyzers ...PacketAnalyzer) {
	r.IndependentAnalyzers = append(r.IndependentAnalyzers, analyzers...)
}

// RegisterStateful adds a detector to the sequential group.
func (r *DetectorRegistry) RegisterStateful(analyzers ...PacketAnalyzer) {
	r.StatefulAnalyzers = append(r.StatefulAnalyzers, analyzers...)
}

// AnalyzePacket runs all registered detectors on a packet.
// Independent detectors run concurrently via a WaitGroup; stateful detectors run sequentially afterward.
//
// Thread-safety strategy:
//   - AnalysisState: LRU caches are internally thread-safe; remaining maps use state.mu
//   - TriageReport: Each detector acquires report.Mu before writing (append to slices)
//   - SecurityState: Protected by its own mutex; only accessed by stateful (sequential) detectors
func (r *DetectorRegistry) AnalyzePacket(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	// Phase 1: Run independent (parallel-safe) detectors concurrently.
	// Each goroutine acquires report.Mu around the Analyze call to serialize report writes.
	// Parallelism benefit comes from concurrent packet layer parsing and filtering
	// that each detector performs before deciding whether to write.
	if len(r.IndependentAnalyzers) > 0 {
		var wg sync.WaitGroup
		wg.Add(len(r.IndependentAnalyzers))

		for _, analyzer := range r.IndependentAnalyzers {
			go func(a PacketAnalyzer) {
				defer wg.Done()
				// Lock report for the write phase — AnalysisState LRU caches
				// are already thread-safe from Step 1 refactor.
				// Use a nested func so defer Unlock runs before recoverDetector,
				// preventing deadlock if the analyzer panics while holding the lock.
				report.Mu.Lock()
				func() {
					defer report.Mu.Unlock()
					defer r.recoverDetector(a.Name())
					a.Analyze(packet, state, report)
				}()
			}(analyzer)
		}

		wg.Wait()
	}

	// Phase 2: Run stateful detectors sequentially (they share SecurityState maps).
	// These detectors write to SecurityState which is protected by its own mutex.
	for _, analyzer := range r.StatefulAnalyzers {
		func() {
			defer r.recoverDetector(analyzer.Name())
			analyzer.Analyze(packet, state, report)
		}()
	}
}

// recoverDetector catches panics from individual detectors so one crash doesn't kill the pipeline.
func (r *DetectorRegistry) recoverDetector(name string) {
	if rec := recover(); rec != nil {
		fmt.Fprintf(os.Stderr, "[PANIC] Detector %q crashed: %v\n", name, rec)
		if r.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG] Stack trace:\n%s\n", debug.Stack())
		}
	}
}

// --- Adapter helpers for detectors with non-standard method signatures ---

// AnalyzerFunc wraps a plain function as a PacketAnalyzer.
type AnalyzerFunc struct {
	name string
	fn   func(gopacket.Packet, *models.AnalysisState, *models.TriageReport)
}

func (a *AnalyzerFunc) Name() string { return a.name }
func (a *AnalyzerFunc) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	a.fn(packet, state, report)
}

// NewAnalyzerFunc creates a PacketAnalyzer from a function.
func NewAnalyzerFunc(name string, fn func(gopacket.Packet, *models.AnalysisState, *models.TriageReport)) PacketAnalyzer {
	return &AnalyzerFunc{name: name, fn: fn}
}

// PacketOnlyAnalyzer wraps detectors that only take a packet (no state/report).
type PacketOnlyAnalyzer struct {
	name string
	fn   func(gopacket.Packet)
}

func (a *PacketOnlyAnalyzer) Name() string { return a.name }
func (a *PacketOnlyAnalyzer) Analyze(packet gopacket.Packet, _ *models.AnalysisState, _ *models.TriageReport) {
	a.fn(packet)
}

// NewPacketOnlyAnalyzer creates a PacketAnalyzer from a packet-only function.
func NewPacketOnlyAnalyzer(name string, fn func(gopacket.Packet)) PacketAnalyzer {
	return &PacketOnlyAnalyzer{name: name, fn: fn}
}
