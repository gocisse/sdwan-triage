package analyzer

import (
	"sync/atomic"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
)

// mockAnalyzer is a test PacketAnalyzer that tracks invocations.
type mockAnalyzer struct {
	name  string
	calls int64 // atomic counter for concurrent safety
}

func (m *mockAnalyzer) Name() string { return m.name }
func (m *mockAnalyzer) Analyze(_ gopacket.Packet, _ *models.AnalysisState, _ *models.TriageReport) {
	atomic.AddInt64(&m.calls, 1)
}

// panicAnalyzer always panics — used to verify recovery.
type panicAnalyzer struct{ name string }

func (p *panicAnalyzer) Name() string { return p.name }
func (p *panicAnalyzer) Analyze(_ gopacket.Packet, _ *models.AnalysisState, _ *models.TriageReport) {
	panic("intentional test panic")
}

func TestDetectorRegistry_AllDetectorsRun(t *testing.T) {
	reg := NewDetectorRegistry(false)

	ind1 := &mockAnalyzer{name: "ind-1"}
	ind2 := &mockAnalyzer{name: "ind-2"}
	ind3 := &mockAnalyzer{name: "ind-3"}
	seq1 := &mockAnalyzer{name: "seq-1"}
	seq2 := &mockAnalyzer{name: "seq-2"}

	reg.RegisterIndependent(ind1, ind2, ind3)
	reg.RegisterStateful(seq1, seq2)

	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Run 100 packets through the registry
	for i := 0; i < 100; i++ {
		reg.AnalyzePacket(nil, state, report)
	}

	// Every detector should have been called exactly 100 times
	for _, m := range []*mockAnalyzer{ind1, ind2, ind3, seq1, seq2} {
		got := atomic.LoadInt64(&m.calls)
		if got != 100 {
			t.Errorf("detector %q: got %d calls, want 100", m.name, got)
		}
	}
}

func TestDetectorRegistry_PanicRecovery(t *testing.T) {
	reg := NewDetectorRegistry(false)

	good := &mockAnalyzer{name: "good"}
	bad := &panicAnalyzer{name: "bad-panicker"}

	// Independent group: one panics, the other should still run
	reg.RegisterIndependent(good, bad)

	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Should not panic
	reg.AnalyzePacket(nil, state, report)

	if atomic.LoadInt64(&good.calls) != 1 {
		t.Error("good detector should have been called despite panic in sibling")
	}
}

func TestDetectorRegistry_StatefulPanicRecovery(t *testing.T) {
	reg := NewDetectorRegistry(false)

	before := &mockAnalyzer{name: "before"}
	bad := &panicAnalyzer{name: "bad-stateful"}
	after := &mockAnalyzer{name: "after"}

	reg.RegisterStateful(before, bad, after)

	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	reg.AnalyzePacket(nil, state, report)

	if atomic.LoadInt64(&before.calls) != 1 {
		t.Error("'before' detector should have run")
	}
	if atomic.LoadInt64(&after.calls) != 1 {
		t.Error("'after' detector should have run despite panic in 'bad-stateful'")
	}
}

func TestDetectorRegistry_AnalyzerFuncAdapter(t *testing.T) {
	var called bool
	a := NewAnalyzerFunc("test-func", func(_ gopacket.Packet, _ *models.AnalysisState, _ *models.TriageReport) {
		called = true
	})

	if a.Name() != "test-func" {
		t.Errorf("Name() = %q, want %q", a.Name(), "test-func")
	}

	a.Analyze(nil, nil, nil)
	if !called {
		t.Error("AnalyzerFunc should have been called")
	}
}

func TestDetectorRegistry_PacketOnlyAdapter(t *testing.T) {
	var called bool
	a := NewPacketOnlyAnalyzer("pkt-only", func(_ gopacket.Packet) {
		called = true
	})

	if a.Name() != "pkt-only" {
		t.Errorf("Name() = %q, want %q", a.Name(), "pkt-only")
	}

	a.Analyze(nil, nil, nil)
	if !called {
		t.Error("PacketOnlyAnalyzer should have been called")
	}
}

func TestDetectorRegistry_EmptyRegistry(t *testing.T) {
	reg := NewDetectorRegistry(false)
	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	// Should not panic with empty registry
	reg.AnalyzePacket(nil, state, report)
}

func BenchmarkDetectorRegistry_Parallel(b *testing.B) {
	reg := NewDetectorRegistry(false)

	// Register 25 independent + 10 stateful (similar to real workload)
	for i := 0; i < 25; i++ {
		reg.RegisterIndependent(&mockAnalyzer{name: "ind"})
	}
	for i := 0; i < 10; i++ {
		reg.RegisterStateful(&mockAnalyzer{name: "seq"})
	}

	state := models.NewAnalysisState()
	report := &models.TriageReport{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg.AnalyzePacket(nil, state, report)
	}
}
