package detector

import (
	"fmt"
	"testing"
)

// Shannon entropy sums -p*log2(p) over a map of character frequencies; float
// addition is order-dependent, so the result (and a threshold decision near the
// boundary) used to vary between runs.
func TestDeterminism_SubdomainEntropyIsStable(t *testing.T) {
	subs := map[string]bool{}
	for i := 0; i < 60; i++ {
		subs[fmt.Sprintf("x%dq%dzk%d", i*7, i*13, i*i)] = true
	}
	first := calculateSubdomainEntropy(subs)
	for i := 0; i < 300; i++ {
		if got := calculateSubdomainEntropy(subs); got != first {
			t.Fatalf("run %d: entropy %.17g != %.17g", i, got, first)
		}
	}
}
