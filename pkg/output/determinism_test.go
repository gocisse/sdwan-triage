package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Report data derived from maps must come out in a fixed order.

func TestDeterminism_MapKeysToSlice(t *testing.T) {
	m := map[string]bool{}
	for i := 0; i < 30; i++ {
		m[fmt.Sprintf("host-%02d", i)] = true
	}
	for i := 0; i < 100; i++ {
		if got := mapKeysToSlice(m); !sort.StringsAreSorted(got) || len(got) != 30 {
			t.Fatalf("run %d: not sorted: %v", i, got)
		}
	}
}

func TestDeterminism_GeoLocationsCSVAndView(t *testing.T) {
	loc := map[string]int{}
	ips := map[string][]string{}
	for i := 0; i < 25; i++ { // all counts tie
		c := fmt.Sprintf("Country%02d", i)
		loc[c] = 3
		ips[c] = []string{"192.0.2.1"}
	}
	var first, firstView string
	for run := 0; run < 60; run++ {
		path := filepath.Join(t.TempDir(), "geo.csv")
		if err := generateGeoLocationsCSV(loc, path); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		view := fmt.Sprint(convertGeoLocations(loc, ips))
		if run == 0 {
			first, firstView = string(b), view
			continue
		}
		if string(b) != first || view != firstView {
			t.Fatalf("run %d: geo output differs", run)
		}
	}
}

func TestDeterminism_TrafficStatsTies(t *testing.T) {
	r := &models.TriageReport{ApplicationBreakdown: map[string]models.AppCategory{}}
	for i := 0; i < 20; i++ {
		r.ApplicationBreakdown[fmt.Sprintf("app%02d", i)] = models.AppCategory{Name: fmt.Sprintf("app%02d", i), Protocol: fmt.Sprintf("P%02d", i), ByteCount: 100, PacketCount: 5}
		r.TrafficAnalysis = append(r.TrafficAnalysis, models.TrafficFlow{SrcIP: fmt.Sprintf("10.0.0.%d", i), DstIP: "10.9.9.9", TotalBytes: 1000})
	}
	p0, t0 := generateTrafficStats(r)
	a0 := convertApplicationStats(r.ApplicationBreakdown)
	n0 := generateNetworkJSON(r)
	for i := 0; i < 80; i++ {
		p, tt := generateTrafficStats(r)
		if fmt.Sprint(p) != fmt.Sprint(p0) || fmt.Sprint(tt) != fmt.Sprint(t0) {
			t.Fatalf("run %d: traffic stats differ", i)
		}
		if fmt.Sprint(convertApplicationStats(r.ApplicationBreakdown)) != fmt.Sprint(a0) {
			t.Fatalf("run %d: application stats differ", i)
		}
		if generateNetworkJSON(r) != n0 {
			t.Fatalf("run %d: network JSON differs", i)
		}
	}
}
