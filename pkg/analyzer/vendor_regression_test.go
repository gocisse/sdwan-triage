package analyzer

// Vendor-PCAP regression harness (Phase 4.9).
//
// WHAT THIS IS
// It runs the real engine (the same steps as cmd/sdwan-triage: OpenCapture,
// config.LoadThresholds(""), NewProcessorWithOptions(false,false),
// ApplyThresholds, Process) on the four vendor captures and compares a STABLE
// PROJECTION of the resulting report against committed snapshots in
// testdata/vendor/.
//
// WHAT A GREEN RUN MEANS
// "Output unchanged." It does NOT mean "output correct". The snapshots pin the
// engine's CURRENT behavior, including any known defects (for example the
// distinct-flow retransmission count and the saturated risk score). They are
// not verified truth and no external reference (tshark) was used.
//
// HOW TO RUN
//   SDWAN_VENDOR_PCAP_DIR=/Users/mac/tools/VendorTestFile \
//     go test ./pkg/analyzer -run VendorRegression -count=1 -v
//   - Variable unset: the harness is SKIPPED (loudly). It did not run.
//   - Variable set but directory/PCAP missing: the test FAILS.
//   - Snapshots are rewritten ONLY with SDWAN_UPDATE_SNAPSHOTS=1 (in addition
//     to the directory variable). Review the diff of testdata/vendor/ before
//     committing an update.
//
// PROTECTED (projection): event counts per kind and dropped events;
// RootCauseChains (label, effect, basis, confidence, severity, evidence count);
// Findings (id, kind, severity, confidence, basis, evidence count); lengths of
// the legacy slices listed in sliceLengths; security finding counts; histograms
// of tunnel types and vendor DPI issues (order-independent); total bytes;
// RiskScore/RiskLevel; TopIssue/TopIssueCount; number of recommended actions.
// None of these varied across 6 repeated CLI runs on every PCAP.
//
// NOT PROTECTED by this harness (nondeterministic until Phase 4.10):
//   - streams, traffic_analysis, location_details: element ORDER varies between
//     runs (map iteration); location_details also varies in content on
//     Velocloud-Wan.
//   - tcp_handshake_flows, tcp_handshake_correlated_flows, ldap_flows,
//     tunnel_analysis, vendor_dpi_issues: element ORDER varies; only their
//     lengths / order-independent histograms are protected.
//   - dns_tunneling_findings: content varies on Velocloud-Lan (length not used).
//   - packet_loss, voip_analysis: content varies (floating point / map order).
//   - recommended_actions text and order, plain_english_summary: stable on
//     these captures but derived from code order and thresholds that Phase 4.10+
//     may touch; only the recommendation COUNT is protected.
//   - TopIssue: stable on these four captures, but it is chosen by map iteration
//     and is tie-prone in general; a tie on another capture would flap.
//   - Anything involving wall-clock time.
// NOT EXERCISED by the vendor captures: they contain no BGP/BFD events and no
// flow with >=3 retransmission events, so RootCauseChains and Findings are
// empty in every snapshot (the harness does protect against them APPEARING).
// Synthetic goldens (correlation_golden_test.go, findings_test.go) cover those.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/config"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

const (
	envVendorDir      = "SDWAN_VENDOR_PCAP_DIR"
	envUpdateSnapshot = "SDWAN_UPDATE_SNAPSHOTS"
	snapshotNote      = "Snapshot of CURRENT engine behavior on a vendor capture. Not verified truth: green means unchanged, not correct. Regenerate only with SDWAN_UPDATE_SNAPSHOTS=1 and review the diff."
)

var vendorPCAPs = []string{"Velocloud-Lan", "Velocloud-Wan", "cisco-example-lan", "cisco-example-wan"}

type chainProjection struct {
	Underlay      string `json:"underlay"`
	Overlay       string `json:"overlay"`
	Basis         string `json:"basis"`
	Confidence    string `json:"confidence"`
	Severity      string `json:"severity"`
	EvidenceCount int    `json:"evidence_count"`
}

type findingProjection struct {
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"`
	Basis         string `json:"basis"`
	EvidenceCount int    `json:"evidence_count"`
}

type vendorProjection struct {
	Note            string              `json:"_note"`
	PCAP            string              `json:"pcap"`
	EventCounts     map[string]int      `json:"event_counts"`
	EventsDropped   int                 `json:"events_dropped"`
	RootCauseChains []chainProjection   `json:"root_cause_chains"`
	Findings        []findingProjection `json:"findings"`
	SliceLengths    map[string]int      `json:"slice_lengths"`
	SecurityCounts  map[string]int      `json:"security_counts"`
	TunnelTypes     map[string]int      `json:"tunnel_types"`
	VendorDPIIssues map[string]int      `json:"vendor_dpi_issues"`
	TotalBytes      uint64              `json:"total_bytes"`
	RiskScore       int                 `json:"risk_score"`
	RiskLevel       string              `json:"risk_level"`
	TopIssue        string              `json:"top_issue"`
	TopIssueCount   int                 `json:"top_issue_count"`
	Recommendations int                 `json:"recommended_actions_count"`
}

// project reduces a report to the stable, order-independent projection.
func project(name string, r *models.TriageReport) vendorProjection {
	p := vendorProjection{
		Note: snapshotNote, PCAP: name,
		EventCounts:     map[string]int{},
		RootCauseChains: []chainProjection{},
		Findings:        []findingProjection{},
		TunnelTypes:     map[string]int{},
		VendorDPIIssues: map[string]int{},
		TotalBytes:      r.TotalBytes, RiskScore: r.RiskScore, RiskLevel: r.RiskLevel,
		TopIssue: r.TopIssue, TopIssueCount: r.TopIssueCount,
		Recommendations: len(r.RecommendedActions),
		EventsDropped:   r.EventsDropped,
	}
	for k, v := range r.EventCounts {
		p.EventCounts[k] = v
	}
	for _, c := range r.RootCauseChains {
		p.RootCauseChains = append(p.RootCauseChains, chainProjection{c.UnderlayEvent, c.OverlayEffect, c.EvidenceBasis, c.Confidence, c.Severity, c.EvidenceCount})
	}
	sort.SliceStable(p.RootCauseChains, func(i, j int) bool {
		a, b := p.RootCauseChains[i], p.RootCauseChains[j]
		return a.Underlay+"|"+a.Overlay+"|"+a.Basis < b.Underlay+"|"+b.Overlay+"|"+b.Basis
	})
	for _, f := range r.Findings {
		p.Findings = append(p.Findings, findingProjection{f.ID, f.Kind, string(f.Severity), string(f.Confidence), f.Basis, f.EvidenceCount})
	}
	for _, t := range r.TunnelAnalysis {
		p.TunnelTypes[t.Type]++
	}
	for _, v := range r.VendorDPIIssues {
		p.VendorDPIIssues[v.Vendor+"/"+v.IssueID]++
	}
	p.SliceLengths = map[string]int{
		"arp_conflicts":                  len(r.ARPConflicts),
		"bgp_hijack_indicators":          len(r.BGPHijackIndicators),
		"c2_beaconing_findings":          len(r.C2BeaconingFindings),
		"device_fingerprinting":          len(r.DeviceFingerprinting),
		"dhcp_findings":                  len(r.DHCPFindings),
		"dns_anomalies":                  len(r.DNSAnomalies),
		"dns_details":                    len(r.DNSDetails),
		"failed_handshakes":              len(r.FailedHandshakes),
		"http2_flows":                    len(r.HTTP2Flows),
		"http_errors":                    len(r.HTTPErrors),
		"icmp_analysis":                  len(r.ICMPAnalysis),
		"kerberos_flows":                 len(r.KerberosFlows),
		"ldap_flows":                     len(r.LDAPFlows),
		"ntp_findings":                   len(r.NTPFindings),
		"quic_flows":                     len(r.QUICFlows),
		"rtt_analysis":                   len(r.RTTAnalysis),
		"smb_flows":                      len(r.SMBFlows),
		"stability_findings":             len(r.StabilityFindings),
		"suspicious_traffic":             len(r.SuspiciousTraffic),
		"tcp_handshake_correlated_flows": len(r.TCPHandshakeCorrelatedFlows),
		"tcp_handshake_flows":            len(r.TCPHandshakeFlows),
		"tcp_out_of_order_flows":         len(r.TCPOutOfOrderFlows),
		"tcp_retransmissions":            len(r.TCPRetransmissions),
		"tcp_window_findings":            len(r.TCPWindowFindings),
		"threat_intel_matches":           len(r.ThreatIntelMatches),
		"tls_certs":                      len(r.TLSCerts),
		"tls_flows":                      len(r.TLSFlows),
		"traffic_gaps":                   len(r.TrafficGaps),
		"tunnel_analysis":                len(r.TunnelAnalysis),
		"vendor_dpi_issues":              len(r.VendorDPIIssues),
	}
	p.SecurityCounts = map[string]int{
		"ioc_findings":          len(r.Security.IOCFindings),
		"port_scan_findings":    len(r.Security.PortScanFindings),
		"tls_security_findings": len(r.Security.TLSSecurityFindings),
	}
	return p
}

// runVendorPCAP mirrors the CLI's default analysis path.
func runVendorPCAP(t *testing.T, path string) *models.TriageReport {
	t.Helper()
	handle, err := OpenCapture(path)
	if err != nil {
		t.Fatalf("open capture %s: %v", path, err)
	}
	defer handle.Close()

	report := &models.TriageReport{ApplicationBreakdown: make(map[string]models.AppCategory)}
	state := models.NewAnalysisState()
	thresholds, err := config.LoadThresholds("")
	if err != nil {
		t.Fatalf("load thresholds: %v", err)
	}
	p := NewProcessorWithOptions(false, false)
	p.ApplyThresholds(thresholds)
	if err := p.Process(handle.Reader, state, report, nil); err != nil {
		t.Fatalf("process %s: %v", path, err)
	}
	return report
}

func marshalProjection(p vendorProjection) []byte {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// lineDiff reports lines only in want (-) or only in got (+); enough to
// attribute a regression to a field without an external diff dependency.
func lineDiff(want, got string) string {
	toSet := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(s, "\n") {
			m[l]++
		}
		return m
	}
	ws, gs := toSet(want), toSet(got)
	var b strings.Builder
	for _, l := range strings.Split(want, "\n") {
		if gs[l] == 0 {
			fmt.Fprintf(&b, "- %s\n", l)
		}
	}
	for _, l := range strings.Split(got, "\n") {
		if ws[l] == 0 {
			fmt.Fprintf(&b, "+ %s\n", l)
		}
	}
	return b.String()
}

func TestVendorRegression(t *testing.T) {
	dir := os.Getenv(envVendorDir)
	update := os.Getenv(envUpdateSnapshot) == "1"
	if dir == "" {
		if update {
			t.Fatalf("%s=1 requires %s to be set", envUpdateSnapshot, envVendorDir)
		}
		t.Skipf("VENDOR PCAP REGRESSION HARNESS DID NOT RUN: %s is not set. Run with %s=<dir containing %s.pcap ...> go test ./pkg/analyzer -run VendorRegression -v",
			envVendorDir, envVendorDir, vendorPCAPs[0])
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("%s=%q is not an existing directory: %v", envVendorDir, dir, err)
	}
	var missing []string
	for _, n := range vendorPCAPs {
		if _, err := os.Stat(filepath.Join(dir, n+".pcap")); err != nil {
			missing = append(missing, n+".pcap")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%s=%q is missing expected captures: %s", envVendorDir, dir, strings.Join(missing, ", "))
	}

	for _, name := range vendorPCAPs {
		name := name
		t.Run(name, func(t *testing.T) {
			report := runVendorPCAP(t, filepath.Join(dir, name+".pcap"))
			got := marshalProjection(project(name, report))
			snap := filepath.Join("testdata", "vendor", name+".snapshot.json")

			if update {
				if err := os.MkdirAll(filepath.Dir(snap), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(snap, got, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("snapshot UPDATED: %s (review the diff before committing)", snap)
				return
			}

			want, err := os.ReadFile(snap)
			if err != nil {
				t.Fatalf("snapshot %s is missing (%v). Create it deliberately with %s=1 and review it", snap, err, envUpdateSnapshot)
			}
			if string(want) != string(got) {
				t.Errorf("vendor projection for %s changed (snapshot = previous behavior, not truth):\n%s", name, lineDiff(string(want), string(got)))
			}
		})
	}
}

// The projection itself must be deterministic for identical input; this runs
// without any PCAP and guards the harness's own ordering logic.
func TestVendorProjection_OrderIndependent(t *testing.T) {
	a := &models.TriageReport{
		TunnelAnalysis:  []models.TunnelFinding{{Type: "GRE"}, {Type: "IPsec"}, {Type: "GRE"}},
		VendorDPIIssues: []models.VendorDPIIssue{{Vendor: "X", IssueID: "1"}, {Vendor: "Y", IssueID: "2"}},
		RootCauseChains: []models.RootCauseChain{{UnderlayEvent: "B"}, {UnderlayEvent: "A"}},
	}
	b := &models.TriageReport{
		TunnelAnalysis:  []models.TunnelFinding{{Type: "GRE"}, {Type: "GRE"}, {Type: "IPsec"}},
		VendorDPIIssues: []models.VendorDPIIssue{{Vendor: "Y", IssueID: "2"}, {Vendor: "X", IssueID: "1"}},
		RootCauseChains: []models.RootCauseChain{{UnderlayEvent: "A"}, {UnderlayEvent: "B"}},
	}
	if string(marshalProjection(project("x", a))) != string(marshalProjection(project("x", b))) {
		t.Error("projection depends on element order")
	}
}
