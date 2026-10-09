package analyzer

import (
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket/layers"
)

// Phase 4.40 — the legacy DNS headline (risk score, top issue, recommended actions,
// plain-English summary) counts only server failures and private-address answers,
// never names an attack the capture does not show, and points at the evidence sections.

func dnsAnoms(kind string, n int) []models.DNSAnomaly {
	out := make([]models.DNSAnomaly, n)
	for i := range out {
		out[i] = models.DNSAnomaly{Kind: kind, Query: "q.example.net"}
	}
	return out
}

func scored(r *models.TriageReport) *models.TriageReport {
	NewProcessorWithOptions(false, false).calculateRiskScore(r)
	return r
}

var headlineBanned = []string{"hijacking", "poisoning", "malware"}

func assertNoAttackWords(t *testing.T, r *models.TriageReport) {
	t.Helper()
	all := strings.ToLower(strings.Join(r.RecommendedActions, "\n"))
	if r.PlainEnglishSummary != nil {
		all += strings.ToLower(strings.Join(r.PlainEnglishSummary.KeyFindings, "\n"))
	}
	for _, b := range headlineBanned {
		if strings.Contains(all, b) {
			t.Errorf("headline contains %q:\n%s", b, all)
		}
	}
}

func TestDNSHeadline_ObservationKindsDoNotScoreOrBecomeTheTopIssue(t *testing.T) {
	r := &models.TriageReport{}
	for _, k := range []string{models.DNSKindNXDomain, models.DNSKindNoResponse, models.DNSKindNonStandardServer, models.DNSKindSuspiciousDomain} {
		r.DNSAnomalies = append(r.DNSAnomalies, dnsAnoms(k, 300)...)
	}
	scored(r)
	if r.RiskScore != 0 || r.RiskLevel != "Low" || r.TopIssue != "" || r.TopIssueCount != 0 {
		t.Errorf("risk %d/%s top %q/%d from ordinary DNS observations", r.RiskScore, r.RiskLevel, r.TopIssue, r.TopIssueCount)
	}
	for _, a := range r.RecommendedActions {
		if strings.Contains(a, "DNS") {
			t.Errorf("DNS action for ordinary observations: %s", a)
		}
	}
	assertNoAttackWords(t, r)
}

func TestDNSHeadline_ServerFailuresAndPrivateAnswersStillScore(t *testing.T) {
	r := &models.TriageReport{DNSAnomalies: append(append(dnsAnoms(models.DNSKindServerFailure, 2), dnsAnoms(models.DNSKindPrivateAnswer, 1)...), dnsAnoms(models.DNSKindNXDomain, 50)...)}
	scored(r)
	if r.RiskScore != 30 || r.TopIssue != "DNS Anomalies" || r.TopIssueCount != 3 {
		t.Fatalf("risk %d top %q/%d, want 30 / DNS Anomalies / 3", r.RiskScore, r.TopIssue, r.TopIssueCount)
	}
	a := r.RecommendedActions[0]
	for _, must := range []string{"2 DNS server failure response(s)", "1 private-address answer(s)", "split-horizon or filtering DNS as well as manipulation", "dns_anomalies", "dns_resolver_summary"} {
		if !strings.Contains(a, must) {
			t.Errorf("action lacks %q: %s", must, a)
		}
	}
	assertNoAttackWords(t, r)
	// Server failures alone: no private-answer sentence.
	r = scored(&models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 1)})
	if strings.Contains(r.RecommendedActions[0], "private") {
		t.Errorf("private-answer text without a private answer: %s", r.RecommendedActions[0])
	}
}

// Anomalies without a kind (older reports) keep counting, as before.
func TestDNSHeadline_UnclassifiedAnomaliesStillCount(t *testing.T) {
	r := scored(&models.TriageReport{DNSAnomalies: make([]models.DNSAnomaly, 3)})
	if r.RiskScore != 30 || r.TopIssue != "DNS Anomalies" || r.TopIssueCount != 3 {
		t.Errorf("risk %d top %q/%d", r.RiskScore, r.TopIssue, r.TopIssueCount)
	}
}

func TestDNSHeadline_TopIssueIsChosenAmongRealIssues(t *testing.T) {
	r := scored(&models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindNXDomain, 1000), TCPRetransmissions: make([]models.TCPFlow, 3)})
	if r.TopIssue != "TCP Retransmissions" || r.TopIssueCount != 3 || r.RiskScore != 15 {
		t.Errorf("top %q/%d risk %d", r.TopIssue, r.TopIssueCount, r.RiskScore)
	}
}

func TestDNSHeadline_TunnelingHeuristicIsNotPresentedAsMalware(t *testing.T) {
	r := &models.TriageReport{DNSTunnelingFindings: []models.DNSTunnelingFinding{{SourceIP: "172.26.88.17", Domain: "microsoft.com", Severity: "Warning", QueryCount: 20}}}
	scored(r)
	if r.RiskScore != 15 { // scoring weight of the heuristic is unchanged by this phase
		t.Errorf("risk = %d", r.RiskScore)
	}
	a := strings.Join(r.RecommendedActions, "\n")
	for _, must := range []string{"heuristic", "legitimate infrastructure and cloud domains can trigger it", "not confirmation of tunneling or of malicious activity", "dns_tunneling_findings"} {
		if !strings.Contains(a, must) {
			t.Errorf("action lacks %q: %s", must, a)
		}
	}
	if strings.Contains(a, "CRITICAL") || strings.Contains(a, "Investigate the source host") {
		t.Errorf("tunneling action still alarmist: %s", a)
	}
	assertNoAttackWords(t, r)
}

// Attack wording is not removed where independent evidence supports it, and unrelated
// actions are unchanged.
func TestDNSHeadline_OtherActionsAndIOCWordingAreUnchanged(t *testing.T) {
	r := scored(&models.TriageReport{Security: models.SecurityAnalysis{IOCFindings: make([]models.IOCFinding, 1)}, TCPWindowFindings: make([]models.TCPWindowFinding, 1)})
	a := strings.Join(r.RecommendedActions, "\n")
	if !strings.Contains(a, "CRITICAL: Indicators of Compromise detected. Isolate affected systems and perform forensic analysis.") ||
		!strings.Contains(a, "MEDIUM: TCP window size issues detected.") {
		t.Errorf("actions = %s", a)
	}
	r = scored(&models.TriageReport{SuspiciousTraffic: make([]models.SuspiciousFlow, 1)})
	if !strings.Contains(r.RecommendedActions[0], "a heuristic match alone does not establish compromise or unauthorized access") {
		t.Errorf("suspicious-traffic action = %s", r.RecommendedActions[0])
	}
	assertNoAttackWords(t, r)
}

func TestDNSHeadline_ActionPointsAtResolverAndICMPEvidence(t *testing.T) {
	r := &models.TriageReport{
		DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 1),
		DNSResolverSummary: &models.DNSResolverSummary{Resolvers: []models.DNSResolverStats{
			{Resolver: "172.24.88.11", Queries: 591, Answered: 0},
			{Resolver: "8.8.8.8", Queries: 1937, Answered: 1936},
			{Resolver: "10.0.0.9", Queries: 1, Answered: 0},
		}},
		ICMPErrorEvidence: &models.ICMPErrorEvidence{Errors: []models.ICMPErrorGroup{
			{Family: "ICMP", Type: 3, Code: 1, Reporter: "172.26.88.17", Count: 604, FirstFrame: 13, Quoted: models.ICMPQuotedFlow{Status: "complete", Protocol: "UDP", Dst: "172.24.88.11", DstPort: 53}},
			{Family: "ICMP", Type: 11, Code: 0, Reporter: "10.0.0.1", Count: 5, FirstFrame: 7, Quoted: models.ICMPQuotedFlow{Status: "complete", Protocol: "UDP", Dst: "10.9.9.9", DstPort: 161}}, // not DNS
		}},
	}
	scored(r)
	a := r.RecommendedActions[0]
	for _, must := range []string{"172.24.88.11 (591 queries, 0 replies observed)", "10.0.0.9 (1 query, 0 replies observed)", "may not contain the return direction",
		"ICMP type 3 code 1 from 172.26.88.17 ×604 about queries to 172.24.88.11 (first frame 13)", "icmp_error_evidence"} {
		if !strings.Contains(a, must) {
			t.Errorf("action lacks %q:\n%s", must, a)
		}
	}
	if strings.Contains(a, "8.8.8.8") || strings.Contains(a, "10.9.9.9") {
		t.Errorf("answered resolver or non-DNS ICMP flow listed: %s", a)
	}
	// Without the evidence sections nothing resolver-specific is invented.
	r = scored(&models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindServerFailure, 1)})
	if strings.Contains(r.RecommendedActions[0], "no observed reply") || strings.Contains(r.RecommendedActions[0], "ICMP errors quoting") {
		t.Errorf("invented evidence: %s", r.RecommendedActions[0])
	}
}

func TestDNSHeadline_PlainEnglishSummaryWording(t *testing.T) {
	if dnsSummaryLine(&models.TriageReport{}) != "" {
		t.Error("line without anomalies")
	}
	obs := dnsSummaryLine(&models.TriageReport{DNSAnomalies: dnsAnoms(models.DNSKindNXDomain, 4)})
	for _, must := range []string{"4 observation(s)", "not by themselves a DNS fault", "dns_resolver_summary"} {
		if !strings.Contains(obs, must) {
			t.Errorf("observation line lacks %q: %s", must, obs)
		}
	}
	mixed := dnsSummaryLine(&models.TriageReport{DNSAnomalies: append(dnsAnoms(models.DNSKindServerFailure, 2), dnsAnoms(models.DNSKindNoResponse, 5)...)})
	if !strings.Contains(mixed, "2 server failure(s) and 0 private-address answer(s) observed, plus 5 other DNS observation(s)") {
		t.Errorf("mixed line = %s", mixed)
	}
	for _, l := range []string{obs, mixed} {
		for _, b := range append(headlineBanned, "attack", "confirmed") {
			if strings.Contains(strings.ToLower(l), b) {
				t.Errorf("summary says %q: %s", b, l)
			}
		}
	}
}

// End to end: ordinary DNS results leave the headline clean; a server failure scores.
func TestDNSHeadline_EndToEndOrdinaryResultsVersusServerFailure(t *testing.T) {
	c, s := dkClient, dkGoogle
	var ordinary [][]byte
	for i := 0; i < 5; i++ {
		id := uint16(100 + i)
		ordinary = append(ordinary, dkQuery(t, c, s, id, "gone.example.net"), dkResponse(t, c, s, id, layers.DNSResponseCodeNXDomain, "gone.example.net"))
	}
	r := runGolden(t, ordinary)
	if len(r.DNSAnomalies) != 5 || r.RiskScore != 0 || r.TopIssue != "" || r.NetworkHealth != models.NetworkHealthGood {
		t.Errorf("NXDOMAIN-only: anomalies %d risk %d top %q health %s", len(r.DNSAnomalies), r.RiskScore, r.TopIssue, r.NetworkHealth)
	}
	r = runGolden(t, [][]byte{dkQuery(t, c, s, 7, "fail.example.net"), dkResponse(t, c, s, 7, layers.DNSResponseCodeServFail, "fail.example.net")})
	if r.RiskScore != 10 || r.TopIssue != "DNS Anomalies" || r.NetworkHealth != models.NetworkHealthFair {
		t.Errorf("SERVFAIL: risk %d top %q health %s", r.RiskScore, r.TopIssue, r.NetworkHealth)
	}
}

// Phase 4.42 — the tunneling heuristic's weight (15) applies per distinct source IP.

func tunMatches(sources []string, perSource int) []models.DNSTunnelingFinding {
	var out []models.DNSTunnelingFinding
	for _, s := range sources {
		for i := 0; i < perSource; i++ {
			out = append(out, models.DNSTunnelingFinding{SourceIP: s, ServerIP: "8.8.8.8", Domain: "d" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.net", Severity: "Warning", QueryCount: 20})
		}
	}
	return out
}

func TestTunnelingSourceCount_OneSourceWith28DomainsIsOneContribution(t *testing.T) {
	r := scored(&models.TriageReport{DNSTunnelingFindings: tunMatches([]string{"172.26.88.17"}, 28)})
	if r.RiskScore != 15 || r.TopIssue != "DNS Tunneling" || r.TopIssueCount != 1 {
		t.Errorf("risk %d top %q/%d, want 15 / DNS Tunneling / 1", r.RiskScore, r.TopIssue, r.TopIssueCount)
	}
	if len(r.DNSTunnelingFindings) != 28 {
		t.Errorf("findings = %d, want all 28 preserved", len(r.DNSTunnelingFindings))
	}
}

func TestTunnelingSourceCount_TwoSourcesAndFourSources(t *testing.T) {
	two := append(tunMatches([]string{"172.26.88.17"}, 27), tunMatches([]string{"10.160.4.40"}, 1)...)
	r := scored(&models.TriageReport{DNSTunnelingFindings: two})
	if len(two) != 28 || r.RiskScore != 30 || r.TopIssueCount != 2 || len(r.DNSTunnelingFindings) != 28 {
		t.Errorf("two sources: %d findings, risk %d, top count %d", len(r.DNSTunnelingFindings), r.RiskScore, r.TopIssueCount)
	}
	r = scored(&models.TriageReport{DNSTunnelingFindings: tunMatches([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}, 3)})
	if r.RiskScore != 60 || r.RiskLevel != "Critical" || r.TopIssueCount != 4 {
		t.Errorf("four sources: risk %d/%s top count %d", r.RiskScore, r.RiskLevel, r.TopIssueCount)
	}
}

func TestTunnelingSourceCount_EmptySourcesAndEmptyListContributeNothing(t *testing.T) {
	r := scored(&models.TriageReport{DNSTunnelingFindings: tunMatches([]string{"", ""}, 5)})
	if r.RiskScore != 0 || r.TopIssue != "" || len(r.DNSTunnelingFindings) != 10 {
		t.Errorf("empty sources: risk %d top %q findings %d", r.RiskScore, r.TopIssue, len(r.DNSTunnelingFindings))
	}
	// An empty source next to a real one is not an extra source.
	r = scored(&models.TriageReport{DNSTunnelingFindings: append(tunMatches([]string{"10.0.0.1"}, 2), tunMatches([]string{""}, 2)...)})
	if r.RiskScore != 15 || r.TopIssueCount != 1 {
		t.Errorf("mixed: risk %d top count %d", r.RiskScore, r.TopIssueCount)
	}
	r = scored(&models.TriageReport{})
	if r.RiskScore != 0 || r.TopIssue != "" {
		t.Errorf("empty list: risk %d top %q", r.RiskScore, r.TopIssue)
	}
	if dnsTunnelingSourceCount(&models.TriageReport{DNSTunnelingFindings: []models.DNSTunnelingFinding{{ServerIP: "8.8.8.8", Domain: "x.net"}}}) != 0 {
		t.Error("a source was inferred from a server address or domain")
	}
}

// Weight, recommendation wording and the other scoring branches / top-issue ordering are unchanged.
func TestTunnelingSourceCount_OtherBehaviourUnchanged(t *testing.T) {
	r := scored(&models.TriageReport{
		DNSTunnelingFindings: tunMatches([]string{"10.0.0.1"}, 28),
		HTTPErrors:           make([]models.HTTPError, 8),
		SuspiciousTraffic:    make([]models.SuspiciousFlow, 2),
	})
	// 15 (tunneling) + 16 (HTTP errors ×2) + 10 (suspicious ×5) = 41; top issue = most instances (HTTP errors 8).
	if r.RiskScore != 41 || r.TopIssue != "HTTP Errors" || r.TopIssueCount != 8 {
		t.Errorf("risk %d top %q/%d", r.RiskScore, r.TopIssue, r.TopIssueCount)
	}
	if !strings.Contains(strings.Join(r.RecommendedActions, "\n"), dnsTunnelingActionText) {
		t.Errorf("tunneling recommendation changed: %v", r.RecommendedActions)
	}
	// Source deduplication cannot change the order of ties: same counts resolve as before.
	r = scored(&models.TriageReport{DNSTunnelingFindings: tunMatches([]string{"a", "b", "c"}, 4), TCPRetransmissions: make([]models.TCPFlow, 3)})
	if r.TopIssueCount != 3 || (r.TopIssue != "DNS Tunneling" && r.TopIssue != "TCP Retransmissions") {
		t.Errorf("tie: %q/%d", r.TopIssue, r.TopIssueCount)
	}
}
