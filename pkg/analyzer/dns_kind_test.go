package analyzer

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/events"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── helpers ─────────────────────────────────────────────────────

// dkPayload serialises a DNS message with one question and the given answers.
func dkPayload(t *testing.T, id uint16, response bool, rcode layers.DNSResponseCode, name string, answers ...net.IP) []byte {
	t.Helper()
	d := &layers.DNS{
		ID: id, QR: response, RD: true, ResponseCode: rcode, QDCount: 1,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
	for _, ip := range answers {
		typ := layers.DNSTypeA
		if ip.To4() == nil {
			typ = layers.DNSTypeAAAA
		}
		d.Answers = append(d.Answers, layers.DNSResourceRecord{Name: []byte(name), Type: typ, Class: layers.DNSClassIN, TTL: 60, IP: ip})
	}
	d.ANCount = uint16(len(d.Answers))
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, d); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dkQuery(t *testing.T, client, server []byte, id uint16, name string) []byte {
	return testpcap.UDPFrame(testpcap.ClientMAC, testpcap.ServerMAC, client, server, 40000+id%1000, 53, dkPayload(t, id, false, 0, name))
}

func dkResponse(t *testing.T, client, server []byte, id uint16, rcode layers.DNSResponseCode, name string, answers ...net.IP) []byte {
	return testpcap.UDPFrame(testpcap.ServerMAC, testpcap.ClientMAC, server, client, 53, 40000+id%1000, dkPayload(t, id, true, rcode, name, answers...))
}

// dkResponseV6 is a response whose server address is IPv6 (client stays IPv4-mapped
// for simplicity: both ends are IPv6).
func dkResponseV6(t *testing.T, id uint16, name string, server, client net.IP, answers ...net.IP) []byte {
	payload := dkPayload(t, id, true, 0, name, answers...)
	udp := testpcap.BuildUDP(53, 40000+id%1000, payload)
	ip6 := make([]byte, 40+len(udp))
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(udp)))
	ip6[6], ip6[7] = 17, 64
	copy(ip6[8:24], server.To16())
	copy(ip6[24:40], client.To16())
	copy(ip6[40:], udp)
	return testpcap.BuildEthernet(testpcap.ServerMAC, testpcap.ClientMAC, 0x86DD, ip6)
}

func dkQueryV6(t *testing.T, id uint16, name string, client, server net.IP) []byte {
	payload := dkPayload(t, id, false, 0, name)
	udp := testpcap.BuildUDP(40000+id%1000, 53, payload)
	ip6 := make([]byte, 40+len(udp))
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(udp)))
	ip6[6], ip6[7] = 17, 64
	copy(ip6[8:24], client.To16())
	copy(ip6[24:40], server.To16())
	copy(ip6[40:], udp)
	return testpcap.BuildEthernet(testpcap.ClientMAC, testpcap.ServerMAC, 0x86DD, ip6)
}

func kindsByQuery(r *models.TriageReport) map[string][]string {
	out := map[string][]string{}
	for _, a := range r.DNSAnomalies {
		out[a.Query] = append(out[a.Query], a.Kind)
	}
	return out
}

func countKind(r *models.TriageReport, kind string) int {
	n := 0
	for _, a := range r.DNSAnomalies {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

var (
	dkClient   = testpcap.ClientIP // 192.168.1.100
	dkClientB  = []byte{192, 168, 1, 101}
	dkGoogle   = testpcap.DNSServer     // 8.8.8.8 (allow-listed)
	dkLevel3   = []byte{4, 2, 2, 1}     // public resolver NOT in the allow-list
	dkInternal = []byte{10, 160, 4, 39} // private resolver
	dkWeb      = net.IPv4(93, 184, 216, 34)
	dkQuad9v6  = net.ParseIP("2620:fe::fe")
	dkClientV6 = net.ParseIP("2001:db8::10")
	dkGoogleV6 = net.ParseIP("2001:4860:4860::8888")
)

// ─── structured kind ─────────────────────────────────────────────

func TestDNSKind_EachKindAssignedAtSource(t *testing.T) {
	c, s := dkClient, dkGoogle
	pk := [][]byte{
		// server_failure (SERVFAIL), nxdomain, refused
		dkQuery(t, c, s, 1, "fail.example.net"), dkResponse(t, c, s, 1, layers.DNSResponseCodeServFail, "fail.example.net"),
		dkQuery(t, c, s, 2, "gone.example.net"), dkResponse(t, c, s, 2, layers.DNSResponseCodeNXDomain, "gone.example.net"),
		dkQuery(t, c, s, 3, "refused.example.net"), dkResponse(t, c, s, 3, layers.DNSResponseCodeRefused, "refused.example.net"),
		// non_standard_server: allow-list miss on a public responder
		dkQuery(t, c, dkLevel3, 4, "odd.example.net"), dkResponse(t, c, dkLevel3, 4, 0, "odd.example.net", dkWeb),
		// private_answer: private address for a public-TLD name from an allow-listed server
		dkQuery(t, c, s, 5, "intranet.example.com"), dkResponse(t, c, s, 5, 0, "intranet.example.com", net.IPv4(10, 1, 2, 3)),
		// suspicious_domain: >5 labels
		dkQuery(t, c, s, 6, "x.a.b.c.d.example.org"), dkResponse(t, c, s, 6, 0, "x.a.b.c.d.example.org", dkWeb),
		// no_response: same (client,name) twice, never answered
		dkQuery(t, c, s, 7, "silent.example.net"), dkQuery(t, c, s, 7, "silent.example.net"),
	}
	r := runGolden(t, pk)
	want := map[string]string{
		"fail.example.net":      models.DNSKindServerFailure,
		"gone.example.net":      models.DNSKindNXDomain,
		"refused.example.net":   models.DNSKindServerFailure,
		"odd.example.net":       models.DNSKindNonStandardServer,
		"intranet.example.com":  models.DNSKindPrivateAnswer,
		"x.a.b.c.d.example.org": models.DNSKindSuspiciousDomain,
		"silent.example.net":    models.DNSKindNoResponse,
	}
	got := kindsByQuery(r)
	for name, kind := range want {
		if len(got[name]) != 1 || got[name][0] != kind {
			t.Errorf("%s: kinds = %v, want exactly [%s]", name, got[name], kind)
		}
	}
	if len(r.DNSAnomalies) != len(want) {
		t.Errorf("anomalies = %d, want %d: %+v", len(r.DNSAnomalies), len(want), r.DNSAnomalies)
	}
	for _, a := range r.DNSAnomalies {
		if a.Reason == "" {
			t.Errorf("reason text must still be present: %+v", a)
		}
	}
}

func TestDNSKind_SerializedInJSONAndEvents(t *testing.T) {
	c, s := dkClient, dkGoogle
	r := runGolden(t, [][]byte{dkQuery(t, c, s, 1, "fail.example.net"), dkResponse(t, c, s, 1, layers.DNSResponseCodeServFail, "fail.example.net")})
	b, err := json.Marshal(r.DNSAnomalies)
	if err != nil || !strings.Contains(string(b), `"kind":"server_failure"`) {
		t.Fatalf("kind missing from JSON: %s (%v)", b, err)
	}
	evs := r.Events.ByKind(events.DNSAnomaly)
	if len(evs) != 1 || evs[0].Attrs["kind"] != models.DNSKindServerFailure || evs[0].Attrs["reason"] == "" {
		t.Fatalf("event attrs = %+v", evs)
	}
}

// ─── counting: one response/kind is one observation ──────────────

func TestDNSCount_MultiAnswerResponseIsOneAnomalyPerKind(t *testing.T) {
	six := []net.IP{net.IPv4(1, 1, 1, 1), net.IPv4(1, 1, 1, 2), net.IPv4(1, 1, 1, 3), net.IPv4(1, 1, 1, 4), net.IPv4(1, 1, 1, 5), net.IPv4(1, 1, 1, 6)}
	// Six answers from a non-allow-listed public resolver: ONE non_standard_server anomaly (was six).
	r := runGolden(t, [][]byte{
		dkQuery(t, dkClient, dkLevel3, 1, "multi.example.net"),
		dkResponse(t, dkClient, dkLevel3, 1, 0, "multi.example.net", six...),
	})
	if len(r.DNSAnomalies) != 1 || r.DNSAnomalies[0].Kind != models.DNSKindNonStandardServer {
		t.Fatalf("want exactly 1 non_standard_server, got %+v", r.DNSAnomalies)
	}
	if r.DNSAnomalies[0].AnswerIP != "1.1.1.1" {
		t.Errorf("AnswerIP should be the first offending answer, got %q", r.DNSAnomalies[0].AnswerIP)
	}

	// Three private answers for a public-TLD name: ONE private_answer.
	r = runGolden(t, [][]byte{
		dkQuery(t, dkClient, dkGoogle, 2, "intranet.example.com"),
		dkResponse(t, dkClient, dkGoogle, 2, 0, "intranet.example.com", net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 3)),
	})
	if len(r.DNSAnomalies) != 1 || r.DNSAnomalies[0].Kind != models.DNSKindPrivateAnswer {
		t.Fatalf("want exactly 1 private_answer, got %+v", r.DNSAnomalies)
	}

	// Several answers, non-standard server AND suspicious name: one anomaly of EACH kind, not six.
	r = runGolden(t, [][]byte{
		dkQuery(t, dkClient, dkLevel3, 3, "x.a.b.c.d.example.org"),
		dkResponse(t, dkClient, dkLevel3, 3, 0, "x.a.b.c.d.example.org", six...),
	})
	if len(r.DNSAnomalies) != 2 || countKind(r, models.DNSKindNonStandardServer) != 1 || countKind(r, models.DNSKindSuspiciousDomain) != 1 {
		t.Fatalf("want one anomaly per distinct kind, got %+v", r.DNSAnomalies)
	}
	// Separate responses remain separate observations.
	r = runGolden(t, [][]byte{
		dkQuery(t, dkClient, dkLevel3, 4, "a.example.net"), dkResponse(t, dkClient, dkLevel3, 4, 0, "a.example.net", six...),
		dkQuery(t, dkClient, dkLevel3, 5, "b.example.net"), dkResponse(t, dkClient, dkLevel3, 5, 0, "b.example.net", six...),
	})
	if len(r.DNSAnomalies) != 2 {
		t.Fatalf("two responses = two observations, got %d", len(r.DNSAnomalies))
	}
}

// ─── existing heuristics are intact (Phase 4.20 changes meaning, not detection) ──

func TestDNSHeuristics_UnchangedBehaviour(t *testing.T) {
	c := dkClient
	pk := [][]byte{
		// Allow-listed resolver, normal answer: nothing.
		dkQuery(t, c, dkGoogle, 1, "www.example.net"), dkResponse(t, c, dkGoogle, 1, 0, "www.example.net", dkWeb),
		// Private/enterprise resolver: never "non-standard".
		dkQuery(t, c, dkInternal, 2, "corp.example.net"), dkResponse(t, c, dkInternal, 2, 0, "corp.example.net", dkWeb),
		// 4.2.2.1 (public, not in the list): still flagged by the existing rule.
		dkQuery(t, c, dkLevel3, 3, "level3.example.net"), dkResponse(t, c, dkLevel3, 3, 0, "level3.example.net", dkWeb),
		// Microsoft update CDN name (6 labels): still matches the label-count heuristic.
		dkQuery(t, c, dkGoogle, 4, "2.tlu.dl.delivery.mp.microsoft.com"), dkResponse(t, c, dkGoogle, 4, 0, "2.tlu.dl.delivery.mp.microsoft.com", dkWeb),
		// NCSI answered with a ULA by an internal resolver: still the existing private-answer rule.
		dkQuery(t, c, dkInternal, 5, "dns.msftncsi.com"), dkResponse(t, c, dkInternal, 5, 0, "dns.msftncsi.com", net.ParseIP("fd3e:4f5a:5b81::1")),
		// Ordinary NXDOMAIN.
		dkQuery(t, c, dkGoogle, 6, "wpad.example.net"), dkResponse(t, c, dkGoogle, 6, layers.DNSResponseCodeNXDomain, "wpad.example.net"),
	}
	r := runGolden(t, pk)
	got := kindsByQuery(r)
	expect := map[string]string{
		"level3.example.net":                 models.DNSKindNonStandardServer,
		"2.tlu.dl.delivery.mp.microsoft.com": models.DNSKindSuspiciousDomain,
		"dns.msftncsi.com":                   models.DNSKindPrivateAnswer,
		"wpad.example.net":                   models.DNSKindNXDomain,
	}
	for name, kind := range expect {
		if len(got[name]) != 1 || got[name][0] != kind {
			t.Errorf("%s: %v, want [%s]", name, got[name], kind)
		}
	}
	for _, quiet := range []string{"www.example.net", "corp.example.net"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s must stay unflagged, got %v", quiet, got[quiet])
		}
	}
}

func TestDNSHeuristics_IPv6ProviderStillFlaggedByExistingRule(t *testing.T) {
	// Documents CURRENT behaviour (allow-list is IPv4-only); redesign is out of scope for 4.20.
	for name, server := range map[string]net.IP{"Quad9 IPv6": dkQuad9v6, "Google IPv6": dkGoogleV6} {
		r := runGolden(t, [][]byte{
			dkQueryV6(t, 1, "v6.example.net", dkClientV6, server),
			dkResponseV6(t, 1, "v6.example.net", server, dkClientV6, dkWeb),
		})
		if len(r.DNSAnomalies) != 1 || r.DNSAnomalies[0].Kind != models.DNSKindNonStandardServer {
			t.Errorf("%s: %+v", name, r.DNSAnomalies)
		}
	}
}

// ─── capture-boundary behaviour (observations, no certainty claimed) ──

func TestDNSBoundary_SingleRecentQueryNotAnAnomaly(t *testing.T) {
	r := runGolden(t, [][]byte{dkQuery(t, dkClient, dkGoogle, 1, "late.example.net")})
	if len(r.DNSAnomalies) != 0 {
		t.Fatalf("a lone query at the end of the capture may simply be cut off: %+v", r.DNSAnomalies)
	}
}

func TestDNSBoundary_RetriesAreNoResponse(t *testing.T) {
	q := dkQuery(t, dkClient, dkGoogle, 1, "retry.example.net")
	r := runGolden(t, [][]byte{q, q})
	if len(r.DNSAnomalies) != 1 || r.DNSAnomalies[0].Kind != models.DNSKindNoResponse {
		t.Fatalf("got %+v", r.DNSAnomalies)
	}
}

// Lab 6 shape: three queries with one transaction ID, then a SERVFAIL with a
// different ID for the same name. Both remain visible as separate kinds; the
// detector does not claim the SERVFAIL answers the queries.
func TestDNSBoundary_ResponseIDMismatch(t *testing.T) {
	q := dkQuery(t, dkClient, dkGoogle, 0x6566, "sn3.example.net")
	r := runGolden(t, [][]byte{q, q, q, dkResponse(t, dkClient, dkGoogle, 0x3742, layers.DNSResponseCodeServFail, "sn3.example.net")})
	if countKind(r, models.DNSKindServerFailure) != 1 || countKind(r, models.DNSKindNoResponse) != 1 || len(r.DNSAnomalies) != 2 {
		t.Fatalf("got %+v", r.DNSAnomalies)
	}
}

func TestDNSBoundary_OneSidedCapture(t *testing.T) {
	// Responses only (queries on another path): success is silent, a failure is still evidence.
	r := runGolden(t, [][]byte{
		dkResponse(t, dkClient, dkGoogle, 1, 0, "ok.example.net", dkWeb),
		dkResponse(t, dkClient, dkGoogle, 2, layers.DNSResponseCodeServFail, "bad.example.net"),
	})
	if len(r.DNSAnomalies) != 1 || r.DNSAnomalies[0].Kind != models.DNSKindServerFailure {
		t.Fatalf("got %+v", r.DNSAnomalies)
	}
}

func TestDNSBoundary_SameIDDifferentClients(t *testing.T) {
	// Two clients reuse transaction ID 0x1234 for different names. The detector keeps a
	// global ID->name map (last query wins) that overrides the response's own question, so
	// only the client that queried last is matched reliably. KNOWN LIMITATION (out of scope
	// for Phase 4.20, recorded in the audit): the other client's record can stay unmatched.
	// What must hold regardless: nothing is credited to the wrong client and no anomaly is
	// invented for answered traffic.
	r := runGolden(t, [][]byte{
		dkQuery(t, dkClient, dkGoogle, 0x1234, "one.example.net"),
		dkQuery(t, dkClientB, dkGoogle, 0x1234, "two.example.net"),
		dkResponse(t, dkClientB, dkGoogle, 0x1234, 0, "two.example.net", dkWeb),
		dkResponse(t, dkClient, dkGoogle, 0x1234, 0, "one.example.net", dkWeb),
	})
	if len(r.DNSAnomalies) != 0 {
		t.Fatalf("no anomaly expected for answered traffic: %+v", r.DNSAnomalies)
	}
	for _, rec := range r.DNSDetails {
		if rec.SourceIP == "192.168.1.101" && rec.ResponseTimestamp == nil {
			t.Errorf("client B (last querier) must be matched: %+v", rec)
		}
		if rec.SourceIP == "192.168.1.100" && rec.ResponseTimestamp != nil && rec.QueryName != "one.example.net" {
			t.Errorf("response credited to the wrong record: %+v", rec)
		}
	}
}

// Partial pcapng: DNS kinds and the completeness record coexist; neither alters the other.
func TestDNSKind_PartialCaptureKeepsKinds(t *testing.T) {
	c, s := dkClient, dkGoogle
	frames := [][]byte{dkQuery(t, c, s, 1, "fail.example.net"), dkResponse(t, c, s, 1, layers.DNSResponseCodeServFail, "fail.example.net")}
	pkts := append(testpcap.EthernetNG(frames), unsupportedPkts(3)...)
	path := writeNG(t, []uint16{testpcap.LinkTypeEthernet, testpcap.LinkTypeEthernetMPkt}, pkts)
	r, _, err := processFile(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Completeness == nil || r.Completeness.PacketsUnsupported != 3 {
		t.Fatalf("completeness = %+v", r.Completeness)
	}
	if len(r.DNSAnomalies) != 1 || r.DNSAnomalies[0].Kind != models.DNSKindServerFailure {
		t.Fatalf("anomalies = %+v", r.DNSAnomalies)
	}
}
