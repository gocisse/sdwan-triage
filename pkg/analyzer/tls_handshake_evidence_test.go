package analyzer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.34 — TLS handshake and alert evidence: alert records (readable or encrypted),
// ClientHello/ServerHello frames per connection, and ClientHello without ServerHello,
// all observational. Packets are 100 ms apart.

const tlsPort = 52000

func tlsRecord(ct byte, version [2]byte, body []byte) []byte {
	return append([]byte{ct, version[0], version[1], byte(len(body) >> 8), byte(len(body))}, body...)
}

func hsMsg(typ byte, body []byte) []byte {
	return append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func clientHelloRecord(sni string) []byte {
	b := []byte{3, 3}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)                // session id
	b = append(b, 0, 2, 0x13, 0x01) // one cipher suite
	b = append(b, 1, 0)             // compression
	name := []byte(sni)
	ext := []byte{0, 0, byte((len(name) + 5) >> 8), byte(len(name) + 5), byte((len(name) + 3) >> 8), byte(len(name) + 3), 0, byte(len(name) >> 8), byte(len(name))}
	ext = append(ext, name...)
	b = append(b, byte(len(ext)>>8), byte(len(ext)))
	b = append(b, ext...)
	return tlsRecord(22, [2]byte{3, 1}, hsMsg(1, b))
}

func serverHelloRecord() []byte {
	b := []byte{3, 3}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0, 0x13, 0x01, 0)
	return tlsRecord(22, [2]byte{3, 3}, hsMsg(2, b))
}

func alertRecord(level, desc byte) []byte { return tlsRecord(21, [2]byte{3, 3}, []byte{level, desc}) }

func encAlertRecord() []byte {
	return tlsRecord(21, [2]byte{3, 3}, append(make([]byte, 24), 0xaa, 0xbb))
}

// tlsSeqNext keeps each direction's sequence numbers contiguous across calls so that
// the synthetic segments are never mistaken for TCP retransmissions or gaps.
var tlsSeqNext = map[[2]uint32]uint32{}

func tlsSeg(fromServer bool, port uint16, payload []byte) []byte {
	dir := uint32(0)
	if fromServer {
		dir = 1
	}
	k := [2]uint32{dir, uint32(port)}
	seq, ok := tlsSeqNext[k]
	if !ok {
		seq = 1001
	}
	tlsSeqNext[k] = seq + uint32(len(payload))
	if fromServer {
		return testpcap.TCPFrame(testpcap.ServerMAC, testpcap.ClientMAC, testpcap.ServerIP, testpcap.ClientIP, 443, port, seq, 1001, testpcap.PSH|testpcap.ACK, payload)
	}
	return testpcap.TCPFrame(testpcap.ClientMAC, testpcap.ServerMAC, testpcap.ClientIP, testpcap.ServerIP, port, 443, seq, 5001, testpcap.PSH|testpcap.ACK, payload)
}

func tlsEv(t *testing.T, r *models.TriageReport) *models.TLSHandshakeEvidence {
	t.Helper()
	if r.TLSHandshakeEvidence == nil {
		t.Fatal("no tls_handshake_evidence")
	}
	return r.TLSHandshakeEvidence
}

var tlsBanned = []string{"caused by", "because the server", "server rejected", "server refused", "certificate problem", "provider", "isp ", "blocked", "outage", "attack", "faulty"}

func tlsNoClaims(t *testing.T, text string) {
	t.Helper()
	l := strings.ToLower(text)
	for _, b := range tlsBanned {
		if strings.Contains(l, b) {
			t.Errorf("text makes an unsupported claim (%q): %s", b, text)
		}
	}
}

func TestTLSEvidence_AbsentForAHealthyHandshakeWithoutAlerts(t *testing.T) {
	r := runGolden(t, [][]byte{tlsSeg(false, tlsPort, clientHelloRecord("ok.example.net")), tlsSeg(true, tlsPort, serverHelloRecord())})
	if r.TLSHandshakeEvidence != nil {
		t.Errorf("evidence without alert or missing ServerHello: %+v", r.TLSHandshakeEvidence)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "tls_handshake_evidence") {
		t.Error("key serialized without evidence")
	}
}

func TestTLSEvidence_ReadableFatalAlertFromTheServer(t *testing.T) {
	r := runGolden(t, [][]byte{
		tlsSeg(false, tlsPort, clientHelloRecord("alert.example.net")), // frame 1
		tlsSeg(true, tlsPort, serverHelloRecord()),                     // frame 2
		tlsSeg(true, tlsPort, alertRecord(2, 40)),                      // frame 3: fatal handshake_failure
	})
	e := tlsEv(t, r)
	if e.ConnectionsWithAlerts != 1 || e.AlertsTotal != 1 || e.AlertsPlaintext != 1 || e.AlertsEncrypted != 0 || e.ClientHelloNoServerHello != 0 {
		t.Fatalf("totals = %+v", e)
	}
	c := e.Connections[0]
	if c.SNI != "alert.example.net" || c.ClientHelloFrame != 1 || c.ServerHelloFrame != 2 || c.Handshake != "server_hello_observed" || c.Client == "" || c.Server == "" {
		t.Errorf("connection = %+v", c)
	}
	a := c.Alerts[0]
	if a.Frame != 3 || a.FromRole != "server" || a.Visibility != "plaintext" || a.Level != "fatal" || a.Description != "handshake_failure" || a.DescriptionCode == nil || *a.DescriptionCode != 40 {
		t.Errorf("alert = %+v", a)
	}
	if !strings.HasSuffix(a.From, ":443") || !strings.HasSuffix(a.To, ":52000") {
		t.Errorf("direction = %s -> %s", a.From, a.To)
	}
	tlsNoClaims(t, c.Description)
	tlsNoClaims(t, a.Note)
	tlsNoClaims(t, models.TLSHandshakeEvidenceBasis)
}

func TestTLSEvidence_EncryptedAlertShowsNoLevelOrDescription(t *testing.T) {
	r := runGolden(t, [][]byte{
		tlsSeg(false, tlsPort, clientHelloRecord("enc.example.net")), tlsSeg(true, tlsPort, serverHelloRecord()),
		tlsSeg(false, tlsPort, encAlertRecord()),
	})
	e := tlsEv(t, r)
	a := e.Connections[0].Alerts[0]
	if e.AlertsEncrypted != 1 || e.AlertsPlaintext != 0 || a.Visibility != "encrypted" || a.Level != "" || a.Description != "" || a.DescriptionCode != nil || a.FromRole != "client" {
		t.Errorf("alert = %+v totals = %+v", a, e)
	}
	if !strings.Contains(a.Note, "may be a normal close_notify") {
		t.Errorf("note = %s", a.Note)
	}
}

func TestTLSEvidence_ClientHelloWithoutServerHello(t *testing.T) {
	// 1 s apart: the first connection's ClientHello is far from the end; the last one is at the end.
	r := runGoldenInterval(t, [][]byte{
		tlsSeg(false, tlsPort, clientHelloRecord("a.example.net")),
		tlsSeg(false, tlsPort+1, clientHelloRecord("b.example.net")), tlsSeg(true, tlsPort+1, serverHelloRecord()),
		tlsSeg(false, tlsPort+2, clientHelloRecord("c.example.net")),
	}, 1000000000)
	e := tlsEv(t, r)
	if e.ClientHelloNoServerHello != 2 || e.ConnectionsWithAlerts != 0 || e.ConnectionsWithEvidence != 2 {
		t.Fatalf("totals = %+v", e)
	}
	byName := map[string]models.TLSConnectionEvidence{}
	for _, c := range e.Connections {
		byName[c.SNI] = c
	}
	a, c := byName["a.example.net"], byName["c.example.net"]
	if a.Handshake != "no_server_hello_observed" || a.ServerHelloFrame != 0 || a.NearCaptureEnd || a.ClientHelloFrame != 1 {
		t.Errorf("a = %+v", a)
	}
	if !c.NearCaptureEnd || !strings.Contains(c.Description, "cut the exchange off") {
		t.Errorf("c = %+v", c)
	}
	for _, x := range []models.TLSConnectionEvidence{a, c} {
		if !strings.Contains(x.Description, "no ServerHello was observed for this connection in this capture") || !strings.Contains(x.Description, "the capture cannot tell which") {
			t.Errorf("description = %s", x.Description)
		}
		tlsNoClaims(t, x.Description)
	}
	if _, ok := byName["b.example.net"]; ok {
		t.Error("answered connection listed")
	}
}

func TestTLSEvidence_AlertWithoutAnObservedClientHelloHasUnknownRole(t *testing.T) {
	r := runGolden(t, [][]byte{tlsSeg(true, tlsPort, alertRecord(1, 0))})
	c := tlsEv(t, r).Connections[0]
	if c.Handshake != "client_hello_not_observed" || c.Client != "" || c.Alerts[0].FromRole != "unknown" || c.Alerts[0].Level != "warning" || c.Alerts[0].Description != "close_notify" {
		t.Errorf("connection = %+v", c)
	}
}

// Anything that is not a self-consistent TLS record, or an alert record that is cut off,
// must not become evidence.
func TestTLSEvidence_NonTLSAndIncompleteRecordsAreIgnored(t *testing.T) {
	enc := tlsRecord(22, [2]byte{3, 3}, append([]byte{0x01, 0x00, 0x00, 0x05, 0x03, 0x09}, make([]byte, 60)...)) // encrypted-looking handshake record that starts with 0x01
	cases := map[string][]byte{
		"HTTP":                          []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"alert-like, wrong version":     {21, 9, 9, 0, 2, 2, 40},
		"alert cut off":                 alertRecord(2, 40)[:6],
		"length 5 (neither 2 nor >=18)": tlsRecord(21, [2]byte{3, 3}, []byte{1, 2, 3, 4, 5}),
		"handshake record, hs length inconsistent": enc,
		"zero-length record":                       {21, 3, 3, 0, 0, 0, 0},
		"alert level 7":                            alertRecord(7, 40),
	}
	var pk [][]byte
	for _, p := range cases {
		pk = append(pk, tlsSeg(true, tlsPort, p))
	}
	r := runGolden(t, pk)
	if r.TLSHandshakeEvidence != nil {
		t.Errorf("evidence from invalid input: %+v", r.TLSHandshakeEvidence)
	}
}

func TestTLSEvidence_CoalescedRecordsAndAlertAfterHandshakeInOneSegment(t *testing.T) {
	seg := append(append(serverHelloRecord(), tlsRecord(20, [2]byte{3, 3}, []byte{1})...), alertRecord(2, 42)...)
	r := runGolden(t, [][]byte{tlsSeg(false, tlsPort, clientHelloRecord("co.example.net")), tlsSeg(true, tlsPort, seg)})
	c := tlsEv(t, r).Connections[0]
	if c.ServerHelloFrame != 2 || len(c.Alerts) != 1 || c.Alerts[0].Description != "bad_certificate" || c.Alerts[0].Frame != 2 {
		t.Errorf("connection = %+v", c)
	}
}

func TestTLSEvidence_AlertListIsBoundedButCounted(t *testing.T) {
	var pk [][]byte
	pk = append(pk, tlsSeg(false, tlsPort, clientHelloRecord("many.example.net")), tlsSeg(true, tlsPort, serverHelloRecord()))
	for i := 0; i < 14; i++ {
		pk = append(pk, tlsSeg(true, tlsPort, alertRecord(1, 0)))
	}
	e := tlsEv(t, runGolden(t, pk))
	c := e.Connections[0]
	if c.AlertsTotal != 14 || len(c.Alerts) != 10 || c.AlertsOmitted != 4 || e.AlertsTotal != 14 {
		t.Errorf("alerts = total %d listed %d omitted %d (evidence total %d)", c.AlertsTotal, len(c.Alerts), c.AlertsOmitted, e.AlertsTotal)
	}
}

func TestTLSEvidence_ConnectionListIsBoundedAndOrdered(t *testing.T) {
	var pk [][]byte
	for i := 0; i < 55; i++ { // 55 ClientHellos without ServerHello
		pk = append(pk, tlsSeg(false, uint16(tlsPort+i), clientHelloRecord("n.example.net")))
	}
	pk = append(pk, tlsSeg(true, tlsPort+100, alertRecord(2, 40))) // an alert connection, latest in time
	e := tlsEv(t, runGolden(t, pk))
	if e.ConnectionsWithEvidence != 56 || e.ConnectionsShown != 50 || e.OmittedConnections != 6 || e.ClientHelloNoServerHello != 55 {
		t.Fatalf("totals = %+v", e)
	}
	if e.Connections[0].AlertsTotal != 1 { // alert connections are listed first even though they came last
		t.Errorf("first connection = %+v", e.Connections[0])
	}
}

func TestTLSEvidence_DeterministicAndLeavesOtherOutputUnchanged(t *testing.T) {
	mk := func(extra bool) *models.TriageReport {
		pk := [][]byte{tlsSeg(false, tlsPort, clientHelloRecord("d.example.net")), tlsSeg(true, tlsPort, serverHelloRecord())}
		if extra {
			pk = append(pk, tlsSeg(true, tlsPort, alertRecord(2, 40)), tlsSeg(false, tlsPort, encAlertRecord()))
		}
		return runGolden(t, pk)
	}
	first, _ := json.Marshal(mk(true).TLSHandshakeEvidence)
	for i := 0; i < 3; i++ {
		if b, _ := json.Marshal(mk(true).TLSHandshakeEvidence); string(b) != string(first) {
			t.Fatal("not deterministic")
		}
	}
	r0, r1 := mk(false), mk(true)
	if len(r0.TLSCerts) != len(r1.TLSCerts) || len(r0.TLSFlows) != len(r1.TLSFlows) || r0.RiskScore != r1.RiskScore {
		t.Errorf("existing TLS/risk output changed: %d/%d certs, %d/%d flows", len(r0.TLSCerts), len(r1.TLSCerts), len(r0.TLSFlows), len(r1.TLSFlows))
	}
}
