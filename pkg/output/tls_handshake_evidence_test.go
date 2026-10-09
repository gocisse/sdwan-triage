package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func tlsText(r *models.TriageReport) string {
	var b bytes.Buffer
	WriteTLSHandshakeEvidence(&b, r)
	return b.String()
}

func TestTLSCLI_NothingWithoutEvidence(t *testing.T) {
	if tlsText(&models.TriageReport{}) != "" || tlsText(&models.TriageReport{TLSHandshakeEvidence: &models.TLSHandshakeEvidence{}}) != "" {
		t.Error("output without evidence")
	}
}

func TestTLSCLI_ShowsAlertsHandshakeFramesAndLimits(t *testing.T) {
	code := uint8(40)
	e := &models.TLSHandshakeEvidence{ConnectionsWithAlerts: 2, AlertsTotal: 6, AlertsPlaintext: 1, AlertsEncrypted: 5, ClientHelloNoServerHello: 1,
		ConnectionsWithEvidence: 3, ConnectionsShown: 3, MaxConnections: 50, ConnectionsUntracked: 4,
		Connections: []models.TLSConnectionEvidence{
			{Endpoints: "a:1 <-> b:443", SNI: "x.example.net", Handshake: "server_hello_observed", ClientHelloFrame: 3, ServerHelloFrame: 5, AlertsTotal: 5,
				Alerts: []models.TLSAlertRecord{
					{Frame: 9, From: "b:443", FromRole: "server", Visibility: "plaintext", Level: "fatal", Description: "handshake_failure", DescriptionCode: &code},
					{Frame: 10, From: "a:1", FromRole: "client", Visibility: "encrypted"}, {Frame: 11, From: "a:1", FromRole: "client", Visibility: "encrypted"},
					{Frame: 12, From: "a:1", FromRole: "client", Visibility: "encrypted"}, {Frame: 13, From: "a:1", FromRole: "client", Visibility: "encrypted"}}},
			{Endpoints: "c:2 <-> d:443", Handshake: "no_server_hello_observed", ClientHelloFrame: 20, NearCaptureEnd: true},
			{Endpoints: "e:3 <-> f:443", Handshake: "client_hello_not_observed", AlertsTotal: 1, Alerts: []models.TLSAlertRecord{{Frame: 30, From: "f:443", FromRole: "unknown", Visibility: "encrypted"}}},
		}}
	out := tlsText(&models.TriageReport{TLSHandshakeEvidence: e})
	for _, must := range []string{
		"TLS ALERTS AND HANDSHAKES (observations from this capture; an alert or a missing ServerHello does not by itself show why a connection failed or where the cause lies):",
		"2 connection(s) with a TLS alert (6 alert record(s): 1 readable, 5 encrypted); 1 connection(s) with a ClientHello and no observed ServerHello.",
		"Connection a:1 <-> b:443 (SNI x.example.net)", "ClientHello frame 3; ServerHello frame 5.",
		"Alert (frame 9) from server b:443, fatal, handshake_failure (readable).",
		"Alert (frame 10) from client a:1: encrypted, level and description not visible (may be a normal close_notify).",
		"... 2 more alert record(s) for this connection (5 listed in the JSON report, tls_handshake_evidence).",
		"ClientHello frame 20 (within 2 s of the end of the capture); no ServerHello observed in this capture.",
		"ClientHello not observed in this capture.", "4 further connection(s) were not tracked", "encrypted alerts and handshake content are not decoded",
	} {
		if !strings.Contains(out, must) {
			t.Errorf("missing %q in:\n%s", must, out)
		}
	}
	for _, banned := range []string{"caused", "outage", "provider", "rejected"} {
		if strings.Contains(strings.ToLower(out), banned) {
			t.Errorf("contains %q", banned)
		}
	}
}

func TestTLSCLI_ConnectionBoundIsExplicit(t *testing.T) {
	e := &models.TLSHandshakeEvidence{ConnectionsWithEvidence: 12, MaxConnections: 50}
	for i := 0; i < 12; i++ {
		e.Connections = append(e.Connections, models.TLSConnectionEvidence{Endpoints: "x <-> y", Handshake: "no_server_hello_observed", ClientHelloFrame: uint64(i + 1)})
	}
	out := tlsText(&models.TriageReport{TLSHandshakeEvidence: e})
	if got := strings.Count(out, "  Connection "); got != cliTLSMaxConnections {
		t.Errorf("connections shown = %d", got)
	}
	if !strings.Contains(out, "Display limited: showing 8 of 12 connections; the JSON list (tls_handshake_evidence) is bounded at 50.") {
		t.Errorf("notice missing:\n%s", out)
	}
	if tlsText(&models.TriageReport{TLSHandshakeEvidence: e}) != out {
		t.Error("not deterministic")
	}
}
