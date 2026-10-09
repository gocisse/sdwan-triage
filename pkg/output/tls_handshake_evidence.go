package output

import (
	"fmt"
	"io"
	"os"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.34 — concise CLI view of the TLS handshake/alert evidence. It writes nothing
// when there is no such evidence. It reports what was seen in which frame; it never
// states why a connection failed or who is at fault.
const (
	cliTLSMaxConnections = 8
	cliTLSMaxAlerts      = 3
)

// PrintTLSHandshakeEvidence writes the TLS ALERTS AND HANDSHAKES section to stdout.
func PrintTLSHandshakeEvidence(r *models.TriageReport) { WriteTLSHandshakeEvidence(os.Stdout, r) }

func helloFrame(f uint64) string {
	if f == 0 {
		return "frame not available"
	}
	return fmt.Sprintf("frame %d", f)
}

// WriteTLSHandshakeEvidence writes the section (see above).
func WriteTLSHandshakeEvidence(w io.Writer, r *models.TriageReport) {
	e := r.TLSHandshakeEvidence
	if e == nil || len(e.Connections) == 0 {
		return
	}
	fmt.Fprintln(w, "TLS ALERTS AND HANDSHAKES (observations from this capture; an alert or a missing ServerHello does not by itself show why a connection failed or where the cause lies):")
	fmt.Fprintf(w, "  %d connection(s) with a TLS alert (%d alert record(s): %d readable, %d encrypted); %d connection(s) with a ClientHello and no observed ServerHello.\n",
		e.ConnectionsWithAlerts, e.AlertsTotal, e.AlertsPlaintext, e.AlertsEncrypted, e.ClientHelloNoServerHello)
	shown := e.Connections
	if len(shown) > cliTLSMaxConnections {
		shown = shown[:cliTLSMaxConnections]
	}
	for _, c := range shown {
		sni := ""
		if c.SNI != "" {
			sni = " (SNI " + c.SNI + ")"
		}
		fmt.Fprintf(w, "  Connection %s%s\n", c.Endpoints, sni)
		switch c.Handshake {
		case "server_hello_observed":
			fmt.Fprintf(w, "    ClientHello %s; ServerHello %s.\n", helloFrame(c.ClientHelloFrame), helloFrame(c.ServerHelloFrame))
		case "no_server_hello_observed":
			end := ""
			if c.NearCaptureEnd {
				end = " (within 2 s of the end of the capture)"
			}
			fmt.Fprintf(w, "    ClientHello %s%s; no ServerHello observed in this capture.\n", helloFrame(c.ClientHelloFrame), end)
		default:
			fmt.Fprintln(w, "    ClientHello not observed in this capture.")
		}
		for i, a := range c.Alerts {
			if i >= cliTLSMaxAlerts {
				break
			}
			switch a.Visibility {
			case "plaintext":
				fmt.Fprintf(w, "    Alert (%s) from %s %s, %s, %s (%s).\n", helloFrame(a.Frame), a.FromRole, a.From, a.Level, a.Description, "readable")
			default:
				fmt.Fprintf(w, "    Alert (%s) from %s %s: encrypted, level and description not visible (may be a normal close_notify).\n", helloFrame(a.Frame), a.FromRole, a.From)
			}
		}
		if more := c.AlertsTotal - cliTLSMaxAlerts; more > 0 {
			fmt.Fprintf(w, "    ... %d more alert record(s) for this connection (%d listed in the JSON report, tls_handshake_evidence).\n", more, len(c.Alerts))
		}
	}
	if e.ConnectionsWithEvidence > len(shown) {
		fmt.Fprintf(w, "  Display limited: showing %d of %d connections; the JSON list (tls_handshake_evidence) is bounded at %d.\n", len(shown), e.ConnectionsWithEvidence, e.MaxConnections)
	}
	if e.ConnectionsUntracked > 0 {
		fmt.Fprintf(w, "  %d further connection(s) were not tracked because the tracking bound was reached; their evidence is unknown.\n", e.ConnectionsUntracked)
	}
	fmt.Fprintln(w, "  Records are read per TCP segment without reassembly; encrypted alerts and handshake content are not decoded.")
	fmt.Fprintln(w)
}
