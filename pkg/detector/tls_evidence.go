package detector

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// Phase 4.34 — TLS handshake and alert evidence. The existing TLS analyzers return before
// looking at anything but handshake records, so alerts were never seen and a connection
// that never got a ServerHello left no trace. This tracker records, per TCP connection,
// the ClientHello/ServerHello frames and alert records. It changes no existing TLS result.
//
// Parsing rules (no TCP reassembly): a segment is read as TLS records only when its first
// bytes form a plausible record header (content type 20–23, version 3.0–3.4, length within
// the TLS maximum); records are chained while each header stays plausible. A hello is
// accepted only if its handshake header is self-consistent, so that encrypted handshake
// records (e.g. a Finished message) are not mistaken for a hello. An alert needs the whole
// record inside the segment: length 2 is a plaintext alert (level 1/2); length >= 18 is an
// encrypted alert whose level and description are not visible.
const (
	// tlsEvMaxConns bounds tracked connections; further ones are counted, not tracked.
	tlsEvMaxConns = 20000
	// tlsEvMaxConnsListed bounds the listed (JSON) connections.
	tlsEvMaxConnsListed = 50
	// tlsEvMaxAlerts bounds alert records kept per connection (the total is still counted).
	tlsEvMaxAlerts  = 10
	tlsEvNearEndSec = 2.0
	tlsEvOrder      = "connections with alerts first, then ClientHello without ServerHello; within each group earlier first observation first, then endpoints; display order only"
	tlsEvTimeFmt    = "2006-01-02T15:04:05.000Z"
)

var tlsAlertNames = map[uint8]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed", 22: "record_overflow",
	30: "decompression_failure", 40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate", 43: "unsupported_certificate",
	44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
	49: "access_denied", 50: "decode_error", 51: "decrypt_error", 60: "export_restriction", 70: "protocol_version",
	71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
	109: "missing_extension", 110: "unsupported_extension", 111: "certificate_unobtainable", 112: "unrecognized_name",
	113: "bad_certificate_status_response", 114: "bad_certificate_hash_value", 115: "unknown_psk_identity",
	116: "certificate_required", 120: "no_application_protocol",
}

type tlsRecord struct {
	ct       byte
	length   int
	body     []byte // available bytes of the record body (may be shorter than length)
	complete bool
}

func plausibleTLSHeader(b []byte) (ct byte, length int, ok bool) {
	if len(b) < 5 || b[0] < 20 || b[0] > 23 || b[1] != 3 || b[2] > 4 {
		return 0, 0, false
	}
	length = int(b[3])<<8 | int(b[4])
	if length == 0 || length > 18432 {
		return 0, 0, false
	}
	return b[0], length, true
}

// parseTLSRecords chains plausible record headers from the start of a TCP payload.
func parseTLSRecords(p []byte) []tlsRecord {
	var out []tlsRecord
	for len(p) >= 5 {
		ct, n, ok := plausibleTLSHeader(p)
		if !ok {
			break
		}
		body := p[5:]
		rec := tlsRecord{ct: ct, length: n}
		if len(body) >= n {
			rec.body, rec.complete = body[:n], true
			p = body[n:]
		} else {
			rec.body = body
			p = nil
		}
		out = append(out, rec)
	}
	return out
}

// helloType returns 1 (ClientHello) or 2 (ServerHello) when the handshake record starts
// with a self-consistent hello header, else 0.
func helloType(r tlsRecord) uint8 {
	b := r.body
	if r.ct != 22 || len(b) < 6 || (b[0] != 1 && b[0] != 2) {
		return 0
	}
	if b[4] != 3 || b[5] > 4 { // legacy_version 3.0–3.4
		return 0
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if r.complete && hsLen+4 != r.length && hsLen+4 > r.length {
		return 0
	}
	if r.length < 40 {
		return 0
	}
	return b[0]
}

// isAlertRecord: a complete alert record that is either plaintext (length 2, level 1 or 2)
// or long enough to be an encrypted alert (>= 18 bytes: explicit/sequence data plus an AEAD tag).
func isAlertRecord(r tlsRecord) bool {
	if r.ct != 21 || !r.complete {
		return false
	}
	return (r.length == 2 && (r.body[0] == 1 || r.body[0] == 2)) || r.length >= 18
}

type tlsConn struct {
	a, b             string // sorted endpoints
	client           string
	sni              string
	chFrame, shFrame uint64
	shNoFrame        bool // ServerHello seen but no frame reference was available
	chTime           time.Time
	firstSeen        time.Time
	alerts           []models.TLSAlertRecord
	alertSrc         []string
	alertsTotal      int
	plaintext        int
	encrypted        int
}

type tlsEvidenceTracker struct {
	conns      map[string]*tlsConn
	untracked  int
	maxConns   int
	lastPacket time.Time
}

func newTLSEvidenceTracker() *tlsEvidenceTracker {
	return &tlsEvidenceTracker{conns: make(map[string]*tlsConn), maxConns: tlsEvMaxConns}
}

func endpointText(ip string, port uint16) string { return net.JoinHostPort(ip, fmt.Sprint(port)) }

// observe reads one TCP segment payload.
func (t *tlsEvidenceTracker) observe(payload []byte, srcIP string, srcPort uint16, dstIP string, dstPort uint16, ts time.Time, report *models.TriageReport) {
	if ts.After(t.lastPacket) {
		t.lastPacket = ts
	}
	recs := parseTLSRecords(payload)
	if len(recs) == 0 {
		return
	}
	var hello, alert bool
	for _, r := range recs {
		if helloType(r) != 0 {
			hello = true
		}
		if isAlertRecord(r) {
			alert = true
		}
	}
	if !hello && !alert {
		return
	}
	src, dst := endpointText(srcIP, srcPort), endpointText(dstIP, dstPort)
	a, b := src, dst
	if b < a {
		a, b = b, a
	}
	key := a + " <-> " + b
	c := t.conns[key]
	if c == nil {
		if len(t.conns) >= t.maxConns {
			t.untracked++
			return
		}
		c = &tlsConn{a: a, b: b, firstSeen: ts}
		t.conns[key] = c
	}
	frame, haveFrame := currentFrame(report, ts)
	for _, r := range recs {
		switch ht := helloType(r); {
		case ht == 1:
			if c.chTime.IsZero() {
				c.chTime, c.client = ts, src
				if haveFrame {
					c.chFrame = frame
				}
				if sni := extractSNI(append([]byte{0x16, 3, 1, byte(r.length >> 8), byte(r.length)}, r.body...)); sni != "" {
					c.sni = sni
				}
			}
		case ht == 2:
			if c.shFrame == 0 && !c.shNoFrame {
				if haveFrame {
					c.shFrame = frame
				} else {
					c.shNoFrame = true
				}
			}
		case isAlertRecord(r):
			c.alertsTotal++
			al := models.TLSAlertRecord{Time: ts.UTC().Format(tlsEvTimeFmt), From: src, To: dst}
			if haveFrame {
				al.Frame = frame
			}
			if r.length == 2 {
				c.plaintext++
				al.Visibility = "plaintext"
				al.Level = map[byte]string{1: "warning", 2: "fatal"}[r.body[0]]
				code := r.body[1]
				al.DescriptionCode = &code
				if name, ok := tlsAlertNames[code]; ok {
					al.Description = name
				} else {
					al.Description = fmt.Sprintf("alert_%d", code)
				}
				al.Note = fmt.Sprintf("Alert record not encrypted: %s, %s.", al.Level, al.Description)
			} else {
				c.encrypted++
				al.Visibility = "encrypted"
				al.Note = "Encrypted alert record: its level and description are not visible, so it may be a normal close_notify or a failure alert."
			}
			if len(c.alerts) < tlsEvMaxAlerts {
				c.alerts = append(c.alerts, al)
				c.alertSrc = append(c.alertSrc, src)
			}
		}
	}
}

// Finalize publishes the evidence (nil when there is nothing to report).
func (t *TLSAnalyzer) Finalize(endOfCapture time.Time, report *models.TriageReport) {
	tr := t.evidence
	if tr == nil {
		return
	}
	end := endOfCapture
	if end.IsZero() {
		end = tr.lastPacket
	}
	type item struct {
		c       *tlsConn
		group   int
		evFirst time.Time
	}
	var items []item
	ev := &models.TLSHandshakeEvidence{
		Basis: models.TLSHandshakeEvidenceBasis, ConnectionsTracked: len(tr.conns), ConnectionsUntracked: tr.untracked,
		MaxConnections: tlsEvMaxConnsListed, MaxAlertsPerConnection: tlsEvMaxAlerts, Order: tlsEvOrder,
		Connections: []models.TLSConnectionEvidence{},
	}
	for _, c := range tr.conns {
		noSH := !c.chTime.IsZero() && !c.shSeen()
		if c.alertsTotal > 0 {
			ev.ConnectionsWithAlerts++
			ev.AlertsTotal += c.alertsTotal
			ev.AlertsPlaintext += c.plaintext
			ev.AlertsEncrypted += c.encrypted
			items = append(items, item{c, 0, c.firstSeen})
		} else if noSH {
			items = append(items, item{c, 1, c.chTime})
		}
		if noSH {
			ev.ClientHelloNoServerHello++
		}
	}
	if len(items) == 0 {
		return
	}
	sort.Slice(items, func(i, j int) bool {
		x, y := items[i], items[j]
		if x.group != y.group {
			return x.group < y.group
		}
		if !x.evFirst.Equal(y.evFirst) {
			return x.evFirst.Before(y.evFirst)
		}
		return x.c.a+x.c.b < y.c.a+y.c.b
	})
	ev.ConnectionsWithEvidence = len(items)
	for idx, it := range items {
		if idx >= tlsEvMaxConnsListed {
			ev.OmittedConnections++
			continue
		}
		ev.Connections = append(ev.Connections, it.c.evidence(end))
	}
	ev.ConnectionsShown = len(ev.Connections)
	report.TLSHandshakeEvidence = ev
}

func (c *tlsConn) shSeen() bool { return c.shFrame != 0 || c.shNoFrame }

func (c *tlsConn) evidence(end time.Time) models.TLSConnectionEvidence {
	out := models.TLSConnectionEvidence{
		Endpoints: c.a + " <-> " + c.b, SNI: c.sni, ClientHelloFrame: c.chFrame, ServerHelloFrame: c.shFrame,
		AlertsTotal: c.alertsTotal, Alerts: c.alerts, AlertsOmitted: c.alertsTotal - len(c.alerts),
	}
	if c.client != "" {
		out.Client = c.client
		if c.client == c.a {
			out.Server = c.b
		} else {
			out.Server = c.a
		}
	}
	for i := range out.Alerts {
		switch {
		case c.client == "":
			out.Alerts[i].FromRole = "unknown"
		case c.alertSrc[i] == c.client:
			out.Alerts[i].FromRole = "client"
		default:
			out.Alerts[i].FromRole = "server"
		}
	}
	switch {
	case c.chTime.IsZero():
		out.Handshake = "client_hello_not_observed"
	case c.shSeen():
		out.Handshake = "server_hello_observed"
	default:
		out.Handshake = "no_server_hello_observed"
		out.NearCaptureEnd = !end.IsZero() && end.Sub(c.chTime).Seconds() < tlsEvNearEndSec
	}
	switch out.Handshake {
	case "no_server_hello_observed":
		out.Description = "A ClientHello was observed but no ServerHello was observed for this connection in this capture. " +
			"That can reflect packets this capture point did not see, a server that did not answer, or a connection that ended first; the capture cannot tell which."
		if out.NearCaptureEnd {
			out.Description += " The ClientHello is within 2 s of the end of the capture, which may simply have cut the exchange off."
		}
	case "client_hello_not_observed":
		out.Description = "The ClientHello was not observed in this capture (the connection may have started before it)."
	default:
		out.Description = "A ServerHello was observed for this connection."
	}
	if c.alertsTotal > 0 {
		out.Description += fmt.Sprintf(" %d TLS alert record(s) observed (%d readable, %d encrypted); an alert does not by itself show why the connection ended or where the cause lies.",
			c.alertsTotal, c.plaintext, c.encrypted)
	}
	return out
}
