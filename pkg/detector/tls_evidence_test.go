package detector

import (
	"testing"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

func rec(ct byte, ver1 byte, body []byte) []byte {
	return append([]byte{ct, 3, ver1, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestParseTLSRecords_ChainsOnlyPlausibleHeaders(t *testing.T) {
	a := rec(21, 3, []byte{2, 40})
	b := rec(20, 3, []byte{1})
	got := parseTLSRecords(append(append([]byte(nil), a...), b...))
	if len(got) != 2 || got[0].ct != 21 || !got[0].complete || got[1].ct != 20 {
		t.Fatalf("records = %+v", got)
	}
	// Garbage after a valid record stops the chain without discarding the valid one.
	if got := parseTLSRecords(append(append([]byte(nil), a...), 9, 9, 9, 9, 9, 9)); len(got) != 1 {
		t.Errorf("records = %+v", got)
	}
	// A truncated record is reported as incomplete.
	if got := parseTLSRecords(a[:6]); len(got) != 1 || got[0].complete {
		t.Errorf("truncated = %+v", got)
	}
	for name, b := range map[string][]byte{
		"empty": nil, "short": {21, 3, 3}, "bad type": {24, 3, 3, 0, 2, 1, 1}, "bad major": {21, 2, 3, 0, 2, 1, 1},
		"bad minor": {21, 3, 9, 0, 2, 1, 1}, "zero length": {21, 3, 3, 0, 0, 1, 1}, "too long": {21, 3, 3, 0xff, 0xff, 1, 1},
	} {
		if got := parseTLSRecords(b); len(got) != 0 {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
}

func TestIsAlertRecord(t *testing.T) {
	cases := []struct {
		name string
		r    tlsRecord
		want bool
	}{
		{"plaintext warning", tlsRecord{ct: 21, length: 2, body: []byte{1, 0}, complete: true}, true},
		{"plaintext fatal", tlsRecord{ct: 21, length: 2, body: []byte{2, 40}, complete: true}, true},
		{"level 0", tlsRecord{ct: 21, length: 2, body: []byte{0, 40}, complete: true}, false},
		{"level 3", tlsRecord{ct: 21, length: 2, body: []byte{3, 40}, complete: true}, false},
		{"encrypted 26", tlsRecord{ct: 21, length: 26, body: make([]byte, 26), complete: true}, true},
		{"too short to be encrypted", tlsRecord{ct: 21, length: 17, body: make([]byte, 17), complete: true}, false},
		{"incomplete", tlsRecord{ct: 21, length: 26, body: make([]byte, 5)}, false},
		{"not an alert", tlsRecord{ct: 23, length: 26, body: make([]byte, 26), complete: true}, false},
	}
	for _, c := range cases {
		if got := isAlertRecord(c.r); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func hello(typ byte, hsLenDelta int) tlsRecord {
	body := make([]byte, 60)
	body[0] = typ
	n := len(body) - 4 + hsLenDelta
	body[1], body[2], body[3] = byte(n>>16), byte(n>>8), byte(n)
	body[4], body[5] = 3, 3
	return tlsRecord{ct: 22, length: len(body), body: body, complete: true}
}

func TestHelloType_RequiresASelfConsistentHandshakeHeader(t *testing.T) {
	if helloType(hello(1, 0)) != 1 || helloType(hello(2, 0)) != 2 {
		t.Error("valid hellos rejected")
	}
	if helloType(hello(1, 5)) != 0 { // declared handshake longer than the record
		t.Error("inconsistent length accepted")
	}
	if helloType(hello(3, 0)) != 0 {
		t.Error("other handshake type accepted")
	}
	bad := hello(1, 0)
	bad.body[4] = 9
	if helloType(bad) != 0 {
		t.Error("bad legacy version accepted")
	}
	short := hello(1, 0)
	short.length, short.body = 30, short.body[:30]
	if helloType(short) != 0 {
		t.Error("tiny hello accepted")
	}
	enc := hello(1, 0)
	enc.ct = 23
	if helloType(enc) != 0 {
		t.Error("application data accepted as hello")
	}
}

func TestTLSEvidence_TrackingBoundIsCounted(t *testing.T) {
	a := NewTLSAnalyzer()
	a.evidence.maxConns = 2
	report := &models.TriageReport{}
	for i := 0; i < 5; i++ {
		a.evidence.observe(rec(21, 3, []byte{1, 0}), "10.0.0.1", 443, "10.0.1.1", uint16(40000+i), time.Unix(1000, 0), report)
	}
	a.Finalize(time.Unix(1001, 0), report)
	e := report.TLSHandshakeEvidence
	if e == nil || e.ConnectionsTracked != 2 || e.ConnectionsUntracked != 3 || e.ConnectionsWithAlerts != 2 {
		t.Fatalf("evidence = %+v", e)
	}
}
