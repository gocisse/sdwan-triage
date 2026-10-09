package models

// TLS handshake and alert evidence (Phase 4.34).
//
// For each TCP connection that carried a TLS alert, or a ClientHello for which no
// ServerHello was observed, this lists what was seen and where (frame numbers): the
// ClientHello and ServerHello frames, and every alert record with its direction and, when
// the alert is not encrypted, its level and description.
//
// It states what was OBSERVED. A TLS alert shows that one side sent an alert record; it
// does not by itself show why, that the application failed, or that a server, certificate,
// provider or tunnel is at fault. An alert whose content is encrypted (TLS 1.2 after the
// key change, and TLS 1.3 encrypted records) shows only that an alert record was sent: its
// level and description are not visible, so it may equally be a normal close_notify. A
// missing ServerHello can reflect packets this capture point did not see, a server that did
// not answer, or a connection that ended first. It feeds no finding, health, risk or
// exit-code decision.

// TLSHandshakeEvidenceBasis explains how to read the evidence.
const TLSHandshakeEvidenceBasis = "Per TCP connection, the ClientHello/ServerHello frames and the TLS alert records seen in this capture. " +
	"Alert level and description are shown only for alerts that are not encrypted; an encrypted alert shows only that an alert record " +
	"was sent (it may be a normal close_notify). Records are read at the start of each TCP segment without reassembly, so records " +
	"split across segments, or segments the capture did not contain, can be missed. An alert or a missing ServerHello does not by itself " +
	"show why a connection failed or where the cause lies."

// TLSAlertRecord is one TLS alert record.
type TLSAlertRecord struct {
	Frame uint64 `json:"frame,omitempty"`
	Time  string `json:"time"`
	From  string `json:"from"` // sender endpoint "address:port"
	To    string `json:"to"`
	// FromRole is "client" or "server" when the ClientHello of the connection was seen
	// (the ClientHello sender is the client), else "unknown".
	FromRole string `json:"from_role"`
	// Visibility: "plaintext" (level and description readable) or "encrypted" (not readable).
	Visibility      string `json:"visibility"`
	Level           string `json:"level,omitempty"`       // warning | fatal (plaintext only)
	Description     string `json:"description,omitempty"` // RFC alert name (plaintext only)
	DescriptionCode *uint8 `json:"description_code,omitempty"`
	Note            string `json:"note"`
}

// TLSConnectionEvidence is the TLS evidence of one TCP connection.
type TLSConnectionEvidence struct {
	Endpoints string `json:"endpoints"` // "a:port <-> b:port", sorted
	Client    string `json:"client,omitempty"`
	Server    string `json:"server,omitempty"`
	SNI       string `json:"sni,omitempty"`
	// ClientHelloFrame / ServerHelloFrame are 0 (omitted) when not observed.
	ClientHelloFrame uint64 `json:"client_hello_frame,omitempty"`
	ServerHelloFrame uint64 `json:"server_hello_frame,omitempty"`
	// Handshake: "server_hello_observed", "no_server_hello_observed" or "client_hello_not_observed".
	Handshake string `json:"handshake"`
	// NearCaptureEnd: the ClientHello was within 2 s of the last packet, which may simply have cut the exchange off.
	NearCaptureEnd bool             `json:"client_hello_near_capture_end,omitempty"`
	AlertsTotal    int              `json:"alerts_total"`
	Alerts         []TLSAlertRecord `json:"alerts,omitempty"`
	AlertsOmitted  int              `json:"alerts_omitted,omitempty"`
	Description    string           `json:"description"`
}

// TLSHandshakeEvidence is the additive JSON object `tls_handshake_evidence`; absent when
// the capture has neither a TLS alert nor a ClientHello without an observed ServerHello.
type TLSHandshakeEvidence struct {
	Basis string `json:"basis"`
	// Totals cover every tracked connection, not only the listed ones.
	ConnectionsTracked       int                     `json:"connections_tracked"`
	ConnectionsUntracked     int                     `json:"connections_untracked,omitempty"` // beyond the tracking bound: unknown
	ConnectionsWithAlerts    int                     `json:"connections_with_alerts"`
	AlertsTotal              int                     `json:"alerts_total"`
	AlertsPlaintext          int                     `json:"alerts_plaintext"`
	AlertsEncrypted          int                     `json:"alerts_encrypted"`
	ClientHelloNoServerHello int                     `json:"connections_client_hello_without_server_hello"`
	ConnectionsWithEvidence  int                     `json:"connections_with_evidence"`
	ConnectionsShown         int                     `json:"connections_shown"`
	OmittedConnections       int                     `json:"omitted_connections,omitempty"`
	MaxConnections           int                     `json:"max_connections"`
	MaxAlertsPerConnection   int                     `json:"max_alerts_per_connection"`
	Order                    string                  `json:"order"`
	Connections              []TLSConnectionEvidence `json:"connections"`
}
