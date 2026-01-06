package models

import (
	"net"
	"regexp"
)

// Private IP blocks (RFC 1918 + localhost + link-local)
var PrivateIPBlocks = []*net.IPNet{
	{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{172, 16, 0, 0}, Mask: net.CIDRMask(12, 32)},
	{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
	{IP: net.IP{127, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
	{IP: net.IP{169, 254, 0, 0}, Mask: net.CIDRMask(16, 32)},
	{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
}

// Public TLD regex
var PublicDomainRegex = regexp.MustCompile(`\.(com|net|org|edu|gov|mil|int|co|io|ai|dev|app|cloud|ai)$`)

// Application port mappings
var WellKnownPorts = map[uint16]string{
	20:   "FTP-Data",
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	465:  "SMTPS",
	587:  "SMTP-Submission",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
}

// Service name to port mapping
var ServiceToPort = map[string]uint16{
	"ftp":      21,
	"ssh":      22,
	"telnet":   23,
	"smtp":     25,
	"dns":      53,
	"http":     80,
	"https":    443,
	"smb":      445,
	"mysql":    3306,
	"rdp":      3389,
	"postgres": 5432,
	"vnc":      5900,
	"redis":    6379,
}

// Suspicious/high-risk ports
var SuspiciousPorts = map[uint16]string{
	6667:  "IRC (potential botnet C&C)",
	6668:  "IRC (potential botnet C&C)",
	6669:  "IRC (potential botnet C&C)",
	1337:  "Common malware port",
	31337: "Back Orifice trojan",
	12345: "NetBus trojan",
	27374: "SubSeven trojan",
	9001:  "Tor network",
	9030:  "Tor network",
	4444:  "Metasploit default",
	5555:  "Android Debug Bridge (potential unauthorized access)",
	7777:  "Common backdoor port",
	8888:  "Common proxy/malware port",
}
