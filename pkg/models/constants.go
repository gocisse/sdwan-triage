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

// DSCP class mappings for QoS analysis
var DSCPClasses = map[uint8]string{
	0:  "BE",   // Best Effort (Default)
	8:  "CS1",  // Class Selector 1 (Scavenger)
	10: "AF11", // Assured Forwarding 11
	12: "AF12", // Assured Forwarding 12
	14: "AF13", // Assured Forwarding 13
	16: "CS2",  // Class Selector 2
	18: "AF21", // Assured Forwarding 21
	20: "AF22", // Assured Forwarding 22
	22: "AF23", // Assured Forwarding 23
	24: "CS3",  // Class Selector 3
	26: "AF31", // Assured Forwarding 31
	28: "AF32", // Assured Forwarding 32
	30: "AF33", // Assured Forwarding 33
	32: "CS4",  // Class Selector 4
	34: "AF41", // Assured Forwarding 41
	36: "AF42", // Assured Forwarding 42
	38: "AF43", // Assured Forwarding 43
	40: "CS5",  // Class Selector 5
	46: "EF",   // Expedited Forwarding (VoIP)
	48: "CS6",  // Class Selector 6 (Network Control)
	56: "CS7",  // Class Selector 7 (Network Control)
}

// DSCP class descriptions for reporting
var DSCPDescriptions = map[string]string{
	"BE":   "Best Effort - Default traffic class",
	"CS1":  "Scavenger - Low priority background traffic",
	"AF11": "Assured Forwarding 11 - Low drop probability",
	"AF12": "Assured Forwarding 12 - Medium drop probability",
	"AF13": "Assured Forwarding 13 - High drop probability",
	"CS2":  "Class Selector 2 - OAM traffic",
	"AF21": "Assured Forwarding 21 - Low drop probability",
	"AF22": "Assured Forwarding 22 - Medium drop probability",
	"AF23": "Assured Forwarding 23 - High drop probability",
	"CS3":  "Class Selector 3 - Signaling",
	"AF31": "Assured Forwarding 31 - Low drop probability",
	"AF32": "Assured Forwarding 32 - Medium drop probability",
	"AF33": "Assured Forwarding 33 - High drop probability",
	"CS4":  "Class Selector 4 - Real-time interactive",
	"AF41": "Assured Forwarding 41 - Low drop probability",
	"AF42": "Assured Forwarding 42 - Medium drop probability",
	"AF43": "Assured Forwarding 43 - High drop probability",
	"CS5":  "Class Selector 5 - Broadcast video",
	"EF":   "Expedited Forwarding - VoIP/Real-time",
	"CS6":  "Class Selector 6 - Network control",
	"CS7":  "Class Selector 7 - Network control",
}

// AppSignature holds application signature information
type AppSignature struct {
	Pattern     string
	Category    string
	Description string
}

// AppSignatures for heuristic identification
var AppSignatures = map[string]AppSignature{
	"SSH":        {Pattern: "SSH-", Category: "Remote Access", Description: "Secure Shell"},
	"HTTP":       {Pattern: "HTTP/", Category: "Web", Description: "Hypertext Transfer Protocol"},
	"TLS":        {Pattern: "\x16\x03", Category: "Encrypted", Description: "TLS Handshake"},
	"DNS":        {Pattern: "", Category: "Network", Description: "Domain Name System"},
	"SMB":        {Pattern: "\xffSMB", Category: "File Sharing", Description: "Server Message Block"},
	"RDP":        {Pattern: "\x03\x00", Category: "Remote Access", Description: "Remote Desktop Protocol"},
	"MySQL":      {Pattern: "", Category: "Database", Description: "MySQL Database"},
	"PostgreSQL": {Pattern: "", Category: "Database", Description: "PostgreSQL Database"},
}
