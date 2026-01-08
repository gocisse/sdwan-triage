package models

import (
	"net"
	"testing"
)

func TestIsPublicDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"google.com", true},
		{"example.net", true},
		{"github.org", true},
		{"stanford.edu", true},
		{"whitehouse.gov", true},
		{"army.mil", true},
		{"example.io", true},
		{"openai.ai", true},
		{"myapp.dev", true},
		{"myapp.app", true},
		{"aws.cloud", true},
		{"example.co", true},
		{"local.lan", false},
		{"router.home", false},
		{"internal.corp", false},
		{"test.local", false},
		{"", false},
		{"google.com.", true}, // Trailing dot should be handled
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := IsPublicDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsPublicDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Private IPv4 ranges (RFC 1918)
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},

		// Loopback
		{"127.0.0.1", true},
		{"127.255.255.255", true},

		// Link-local
		{"169.254.0.1", true},
		{"169.254.255.255", true},

		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"74.6.231.20", false},
		{"2.21.74.74", false},
		{"142.250.185.46", false},

		// IPv6 loopback
		{"::1", true},

		// Invalid IPs
		{"invalid", false},
		{"", false},
		{"256.256.256.256", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := IsPrivateOrReservedIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateOrReservedIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPrivateOrReservedNetIP(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"nil IP", nil, false},
		{"private 10.x", net.ParseIP("10.0.0.1"), true},
		{"private 172.16.x", net.ParseIP("172.16.0.1"), true},
		{"private 192.168.x", net.ParseIP("192.168.1.1"), true},
		{"loopback", net.ParseIP("127.0.0.1"), true},
		{"link-local", net.ParseIP("169.254.1.1"), true},
		{"public Google DNS", net.ParseIP("8.8.8.8"), false},
		{"public Cloudflare", net.ParseIP("1.1.1.1"), false},
		{"IPv6 loopback", net.ParseIP("::1"), true},
		{"IPv6 link-local", net.ParseIP("fe80::1"), true},
		{"IPv6 ULA", net.ParseIP("fd00::1"), true},
		{"IPv6 public", net.ParseIP("2001:4860:4860::8888"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPrivateOrReservedNetIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsPrivateOrReservedNetIP(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"8.8.8.8", false},
		{"::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", true},
		{"fd00::1234:5678", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := IsIPv6(tt.ip)
			if got != tt.want {
				t.Errorf("IsIPv6(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCategorizeIPAddress(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		// Loopback
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},

		// Router/Gateway (private with .1 or .254)
		{"192.168.1.1", "router"},
		{"192.168.0.254", "router"},
		{"10.0.0.1", "router"},
		{"172.16.0.254", "router"},

		// Internal (private, not gateway)
		{"192.168.1.100", "internal"},
		{"10.0.0.50", "internal"},
		{"172.16.5.25", "internal"},

		// Link-local
		{"169.254.1.1", "link-local"},
		{"fe80::1", "link-local"},

		// External (public)
		{"8.8.8.8", "external"},
		{"1.1.1.1", "external"},
		{"142.250.185.46", "external"},

		// Invalid
		{"invalid", "external"},
		{"", "external"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := CategorizeIPAddress(tt.ip)
			if got != tt.want {
				t.Errorf("CategorizeIPAddress(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestGetIPVersion(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.1", "IPv4"},
		{"10.0.0.1", "IPv4"},
		{"8.8.8.8", "IPv4"},
		{"::1", "IPv6"},
		{"fe80::1", "IPv6"},
		{"2001:4860:4860::8888", "IPv6"},
		{"invalid", "IPv4"}, // Defaults to IPv4 for invalid
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := GetIPVersion(tt.ip)
			if got != tt.want {
				t.Errorf("GetIPVersion(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCategorizePort(t *testing.T) {
	tests := []struct {
		port     uint16
		protocol string
		want     string
	}{
		{80, "TCP", "HTTP"},
		{443, "TCP", "HTTPS"},
		{22, "TCP", "SSH"},
		{53, "UDP", "DNS"},
		{21, "TCP", "FTP"},
		{25, "TCP", "SMTP"},
		{3389, "TCP", "RDP"},
		{3306, "TCP", "MySQL"},
		{5432, "TCP", "PostgreSQL"},
		{1024, "TCP", "Registered"},
		{8080, "TCP", "HTTP-Alt"},
		{49152, "TCP", "Ephemeral"},
		{65535, "TCP", "Ephemeral"},
		{1, "TCP", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := CategorizePort(tt.port, tt.protocol)
			if got != tt.want {
				t.Errorf("CategorizePort(%d, %q) = %q, want %q", tt.port, tt.protocol, got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousPort(t *testing.T) {
	tests := []struct {
		port     uint16
		wantSusp bool
		name     string
	}{
		{4444, true, "Metasploit"},
		{5555, true, "Android Debug Bridge"},
		{6667, true, "IRC"},
		{31337, true, "Back Orifice"},
		{12345, true, "NetBus"},
		{9001, true, "Tor"},
		{80, false, "HTTP"},
		{443, false, "HTTPS"},
		{22, false, "SSH"},
		{8080, false, "HTTP-Alt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSusp, _ := IsSuspiciousPort(tt.port)
			if gotSusp != tt.wantSusp {
				t.Errorf("IsSuspiciousPort(%d) suspicious = %v, want %v", tt.port, gotSusp, tt.wantSusp)
			}
		})
	}
}

func TestResolveServiceToPort(t *testing.T) {
	tests := []struct {
		service  string
		wantPort uint16
		wantOK   bool
	}{
		{"http", 80, true},
		{"https", 443, true},
		{"ssh", 22, true},
		{"dns", 53, true},
		{"HTTP", 80, true}, // Case insensitive
		{"HTTPS", 443, true},
		{"80", 80, true}, // Direct port number
		{"443", 443, true},
		{"8080", 8080, true},
		{"unknown_service", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			gotPort, gotOK := ResolveServiceToPort(tt.service)
			if gotPort != tt.wantPort || gotOK != tt.wantOK {
				t.Errorf("ResolveServiceToPort(%q) = (%d, %v), want (%d, %v)",
					tt.service, gotPort, gotOK, tt.wantPort, tt.wantOK)
			}
		})
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{-1, 1, -1},
		{0, 0, 0},
		{-5, -3, -5},
	}

	for _, tt := range tests {
		got := Min(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("Min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
