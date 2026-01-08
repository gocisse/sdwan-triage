package models

import (
	"net"
	"strconv"
	"strings"
)

// IsPublicDomain checks if a domain is a public domain
func IsPublicDomain(domain string) bool {
	domain = strings.TrimRight(strings.ToLower(domain), ".")
	return PublicDomainRegex.MatchString(domain)
}

// IsPrivateOrReservedIP checks if an IP is private or reserved (supports both IPv4 and IPv6)
func IsPrivateOrReservedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return IsPrivateOrReservedNetIP(ip)
}

// IsPrivateOrReservedNetIP checks if a net.IP is private or reserved (supports both IPv4 and IPv6)
func IsPrivateOrReservedNetIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check IPv4 private blocks
	for _, block := range PrivateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}

	// Check IPv6 private blocks
	for _, block := range IPv6PrivateBlocks {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

// IsIPv6 checks if an IP string is IPv6
func IsIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// IsIPv6NetIP checks if a net.IP is IPv6
func IsIPv6NetIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// CategorizeIPAddress categorizes an IP address (IPv4 or IPv6)
// Returns: "internal", "router", "external", "link-local", "loopback"
func CategorizeIPAddress(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "external"
	}
	return CategorizeNetIP(ip)
}

// CategorizeNetIP categorizes a net.IP address
func CategorizeNetIP(ip net.IP) string {
	if ip == nil {
		return "external"
	}

	// Check for loopback
	if ip.IsLoopback() {
		return "loopback"
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link-local"
	}

	// IPv4 specific checks
	if ip4 := ip.To4(); ip4 != nil {
		// Check for router/gateway (.1 or .254 in private ranges)
		if IsPrivateOrReservedNetIP(ip) {
			lastOctet := ip4[3]
			if lastOctet == 1 || lastOctet == 254 {
				return "router"
			}
			return "internal"
		}
		return "external"
	}

	// IPv6 specific checks
	// Check for Unique Local Address (ULA) - fc00::/7
	if len(ip) >= 1 && (ip[0]&0xfe) == 0xfc {
		return "internal"
	}

	// Check if it's in any private/reserved block
	if IsPrivateOrReservedNetIP(ip) {
		return "internal"
	}

	return "external"
}

// GetIPVersion returns "IPv4" or "IPv6" for an IP string
func GetIPVersion(ipStr string) string {
	if IsIPv6(ipStr) {
		return "IPv6"
	}
	return "IPv4"
}

// CategorizePort returns the application name for a port
func CategorizePort(port uint16, protocol string) string {
	if appName, ok := WellKnownPorts[port]; ok {
		return appName
	}

	if port >= 49152 {
		return "Ephemeral"
	}
	if port >= 1024 {
		return "Registered"
	}

	return "Unknown"
}

// IsSuspiciousPort checks if a port is suspicious
func IsSuspiciousPort(port uint16) (bool, string) {
	if reason, ok := SuspiciousPorts[port]; ok {
		return true, reason
	}
	return false, ""
}

// ResolveServiceToPort converts service name to port number
func ResolveServiceToPort(service string) (uint16, bool) {
	// Try direct port number
	if port, err := strconv.ParseUint(service, 10, 16); err == nil {
		return uint16(port), true
	}

	// Try service name lookup
	if port, ok := ServiceToPort[strings.ToLower(service)]; ok {
		return port, true
	}

	return 0, false
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
