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

// IsPrivateOrReservedIP checks if an IP is private or reserved
func IsPrivateOrReservedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, block := range PrivateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
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
