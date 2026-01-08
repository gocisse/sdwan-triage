package detector

import (
	"net"
	"sync"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
)

// GeoIPAnalyzer handles geographic IP analysis
// Note: For full functionality, integrate with MaxMind GeoIP database
type GeoIPAnalyzer struct {
	mu              sync.RWMutex
	ipLocationCache map[string]*GeoLocation
	countryCounts   map[string]int
	enabled         bool
}

// GeoLocation represents geographic location data for an IP
type GeoLocation struct {
	Country     string
	CountryCode string
	City        string
	Region      string
	Latitude    float64
	Longitude   float64
	ASN         int
	ASName      string
	IsPrivate   bool
}

// NewGeoIPAnalyzer creates a new GeoIP analyzer
func NewGeoIPAnalyzer() *GeoIPAnalyzer {
	return &GeoIPAnalyzer{
		ipLocationCache: make(map[string]*GeoLocation),
		countryCounts:   make(map[string]int),
		enabled:         true,
	}
}

// Analyze processes packets for GeoIP information
func (g *GeoIPAnalyzer) Analyze(packet gopacket.Packet, state *models.AnalysisState, report *models.TriageReport) {
	if !g.enabled {
		return
	}

	ipInfo := ExtractIPInfo(packet)
	if ipInfo == nil {
		return
	}

	// Analyze both source and destination IPs
	g.analyzeIP(ipInfo.SrcIP)
	g.analyzeIP(ipInfo.DstIP)
}

func (g *GeoIPAnalyzer) analyzeIP(ipStr string) *GeoLocation {
	g.mu.RLock()
	if loc, exists := g.ipLocationCache[ipStr]; exists {
		g.mu.RUnlock()
		return loc
	}
	g.mu.RUnlock()

	// Parse IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Check if private IP
	loc := &GeoLocation{
		IsPrivate: isPrivateIP(ip),
	}

	if loc.IsPrivate {
		loc.Country = "Private"
		loc.CountryCode = "XX"
	} else {
		// Without MaxMind database, use basic heuristics
		// In production, this would query the GeoIP database
		loc = g.lookupIP(ip)
	}

	g.mu.Lock()
	g.ipLocationCache[ipStr] = loc
	if loc.Country != "" && !loc.IsPrivate {
		g.countryCounts[loc.Country]++
	}
	g.mu.Unlock()

	return loc
}

// lookupIP performs GeoIP lookup (stub - requires MaxMind database for full functionality)
func (g *GeoIPAnalyzer) lookupIP(ip net.IP) *GeoLocation {
	// This is a stub implementation
	// For full functionality, integrate with:
	// github.com/oschwald/maxminddb-golang
	//
	// Example with MaxMind:
	// db, _ := maxminddb.Open("GeoLite2-City.mmdb")
	// var record struct {
	//     Country struct { ISOCode string } `maxminddb:"country"`
	//     City    struct { Names map[string]string } `maxminddb:"city"`
	// }
	// db.Lookup(ip, &record)

	loc := &GeoLocation{
		IsPrivate: false,
	}

	// Basic classification based on IP ranges (very limited)
	// This is just for demonstration - real implementation needs GeoIP database
	if ip.To4() != nil {
		firstOctet := ip.To4()[0]
		switch {
		case firstOctet >= 1 && firstOctet <= 126:
			loc.Country = "Unknown (Class A)"
			loc.CountryCode = "??"
		case firstOctet >= 128 && firstOctet <= 191:
			loc.Country = "Unknown (Class B)"
			loc.CountryCode = "??"
		case firstOctet >= 192 && firstOctet <= 223:
			loc.Country = "Unknown (Class C)"
			loc.CountryCode = "??"
		default:
			loc.Country = "Unknown"
			loc.CountryCode = "??"
		}
	} else {
		loc.Country = "Unknown (IPv6)"
		loc.CountryCode = "??"
	}

	return loc
}

// GetLocationSummary returns country distribution
func (g *GeoIPAnalyzer) GetLocationSummary() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make(map[string]int)
	for country, count := range g.countryCounts {
		result[country] = count
	}
	return result
}

// GetIPLocation returns location for a specific IP
func (g *GeoIPAnalyzer) GetIPLocation(ip string) *GeoLocation {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ipLocationCache[ip]
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip4[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}

	// Check IPv6 private ranges
	if ip.To4() == nil {
		// fc00::/7 (unique local)
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
		// fe80::/10 (link-local)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		// ::1/128 (loopback)
		if ip.Equal(net.IPv6loopback) {
			return true
		}
	}

	return false
}
