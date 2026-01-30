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
	countryIPs      map[string][]string // Track IPs per country
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
		countryIPs:      make(map[string][]string),
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
		// Track the IP for this country (avoid duplicates)
		ips := g.countryIPs[loc.Country]
		found := false
		for _, existingIP := range ips {
			if existingIP == ipStr {
				found = true
				break
			}
		}
		if !found {
			g.countryIPs[loc.Country] = append(ips, ipStr)
		}
	}
	g.mu.Unlock()

	return loc
}

// lookupIP performs GeoIP lookup using known IP ranges
func (g *GeoIPAnalyzer) lookupIP(ip net.IP) *GeoLocation {
	loc := &GeoLocation{
		IsPrivate: false,
	}

	if ip.To4() == nil {
		loc.Country = "Unknown (IPv6)"
		loc.CountryCode = "??"
		return loc
	}

	ip4 := ip.To4()

	// Check against known IP ranges for major providers and regions
	// This provides meaningful geographic context without requiring external databases

	// AWS IP Ranges (approximate, based on common allocations)
	if matchCIDR(ip4, "3.0.0.0/8") || matchCIDR(ip4, "13.0.0.0/8") || matchCIDR(ip4, "15.0.0.0/8") ||
		matchCIDR(ip4, "18.0.0.0/8") || matchCIDR(ip4, "35.0.0.0/8") || matchCIDR(ip4, "52.0.0.0/8") ||
		matchCIDR(ip4, "54.0.0.0/8") || matchCIDR(ip4, "99.0.0.0/8") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Amazon AWS"
		return loc
	}

	// Microsoft Azure / Office 365 ranges
	if matchCIDR(ip4, "13.64.0.0/11") || matchCIDR(ip4, "20.0.0.0/8") || matchCIDR(ip4, "40.0.0.0/8") ||
		matchCIDR(ip4, "51.0.0.0/8") || matchCIDR(ip4, "52.96.0.0/12") || matchCIDR(ip4, "104.40.0.0/13") ||
		matchCIDR(ip4, "157.55.0.0/16") || matchCIDR(ip4, "158.115.0.0/16") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Microsoft Azure"
		return loc
	}

	// Google Cloud / Services
	if matchCIDR(ip4, "8.8.0.0/16") || matchCIDR(ip4, "34.0.0.0/8") || matchCIDR(ip4, "35.0.0.0/8") ||
		matchCIDR(ip4, "64.233.0.0/16") || matchCIDR(ip4, "66.102.0.0/16") || matchCIDR(ip4, "66.249.0.0/16") ||
		matchCIDR(ip4, "72.14.0.0/16") || matchCIDR(ip4, "74.125.0.0/16") || matchCIDR(ip4, "142.250.0.0/15") ||
		matchCIDR(ip4, "172.217.0.0/16") || matchCIDR(ip4, "173.194.0.0/16") || matchCIDR(ip4, "209.85.0.0/16") ||
		matchCIDR(ip4, "216.58.0.0/16") || matchCIDR(ip4, "216.239.0.0/16") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Google"
		return loc
	}

	// Cloudflare
	if matchCIDR(ip4, "1.1.1.0/24") || matchCIDR(ip4, "104.16.0.0/12") || matchCIDR(ip4, "172.64.0.0/13") ||
		matchCIDR(ip4, "173.245.48.0/20") || matchCIDR(ip4, "188.114.96.0/20") || matchCIDR(ip4, "190.93.240.0/20") ||
		matchCIDR(ip4, "197.234.240.0/22") || matchCIDR(ip4, "198.41.128.0/17") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Cloudflare"
		return loc
	}

	// Akamai
	if matchCIDR(ip4, "23.0.0.0/12") || matchCIDR(ip4, "104.64.0.0/10") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Akamai"
		return loc
	}

	// Facebook/Meta
	if matchCIDR(ip4, "31.13.0.0/16") || matchCIDR(ip4, "157.240.0.0/16") || matchCIDR(ip4, "179.60.192.0/22") ||
		matchCIDR(ip4, "185.60.216.0/22") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Meta/Facebook"
		return loc
	}

	// Apple
	if matchCIDR(ip4, "17.0.0.0/8") {
		loc.Country = "United States"
		loc.CountryCode = "US"
		loc.ASName = "Apple"
		return loc
	}

	// European ranges (common allocations)
	if matchCIDR(ip4, "2.0.0.0/8") || matchCIDR(ip4, "5.0.0.0/8") || matchCIDR(ip4, "31.0.0.0/8") ||
		matchCIDR(ip4, "37.0.0.0/8") || matchCIDR(ip4, "46.0.0.0/8") || matchCIDR(ip4, "62.0.0.0/8") ||
		matchCIDR(ip4, "77.0.0.0/8") || matchCIDR(ip4, "78.0.0.0/8") || matchCIDR(ip4, "79.0.0.0/8") ||
		matchCIDR(ip4, "80.0.0.0/8") || matchCIDR(ip4, "81.0.0.0/8") || matchCIDR(ip4, "82.0.0.0/8") ||
		matchCIDR(ip4, "83.0.0.0/8") || matchCIDR(ip4, "84.0.0.0/8") || matchCIDR(ip4, "85.0.0.0/8") ||
		matchCIDR(ip4, "86.0.0.0/8") || matchCIDR(ip4, "87.0.0.0/8") || matchCIDR(ip4, "88.0.0.0/8") ||
		matchCIDR(ip4, "89.0.0.0/8") || matchCIDR(ip4, "90.0.0.0/8") || matchCIDR(ip4, "91.0.0.0/8") ||
		matchCIDR(ip4, "92.0.0.0/8") || matchCIDR(ip4, "93.0.0.0/8") || matchCIDR(ip4, "94.0.0.0/8") ||
		matchCIDR(ip4, "95.0.0.0/8") || matchCIDR(ip4, "109.0.0.0/8") || matchCIDR(ip4, "176.0.0.0/8") ||
		matchCIDR(ip4, "178.0.0.0/8") || matchCIDR(ip4, "185.0.0.0/8") || matchCIDR(ip4, "188.0.0.0/8") ||
		matchCIDR(ip4, "193.0.0.0/8") || matchCIDR(ip4, "194.0.0.0/8") || matchCIDR(ip4, "195.0.0.0/8") ||
		matchCIDR(ip4, "212.0.0.0/8") || matchCIDR(ip4, "213.0.0.0/8") || matchCIDR(ip4, "217.0.0.0/8") {
		loc.Country = "Europe"
		loc.CountryCode = "EU"
		return loc
	}

	// Asia-Pacific ranges (common allocations)
	if matchCIDR(ip4, "1.0.0.0/8") || matchCIDR(ip4, "14.0.0.0/8") || matchCIDR(ip4, "27.0.0.0/8") ||
		matchCIDR(ip4, "36.0.0.0/8") || matchCIDR(ip4, "39.0.0.0/8") || matchCIDR(ip4, "42.0.0.0/8") ||
		matchCIDR(ip4, "43.0.0.0/8") || matchCIDR(ip4, "49.0.0.0/8") || matchCIDR(ip4, "58.0.0.0/8") ||
		matchCIDR(ip4, "59.0.0.0/8") || matchCIDR(ip4, "60.0.0.0/8") || matchCIDR(ip4, "61.0.0.0/8") ||
		matchCIDR(ip4, "101.0.0.0/8") || matchCIDR(ip4, "103.0.0.0/8") || matchCIDR(ip4, "106.0.0.0/8") ||
		matchCIDR(ip4, "110.0.0.0/8") || matchCIDR(ip4, "111.0.0.0/8") || matchCIDR(ip4, "112.0.0.0/8") ||
		matchCIDR(ip4, "113.0.0.0/8") || matchCIDR(ip4, "114.0.0.0/8") || matchCIDR(ip4, "115.0.0.0/8") ||
		matchCIDR(ip4, "116.0.0.0/8") || matchCIDR(ip4, "117.0.0.0/8") || matchCIDR(ip4, "118.0.0.0/8") ||
		matchCIDR(ip4, "119.0.0.0/8") || matchCIDR(ip4, "120.0.0.0/8") || matchCIDR(ip4, "121.0.0.0/8") ||
		matchCIDR(ip4, "122.0.0.0/8") || matchCIDR(ip4, "123.0.0.0/8") || matchCIDR(ip4, "124.0.0.0/8") ||
		matchCIDR(ip4, "125.0.0.0/8") || matchCIDR(ip4, "126.0.0.0/8") || matchCIDR(ip4, "175.0.0.0/8") ||
		matchCIDR(ip4, "180.0.0.0/8") || matchCIDR(ip4, "182.0.0.0/8") || matchCIDR(ip4, "183.0.0.0/8") ||
		matchCIDR(ip4, "202.0.0.0/8") || matchCIDR(ip4, "203.0.0.0/8") || matchCIDR(ip4, "210.0.0.0/8") ||
		matchCIDR(ip4, "211.0.0.0/8") || matchCIDR(ip4, "218.0.0.0/8") || matchCIDR(ip4, "219.0.0.0/8") ||
		matchCIDR(ip4, "220.0.0.0/8") || matchCIDR(ip4, "221.0.0.0/8") || matchCIDR(ip4, "222.0.0.0/8") ||
		matchCIDR(ip4, "223.0.0.0/8") {
		loc.Country = "Asia-Pacific"
		loc.CountryCode = "AP"
		return loc
	}

	// Latin America ranges
	if matchCIDR(ip4, "177.0.0.0/8") || matchCIDR(ip4, "179.0.0.0/8") || matchCIDR(ip4, "181.0.0.0/8") ||
		matchCIDR(ip4, "186.0.0.0/8") || matchCIDR(ip4, "187.0.0.0/8") || matchCIDR(ip4, "189.0.0.0/8") ||
		matchCIDR(ip4, "190.0.0.0/8") || matchCIDR(ip4, "191.0.0.0/8") || matchCIDR(ip4, "200.0.0.0/8") ||
		matchCIDR(ip4, "201.0.0.0/8") {
		loc.Country = "Latin America"
		loc.CountryCode = "LA"
		return loc
	}

	// Africa ranges
	if matchCIDR(ip4, "41.0.0.0/8") || matchCIDR(ip4, "102.0.0.0/8") || matchCIDR(ip4, "105.0.0.0/8") ||
		matchCIDR(ip4, "154.0.0.0/8") || matchCIDR(ip4, "196.0.0.0/8") || matchCIDR(ip4, "197.0.0.0/8") {
		loc.Country = "Africa"
		loc.CountryCode = "AF"
		return loc
	}

	// North America (remaining US/Canada ranges)
	if matchCIDR(ip4, "4.0.0.0/8") || matchCIDR(ip4, "6.0.0.0/8") || matchCIDR(ip4, "7.0.0.0/8") ||
		matchCIDR(ip4, "9.0.0.0/8") || matchCIDR(ip4, "11.0.0.0/8") || matchCIDR(ip4, "12.0.0.0/8") ||
		matchCIDR(ip4, "16.0.0.0/8") || matchCIDR(ip4, "19.0.0.0/8") || matchCIDR(ip4, "21.0.0.0/8") ||
		matchCIDR(ip4, "22.0.0.0/8") || matchCIDR(ip4, "24.0.0.0/8") || matchCIDR(ip4, "25.0.0.0/8") ||
		matchCIDR(ip4, "26.0.0.0/8") || matchCIDR(ip4, "28.0.0.0/8") || matchCIDR(ip4, "29.0.0.0/8") ||
		matchCIDR(ip4, "30.0.0.0/8") || matchCIDR(ip4, "32.0.0.0/8") || matchCIDR(ip4, "33.0.0.0/8") ||
		matchCIDR(ip4, "38.0.0.0/8") || matchCIDR(ip4, "44.0.0.0/8") || matchCIDR(ip4, "45.0.0.0/8") ||
		matchCIDR(ip4, "47.0.0.0/8") || matchCIDR(ip4, "48.0.0.0/8") || matchCIDR(ip4, "50.0.0.0/8") ||
		matchCIDR(ip4, "55.0.0.0/8") || matchCIDR(ip4, "56.0.0.0/8") || matchCIDR(ip4, "57.0.0.0/8") ||
		matchCIDR(ip4, "63.0.0.0/8") || matchCIDR(ip4, "64.0.0.0/8") || matchCIDR(ip4, "65.0.0.0/8") ||
		matchCIDR(ip4, "66.0.0.0/8") || matchCIDR(ip4, "67.0.0.0/8") || matchCIDR(ip4, "68.0.0.0/8") ||
		matchCIDR(ip4, "69.0.0.0/8") || matchCIDR(ip4, "70.0.0.0/8") || matchCIDR(ip4, "71.0.0.0/8") ||
		matchCIDR(ip4, "72.0.0.0/8") || matchCIDR(ip4, "73.0.0.0/8") || matchCIDR(ip4, "74.0.0.0/8") ||
		matchCIDR(ip4, "75.0.0.0/8") || matchCIDR(ip4, "76.0.0.0/8") || matchCIDR(ip4, "96.0.0.0/8") ||
		matchCIDR(ip4, "97.0.0.0/8") || matchCIDR(ip4, "98.0.0.0/8") || matchCIDR(ip4, "100.0.0.0/8") ||
		matchCIDR(ip4, "104.0.0.0/8") || matchCIDR(ip4, "107.0.0.0/8") || matchCIDR(ip4, "108.0.0.0/8") ||
		matchCIDR(ip4, "128.0.0.0/8") || matchCIDR(ip4, "129.0.0.0/8") || matchCIDR(ip4, "130.0.0.0/8") ||
		matchCIDR(ip4, "131.0.0.0/8") || matchCIDR(ip4, "132.0.0.0/8") || matchCIDR(ip4, "134.0.0.0/8") ||
		matchCIDR(ip4, "135.0.0.0/8") || matchCIDR(ip4, "136.0.0.0/8") || matchCIDR(ip4, "137.0.0.0/8") ||
		matchCIDR(ip4, "138.0.0.0/8") || matchCIDR(ip4, "139.0.0.0/8") || matchCIDR(ip4, "140.0.0.0/8") ||
		matchCIDR(ip4, "141.0.0.0/8") || matchCIDR(ip4, "142.0.0.0/8") || matchCIDR(ip4, "143.0.0.0/8") ||
		matchCIDR(ip4, "144.0.0.0/8") || matchCIDR(ip4, "146.0.0.0/8") || matchCIDR(ip4, "147.0.0.0/8") ||
		matchCIDR(ip4, "148.0.0.0/8") || matchCIDR(ip4, "149.0.0.0/8") || matchCIDR(ip4, "152.0.0.0/8") ||
		matchCIDR(ip4, "155.0.0.0/8") || matchCIDR(ip4, "156.0.0.0/8") || matchCIDR(ip4, "157.0.0.0/8") ||
		matchCIDR(ip4, "158.0.0.0/8") || matchCIDR(ip4, "159.0.0.0/8") || matchCIDR(ip4, "160.0.0.0/8") ||
		matchCIDR(ip4, "161.0.0.0/8") || matchCIDR(ip4, "162.0.0.0/8") || matchCIDR(ip4, "163.0.0.0/8") ||
		matchCIDR(ip4, "164.0.0.0/8") || matchCIDR(ip4, "165.0.0.0/8") || matchCIDR(ip4, "166.0.0.0/8") ||
		matchCIDR(ip4, "167.0.0.0/8") || matchCIDR(ip4, "168.0.0.0/8") || matchCIDR(ip4, "169.0.0.0/8") ||
		matchCIDR(ip4, "170.0.0.0/8") || matchCIDR(ip4, "171.0.0.0/8") || matchCIDR(ip4, "172.0.0.0/8") ||
		matchCIDR(ip4, "173.0.0.0/8") || matchCIDR(ip4, "174.0.0.0/8") || matchCIDR(ip4, "184.0.0.0/8") ||
		matchCIDR(ip4, "198.0.0.0/8") || matchCIDR(ip4, "199.0.0.0/8") || matchCIDR(ip4, "204.0.0.0/8") ||
		matchCIDR(ip4, "205.0.0.0/8") || matchCIDR(ip4, "206.0.0.0/8") || matchCIDR(ip4, "207.0.0.0/8") ||
		matchCIDR(ip4, "208.0.0.0/8") || matchCIDR(ip4, "209.0.0.0/8") || matchCIDR(ip4, "214.0.0.0/8") ||
		matchCIDR(ip4, "215.0.0.0/8") || matchCIDR(ip4, "216.0.0.0/8") {
		loc.Country = "North America"
		loc.CountryCode = "NA"
		return loc
	}

	// Default fallback
	loc.Country = "Unknown"
	loc.CountryCode = "??"
	return loc
}

// matchCIDR checks if an IP matches a CIDR range
func matchCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
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

// GetCountryIPs returns the list of IPs per country
func (g *GeoIPAnalyzer) GetCountryIPs() map[string][]string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make(map[string][]string)
	for country, ips := range g.countryIPs {
		ipsCopy := make([]string, len(ips))
		copy(ipsCopy, ips)
		result[country] = ipsCopy
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
