package main

import (
	"embed"

	"github.com/gocisse/sdwan-triage/pkg/detector"
)

// Embed the GeoLite2-City.mmdb database so the binary is fully self-contained.
// The build step (make build) copies data/GeoLite2-City.mmdb into
// cmd/sdwan-triage/data/ before compilation via the copy-geoip target.
// If the file is not present at build time, compilation will fail —
// run "make setup-geoip" or place the mmdb in ./data/ first.

//go:embed data/GeoLite2-City.mmdb
var geoipFS embed.FS

func init() {
	data, err := geoipFS.ReadFile("data/GeoLite2-City.mmdb")
	if err != nil {
		// Not fatal — will fall back to disk-based lookup
		return
	}
	detector.SetEmbeddedGeoIPData(data)
}
