// generate_samples generates small sample PCAP files for the learning platform.
// Run with: go run tools/generate_samples/main.go
//
// The scenarios themselves live in internal/testpcap so that the same
// deterministic captures are used as golden regression fixtures.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gocisse/sdwan-triage/internal/testpcap"
)

func main() {
	outputDir := "web/frontend/public/samples"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	for _, s := range testpcap.Scenarios() {
		path := filepath.Join(outputDir, s.FileName)
		packets := s.Generate()
		if err := testpcap.WriteFile(path, packets); err != nil {
			fmt.Printf("Error writing %s: %v\n", s.FileName, err)
			continue
		}
		fmt.Printf("Generated %s (%d packets)\n", s.FileName, len(packets))
	}

	fmt.Println("\nAll sample PCAPs generated successfully!")
}
