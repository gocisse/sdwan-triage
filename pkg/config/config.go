package config

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
)

//go:embed templates/*.json
var embeddedTemplates embed.FS

// Config holds all configuration settings for the report
type Config struct {
	Report ReportConfig `json:"report"`
}

// ReportConfig holds report-specific settings
type ReportConfig struct {
	Template        string   `json:"template"`         // e.g., "default", "performance", "security", "custom"
	Sections        []string `json:"sections"`         // List of sections to include
	ExcludeSections []string `json:"exclude_sections"` // List of sections to exclude
	Branding        Branding `json:"branding"`
}

// Branding holds company branding settings
type Branding struct {
	CompanyName string `json:"company_name"`
	LogoPath    string `json:"logo_path"` // Optional path to embed logo
	Footer      string `json:"footer"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Report: ReportConfig{
			Template: "default",
			Sections: []string{
				"executive",
				"security",
				"performance",
				"traffic",
				"protocols",
				"network",
				"visualizations",
			},
			ExcludeSections: []string{},
			Branding: Branding{
				CompanyName: "",
				LogoPath:    "",
				Footer:      "",
			},
		},
	}
}

// LoadConfig loads configuration from a file path
// If path is empty, returns default config
// If path is a predefined template name (e.g., "performance", "security"), loads from embedded templates
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}

	// Check if it's a predefined template name
	predefinedTemplates := map[string]string{
		"default":     "templates/default.json",
		"performance": "templates/performance.json",
		"security":    "templates/security.json",
	}

	if embeddedPath, ok := predefinedTemplates[path]; ok {
		data, err := embeddedTemplates.ReadFile(embeddedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded template %s: %w", path, err)
		}
		return parseConfig(data)
	}

	// Try to load from file path
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	return parseConfig(data)
}

// parseConfig parses JSON config data into a Config struct
func parseConfig(data []byte) (*Config, error) {
	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return config, nil
}

// ShouldIncludeSection checks if a section should be included in the report
func (c *Config) ShouldIncludeSection(section string) bool {
	// If sections list is empty, include all sections
	if len(c.Report.Sections) == 0 {
		// Check if it's excluded
		for _, excluded := range c.Report.ExcludeSections {
			if excluded == section {
				return false
			}
		}
		return true
	}

	// Check if section is in the include list
	for _, included := range c.Report.Sections {
		if included == section {
			// Also check it's not excluded
			for _, excluded := range c.Report.ExcludeSections {
				if excluded == section {
					return false
				}
			}
			return true
		}
	}

	return false
}

// GetTemplateName returns the template name
func (c *Config) GetTemplateName() string {
	if c.Report.Template == "" {
		return "default"
	}
	return c.Report.Template
}
