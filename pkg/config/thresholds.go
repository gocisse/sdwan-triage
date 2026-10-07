package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ThresholdsConfig holds user-configurable detection thresholds
type ThresholdsConfig struct {
	// Port scan detection thresholds
	PortScan PortScanThresholds `yaml:"port_scan"`

	// Performance thresholds
	Performance PerformanceThresholds `yaml:"performance"`

	// Analysis options
	Analysis AnalysisThresholds `yaml:"analysis"`
}

// PortScanThresholds holds port scan detection thresholds
type PortScanThresholds struct {
	HorizontalThreshold int `yaml:"horizontal_threshold"` // Unique ports scanned per source (default: 20)
	VerticalThreshold   int `yaml:"vertical_threshold"`   // Unique hosts scanned per port (default: 10)
}

// PerformanceThresholds holds performance-related thresholds
type PerformanceThresholds struct {
	HighRTTMs      float64 `yaml:"high_rtt_ms"`       // RTT threshold for warning (default: 100ms)
	CriticalRTTMs  float64 `yaml:"critical_rtt_ms"`   // RTT threshold for critical (default: 200ms)
	PacketLossWarn float64 `yaml:"packet_loss_warn"`  // Packet loss % for warning (default: 1%)
	PacketLossCrit float64 `yaml:"packet_loss_crit"`  // Packet loss % for critical (default: 5%)
	RetransmitWarn int     `yaml:"retransmit_warn"`   // Retransmissions for warning (default: 10)
	RetransmitCrit int     `yaml:"retransmit_crit"`  // Retransmissions for critical (default: 50)
	JitterWarnMs   float64 `yaml:"jitter_warn_ms"`    // Jitter threshold for warning (default: 30ms)
	JitterCritMs   float64 `yaml:"jitter_crit_ms"`    // Jitter threshold for critical (default: 50ms)
}

// AnalysisThresholds holds analysis behavior options
type AnalysisThresholds struct {
	DetectionWindowSec float64 `yaml:"detection_window_sec"` // Detection window in seconds (default: 10)
	MaxFlowsInReport   int     `yaml:"max_flows_in_report"`  // Max flows before chunking (default: 500)
}

// DefaultThresholds returns the default threshold configuration
func DefaultThresholds() *ThresholdsConfig {
	return &ThresholdsConfig{
		PortScan: PortScanThresholds{
			HorizontalThreshold: 20,
			VerticalThreshold:   10,
		},
		Performance: PerformanceThresholds{
			HighRTTMs:      100.0,
			CriticalRTTMs:  200.0,
			PacketLossWarn: 1.0,
			PacketLossCrit: 5.0,
			RetransmitWarn: 10,
			RetransmitCrit: 50,
			JitterWarnMs:   30.0,
			JitterCritMs:   50.0,
		},
		Analysis: AnalysisThresholds{
			DetectionWindowSec: 10.0,
			MaxFlowsInReport:   500,
		},
	}
}

// LoadThresholds loads threshold configuration from a YAML file
// If path is empty or a preset name, returns appropriate defaults
func LoadThresholds(path string) (*ThresholdsConfig, error) {
	// Start with defaults
	cfg := DefaultThresholds()

	// If no path provided, return defaults
	if path == "" {
		return cfg, nil
	}

	// Check if path is a preset name
	switch path {
	case "default", "":
		return cfg, nil
	case "performance":
		// Performance-focused preset: lower thresholds for RTT, packet loss and retransmissions
		cfg.Performance.HighRTTMs = 50.0
		cfg.Performance.CriticalRTTMs = 100.0
		cfg.Performance.PacketLossWarn = 0.5
		cfg.Performance.RetransmitWarn = 5
		return cfg, nil
	case "security":
		// Security-focused preset: lower port-scan thresholds
		cfg.PortScan.HorizontalThreshold = 10
		cfg.PortScan.VerticalThreshold = 5
		return cfg, nil
	}

	// Read the config file (YAML format)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read thresholds config file: %w", err)
	}

	// Parse YAML into the config struct
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse thresholds config file: %w", err)
	}

	return cfg, nil
}

// SaveThresholds saves the threshold configuration to a YAML file
func SaveThresholds(cfg *ThresholdsConfig, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal thresholds config: %w", err)
	}

	header := `# SD-WAN Triage Tool - Threshold Configuration
# Override default detection thresholds by modifying values below
# 
# Presets available via -config flag:
#   - default:     Balanced thresholds for general use
#   - performance: Lower RTT/packet loss thresholds
#   - security:    Lower port-scan thresholds for sensitive environments
#
# Custom YAML files can be loaded via: -config /path/to/config.yaml

`
	fullContent := header + string(data)

	if err := os.WriteFile(path, []byte(fullContent), 0644); err != nil {
		return fmt.Errorf("failed to write thresholds config file: %w", err)
	}

	return nil
}
