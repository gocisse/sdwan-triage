package analyzer

import (
	"sync"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// CapacityMonitor detects capacity exhaustion patterns and provides early warnings
type CapacityMonitor struct {
	classifier   *AdvancedClassifier
	healthScorer *HealthScorer

	// Historical data for trend analysis
	bandwidthHistory  []BandwidthSample
	connectionHistory []ConnectionSample
	healthHistory     []HealthSample
	mu                sync.RWMutex

	// Thresholds
	config CapacityConfig
}

// CapacityConfig defines thresholds for capacity warnings
type CapacityConfig struct {
	BandwidthWarningPercent  float64 // Warn when bandwidth > X% of baseline
	BandwidthCriticalPercent float64 // Critical when bandwidth > X% of baseline
	ConnectionWarningCount   int     // Warn when connections exceed this
	ConnectionCriticalCount  int     // Critical when connections exceed this
	HealthDegradationRate    float64 // Warn when health score drops by X per hour
	RetransmitWarningPercent float64 // Warn when retransmit rate > X%
	LatencyWarningMs         float64 // Warn when latency > X ms
	TrendWindowMinutes       int     // Time window for trend analysis
}

// BandwidthSample represents a bandwidth measurement
type BandwidthSample struct {
	Timestamp     time.Time
	BytesPerSec   uint64
	PacketsPerSec uint64
}

// ConnectionSample represents connection count measurement
type ConnectionSample struct {
	Timestamp      time.Time
	ActiveFlows    int
	NewFlowsPerSec float64
}

// HealthSample represents health score measurement
type HealthSample struct {
	Timestamp   time.Time
	AvgScore    float64
	CriticalPct float64
	DegradedPct float64
}

// CapacityWarning represents a capacity-related warning
type CapacityWarning struct {
	Type           CapacityWarningType
	Severity       IssueSeverity
	Title          string
	Description    string
	CurrentValue   float64
	ThresholdValue float64
	TrendDirection string    // "increasing", "stable", "decreasing"
	PredictedTime  time.Time // When threshold will be exceeded
	Recommendation string
}

// CapacityWarningType categorizes capacity warnings
type CapacityWarningType string

const (
	WarningBandwidthHigh      CapacityWarningType = "bandwidth_high"
	WarningConnectionsHigh    CapacityWarningType = "connections_high"
	WarningHealthDegrading    CapacityWarningType = "health_degrading"
	WarningRetransmitsHigh    CapacityWarningType = "retransmits_high"
	WarningLatencyHigh        CapacityWarningType = "latency_high"
	WarningCapacityExhaustion CapacityWarningType = "capacity_exhaustion"
)

// DefaultCapacityConfig returns sensible defaults
func DefaultCapacityConfig() CapacityConfig {
	return CapacityConfig{
		BandwidthWarningPercent:  80,
		BandwidthCriticalPercent: 95,
		ConnectionWarningCount:   5000,
		ConnectionCriticalCount:  10000,
		HealthDegradationRate:    10, // 10 points per hour
		RetransmitWarningPercent: 5,
		LatencyWarningMs:         100,
		TrendWindowMinutes:       30,
	}
}

// NewCapacityMonitor creates a new capacity monitor
func NewCapacityMonitor(config CapacityConfig) *CapacityMonitor {
	return &CapacityMonitor{
		classifier:        NewAdvancedClassifier(),
		healthScorer:      NewHealthScorer(),
		bandwidthHistory:  make([]BandwidthSample, 0),
		connectionHistory: make([]ConnectionSample, 0),
		healthHistory:     make([]HealthSample, 0),
		config:            config,
	}
}

// AnalyzeCapacity analyzes streams for capacity issues
func (cm *CapacityMonitor) AnalyzeCapacity(streams []*models.StreamData, bandwidth *models.BandwidthTimeSeries) []CapacityWarning {
	warnings := []CapacityWarning{}

	// Analyze bandwidth trends
	if bwWarnings := cm.analyzeBandwidth(bandwidth); len(bwWarnings) > 0 {
		warnings = append(warnings, bwWarnings...)
	}

	// Analyze connection counts
	if connWarnings := cm.analyzeConnections(streams); len(connWarnings) > 0 {
		warnings = append(warnings, connWarnings...)
	}

	// Analyze health score trends
	if healthWarnings := cm.analyzeHealthTrends(streams); len(healthWarnings) > 0 {
		warnings = append(warnings, healthWarnings...)
	}

	// Analyze retransmission rates
	if retransWarnings := cm.analyzeRetransmissions(streams); len(retransWarnings) > 0 {
		warnings = append(warnings, retransWarnings...)
	}

	// Predictive analysis
	if predictWarnings := cm.predictCapacityExhaustion(); len(predictWarnings) > 0 {
		warnings = append(warnings, predictWarnings...)
	}

	return warnings
}

// analyzeBandwidth checks bandwidth utilization
func (cm *CapacityMonitor) analyzeBandwidth(bandwidth *models.BandwidthTimeSeries) []CapacityWarning {
	warnings := []CapacityWarning{}

	if bandwidth == nil || len(bandwidth.Buckets) == 0 {
		return warnings
	}

	// Calculate current and peak bandwidth
	peakBps := bandwidth.PeakBytesPerSec
	avgBps := bandwidth.AvgBytesPerSec

	// Record sample for trend analysis
	cm.mu.Lock()
	cm.bandwidthHistory = append(cm.bandwidthHistory, BandwidthSample{
		Timestamp:   time.Now(),
		BytesPerSec: avgBps,
	})
	// Keep only recent history
	if len(cm.bandwidthHistory) > 1000 {
		cm.bandwidthHistory = cm.bandwidthHistory[len(cm.bandwidthHistory)-1000:]
	}
	cm.mu.Unlock()

	// Check for high bandwidth utilization
	// Assuming 1Gbps baseline (can be configured)
	baselineBps := uint64(1000 * 1000 * 1000 / 8) // 1Gbps in bytes
	utilizationPercent := float64(peakBps) / float64(baselineBps) * 100

	if utilizationPercent > cm.config.BandwidthCriticalPercent {
		warnings = append(warnings, CapacityWarning{
			Type:           WarningBandwidthHigh,
			Severity:       SeverityCritical,
			Title:          "Critical Bandwidth Utilization",
			Description:    "Peak bandwidth exceeds critical threshold",
			CurrentValue:   utilizationPercent,
			ThresholdValue: cm.config.BandwidthCriticalPercent,
			TrendDirection: cm.calculateBandwidthTrend(),
			Recommendation: "Immediate capacity expansion or traffic prioritization required",
		})
	} else if utilizationPercent > cm.config.BandwidthWarningPercent {
		warnings = append(warnings, CapacityWarning{
			Type:           WarningBandwidthHigh,
			Severity:       SeverityHigh,
			Title:          "High Bandwidth Utilization",
			Description:    "Peak bandwidth approaching capacity limit",
			CurrentValue:   utilizationPercent,
			ThresholdValue: cm.config.BandwidthWarningPercent,
			TrendDirection: cm.calculateBandwidthTrend(),
			Recommendation: "Plan for capacity expansion or implement QoS policies",
		})
	}

	return warnings
}

// analyzeConnections checks connection counts
func (cm *CapacityMonitor) analyzeConnections(streams []*models.StreamData) []CapacityWarning {
	warnings := []CapacityWarning{}

	connectionCount := len(streams)

	// Record sample
	cm.mu.Lock()
	cm.connectionHistory = append(cm.connectionHistory, ConnectionSample{
		Timestamp:   time.Now(),
		ActiveFlows: connectionCount,
	})
	if len(cm.connectionHistory) > 1000 {
		cm.connectionHistory = cm.connectionHistory[len(cm.connectionHistory)-1000:]
	}
	cm.mu.Unlock()

	if connectionCount > cm.config.ConnectionCriticalCount {
		warnings = append(warnings, CapacityWarning{
			Type:           WarningConnectionsHigh,
			Severity:       SeverityCritical,
			Title:          "Critical Connection Count",
			Description:    "Active connections exceed critical threshold",
			CurrentValue:   float64(connectionCount),
			ThresholdValue: float64(cm.config.ConnectionCriticalCount),
			TrendDirection: cm.calculateConnectionTrend(),
			Recommendation: "Connection table exhaustion imminent - investigate source of connections",
		})
	} else if connectionCount > cm.config.ConnectionWarningCount {
		warnings = append(warnings, CapacityWarning{
			Type:           WarningConnectionsHigh,
			Severity:       SeverityHigh,
			Title:          "High Connection Count",
			Description:    "Active connections approaching limit",
			CurrentValue:   float64(connectionCount),
			ThresholdValue: float64(cm.config.ConnectionWarningCount),
			TrendDirection: cm.calculateConnectionTrend(),
			Recommendation: "Monitor connection growth and prepare for scaling",
		})
	}

	return warnings
}

// analyzeHealthTrends checks for degrading health scores
func (cm *CapacityMonitor) analyzeHealthTrends(streams []*models.StreamData) []CapacityWarning {
	warnings := []CapacityWarning{}

	if len(streams) == 0 {
		return warnings
	}

	// Calculate current health distribution
	var totalScore float64
	criticalCount := 0
	degradedCount := 0

	for _, stream := range streams {
		score := cm.healthScorer.ScoreStream(stream)
		totalScore += score.Score

		switch score.Status {
		case HealthStatusCritical:
			criticalCount++
		case HealthStatusDegraded:
			degradedCount++
		}
	}

	avgScore := totalScore / float64(len(streams))
	criticalPct := float64(criticalCount) / float64(len(streams)) * 100
	degradedPct := float64(degradedCount) / float64(len(streams)) * 100

	// Record sample
	cm.mu.Lock()
	cm.healthHistory = append(cm.healthHistory, HealthSample{
		Timestamp:   time.Now(),
		AvgScore:    avgScore,
		CriticalPct: criticalPct,
		DegradedPct: degradedPct,
	})
	if len(cm.healthHistory) > 1000 {
		cm.healthHistory = cm.healthHistory[len(cm.healthHistory)-1000:]
	}
	cm.mu.Unlock()

	// Check for health degradation trend
	degradationRate := cm.calculateHealthDegradationRate()
	if degradationRate > cm.config.HealthDegradationRate {
		warnings = append(warnings, CapacityWarning{
			Type:           WarningHealthDegrading,
			Severity:       SeverityHigh,
			Title:          "Health Score Degrading",
			Description:    "Average health score declining rapidly",
			CurrentValue:   degradationRate,
			ThresholdValue: cm.config.HealthDegradationRate,
			TrendDirection: "decreasing",
			Recommendation: "Investigate root cause of performance degradation",
		})
	}

	// Check for high critical percentage
	if criticalPct > 20 {
		warnings = append(warnings, CapacityWarning{
			Type:           WarningHealthDegrading,
			Severity:       SeverityCritical,
			Title:          "High Critical Stream Percentage",
			Description:    "More than 20% of streams in critical state",
			CurrentValue:   criticalPct,
			ThresholdValue: 20,
			TrendDirection: cm.calculateHealthTrend(),
			Recommendation: "Immediate investigation required - widespread issues detected",
		})
	}

	return warnings
}

// analyzeRetransmissions checks retransmission rates
func (cm *CapacityMonitor) analyzeRetransmissions(streams []*models.StreamData) []CapacityWarning {
	warnings := []CapacityWarning{}

	if len(streams) == 0 {
		return warnings
	}

	// Calculate overall retransmission rate
	var totalPackets, totalRetransmits uint64
	for _, stream := range streams {
		totalPackets += stream.PacketCount
		for _, segment := range stream.Segments {
			if segment.IsRetransmit {
				totalRetransmits++
			}
		}
	}

	if totalPackets == 0 {
		return warnings
	}

	retransmitRate := float64(totalRetransmits) / float64(totalPackets) * 100

	if retransmitRate > cm.config.RetransmitWarningPercent {
		severity := SeverityHigh
		if retransmitRate > cm.config.RetransmitWarningPercent*2 {
			severity = SeverityCritical
		}

		warnings = append(warnings, CapacityWarning{
			Type:           WarningRetransmitsHigh,
			Severity:       severity,
			Title:          "High Retransmission Rate",
			Description:    "Network experiencing significant packet loss",
			CurrentValue:   retransmitRate,
			ThresholdValue: cm.config.RetransmitWarningPercent,
			TrendDirection: "stable",
			Recommendation: "Check network path quality, QoS configuration, and link utilization",
		})
	}

	return warnings
}

// predictCapacityExhaustion uses trend data to predict future issues
func (cm *CapacityMonitor) predictCapacityExhaustion() []CapacityWarning {
	warnings := []CapacityWarning{}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Need sufficient history for prediction
	if len(cm.bandwidthHistory) < 10 {
		return warnings
	}

	// Calculate bandwidth growth rate
	windowSize := cm.config.TrendWindowMinutes
	recentSamples := cm.getRecentBandwidthSamples(windowSize)

	if len(recentSamples) < 2 {
		return warnings
	}

	// Linear regression for trend prediction
	growthRate := cm.calculateGrowthRate(recentSamples)

	if growthRate > 0 {
		// Predict when capacity will be exhausted
		baselineBps := uint64(1000 * 1000 * 1000 / 8) // 1Gbps
		currentBps := recentSamples[len(recentSamples)-1].BytesPerSec
		remainingCapacity := float64(baselineBps) - float64(currentBps)

		if remainingCapacity > 0 && growthRate > 0 {
			hoursUntilExhaustion := remainingCapacity / growthRate / 3600

			if hoursUntilExhaustion < 24 {
				warnings = append(warnings, CapacityWarning{
					Type:           WarningCapacityExhaustion,
					Severity:       SeverityCritical,
					Title:          "Capacity Exhaustion Predicted",
					Description:    "At current growth rate, bandwidth capacity will be exhausted soon",
					CurrentValue:   hoursUntilExhaustion,
					ThresholdValue: 24,
					TrendDirection: "increasing",
					PredictedTime:  time.Now().Add(time.Duration(hoursUntilExhaustion) * time.Hour),
					Recommendation: "Immediate capacity planning required - consider traffic shaping or expansion",
				})
			} else if hoursUntilExhaustion < 168 { // 1 week
				warnings = append(warnings, CapacityWarning{
					Type:           WarningCapacityExhaustion,
					Severity:       SeverityHigh,
					Title:          "Capacity Exhaustion Warning",
					Description:    "Bandwidth capacity may be exhausted within a week",
					CurrentValue:   hoursUntilExhaustion,
					ThresholdValue: 168,
					TrendDirection: "increasing",
					PredictedTime:  time.Now().Add(time.Duration(hoursUntilExhaustion) * time.Hour),
					Recommendation: "Plan for capacity expansion or traffic optimization",
				})
			}
		}
	}

	return warnings
}

// Helper functions for trend analysis

func (cm *CapacityMonitor) calculateBandwidthTrend() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.bandwidthHistory) < 2 {
		return "stable"
	}

	recent := cm.bandwidthHistory[len(cm.bandwidthHistory)-1]
	older := cm.bandwidthHistory[len(cm.bandwidthHistory)/2]

	if recent.BytesPerSec > older.BytesPerSec*11/10 {
		return "increasing"
	} else if recent.BytesPerSec < older.BytesPerSec*9/10 {
		return "decreasing"
	}
	return "stable"
}

func (cm *CapacityMonitor) calculateConnectionTrend() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.connectionHistory) < 2 {
		return "stable"
	}

	recent := cm.connectionHistory[len(cm.connectionHistory)-1]
	older := cm.connectionHistory[len(cm.connectionHistory)/2]

	if recent.ActiveFlows > older.ActiveFlows*11/10 {
		return "increasing"
	} else if recent.ActiveFlows < older.ActiveFlows*9/10 {
		return "decreasing"
	}
	return "stable"
}

func (cm *CapacityMonitor) calculateHealthTrend() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.healthHistory) < 2 {
		return "stable"
	}

	recent := cm.healthHistory[len(cm.healthHistory)-1]
	older := cm.healthHistory[len(cm.healthHistory)/2]

	if recent.AvgScore > older.AvgScore+5 {
		return "improving"
	} else if recent.AvgScore < older.AvgScore-5 {
		return "degrading"
	}
	return "stable"
}

func (cm *CapacityMonitor) calculateHealthDegradationRate() float64 {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if len(cm.healthHistory) < 2 {
		return 0
	}

	first := cm.healthHistory[0]
	last := cm.healthHistory[len(cm.healthHistory)-1]

	duration := last.Timestamp.Sub(first.Timestamp).Hours()
	if duration < 0.1 {
		return 0
	}

	scoreDrop := first.AvgScore - last.AvgScore
	if scoreDrop < 0 {
		return 0 // Score is improving
	}

	return scoreDrop / duration
}

func (cm *CapacityMonitor) getRecentBandwidthSamples(minutes int) []BandwidthSample {
	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)

	result := make([]BandwidthSample, 0)
	for _, sample := range cm.bandwidthHistory {
		if sample.Timestamp.After(cutoff) {
			result = append(result, sample)
		}
	}
	return result
}

func (cm *CapacityMonitor) calculateGrowthRate(samples []BandwidthSample) float64 {
	if len(samples) < 2 {
		return 0
	}

	first := samples[0]
	last := samples[len(samples)-1]

	duration := last.Timestamp.Sub(first.Timestamp).Seconds()
	if duration < 1 {
		return 0
	}

	bytesGrowth := float64(last.BytesPerSec) - float64(first.BytesPerSec)
	return bytesGrowth / duration // Bytes per second growth rate
}

// GenerateCapacityIssues converts warnings to DetectedIssue format
func (cm *CapacityMonitor) GenerateCapacityIssues(warnings []CapacityWarning) []DetectedIssue {
	issues := make([]DetectedIssue, 0, len(warnings))

	for _, warning := range warnings {
		issue := DetectedIssue{
			ID:              "CAP-" + string(warning.Type),
			Title:           warning.Title,
			TechnicalDesc:   warning.Description,
			BusinessImpact:  "Performance degradation, potential service outage",
			Severity:        warning.Severity,
			Confidence:      0.85,
			Category:        CategoryInfraIssues,
			RootCause:       "Capacity constraints",
			AffectedService: "Network Infrastructure",

			ImmediateActions: []RemediationAction{
				{
					Description:    warning.Recommendation,
					Verification:   "Capacity metrics return to normal",
					EstimatedTime:  "Varies",
					RequiresChange: true,
					SuccessRate:    0.80,
				},
			},
		}
		issues = append(issues, issue)
	}

	return issues
}
