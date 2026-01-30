package intelligence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CustomerDB stores historical intelligence for cross-customer analysis
type CustomerDB struct {
	dbPath       string
	data         *IntelligenceData
	mu           sync.RWMutex
	autoSave     bool
	saveInterval time.Duration
	stopChan     chan struct{}
}

// IntelligenceData contains all stored intelligence
type IntelligenceData struct {
	Version          string                      `json:"version"`
	LastUpdated      time.Time                   `json:"last_updated"`
	IssuePatterns    map[string]*IssuePattern    `json:"issue_patterns"`
	RemediationStats map[string]*RemediationStat `json:"remediation_stats"`
	CustomerProfiles map[string]*CustomerProfile `json:"customer_profiles"`
	TrendData        *TrendAnalysis              `json:"trend_data"`
	EmergingIssues   []*EmergingIssue            `json:"emerging_issues"`
}

// IssuePattern tracks issue occurrence across customers
type IssuePattern struct {
	IssueID           string    `json:"issue_id"`
	Title             string    `json:"title"`
	Category          string    `json:"category"`
	OccurrenceCount   int64     `json:"occurrence_count"`
	AffectedCustomers int64     `json:"affected_customers"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	AvgConfidence     float64   `json:"avg_confidence"`
	VendorSpecific    string    `json:"vendor_specific,omitempty"`
	RelatedIssues     []string  `json:"related_issues"`

	// Resolution tracking
	ResolvedCount     int64   `json:"resolved_count"`
	AvgResolutionMins float64 `json:"avg_resolution_mins"`
	TopRemediation    string  `json:"top_remediation"`
}

// RemediationStat tracks remediation effectiveness
type RemediationStat struct {
	RemediationID    string    `json:"remediation_id"`
	IssueID          string    `json:"issue_id"`
	Description      string    `json:"description"`
	AttemptCount     int64     `json:"attempt_count"`
	SuccessCount     int64     `json:"success_count"`
	SuccessRate      float64   `json:"success_rate"`
	AvgTimeToFixMins float64   `json:"avg_time_to_fix_mins"`
	LastAttempt      time.Time `json:"last_attempt"`

	// Vendor-specific effectiveness
	VendorSuccessRates map[string]float64 `json:"vendor_success_rates"`

	// Failure reasons
	FailureReasons map[string]int64 `json:"failure_reasons"`
}

// CustomerProfile stores customer-specific patterns
type CustomerProfile struct {
	CustomerID    string    `json:"customer_id"`
	Name          string    `json:"name,omitempty"`
	SDWANVendor   string    `json:"sdwan_vendor"`
	AnalysisCount int64     `json:"analysis_count"`
	LastAnalysis  time.Time `json:"last_analysis"`

	// Health trends
	AvgHealthScore float64 `json:"avg_health_score"`
	HealthTrend    string  `json:"health_trend"` // "improving", "stable", "degrading"

	// Common issues
	TopIssues      []string         `json:"top_issues"`
	IssueFrequency map[string]int64 `json:"issue_frequency"`

	// Traffic patterns
	TopServices      []string `json:"top_services"`
	PeakHours        []int    `json:"peak_hours"`
	AvgBandwidthMbps float64  `json:"avg_bandwidth_mbps"`

	// Similar customers (for "customers like you" feature)
	SimilarCustomers []string `json:"similar_customers"`
}

// TrendAnalysis contains aggregate trend data
type TrendAnalysis struct {
	DailyStats    map[string]*DailyStat `json:"daily_stats"`
	WeeklyTrends  []*WeeklyTrend        `json:"weekly_trends"`
	MonthlyTrends []*MonthlyTrend       `json:"monthly_trends"`

	// Global metrics
	TotalAnalyses        int64   `json:"total_analyses"`
	TotalIssues          int64   `json:"total_issues"`
	AvgIssuesPerAnalysis float64 `json:"avg_issues_per_analysis"`

	// Service health
	ServiceHealthScores map[string]float64 `json:"service_health_scores"`
}

// DailyStat contains daily statistics
type DailyStat struct {
	Date           string  `json:"date"`
	AnalysisCount  int64   `json:"analysis_count"`
	IssueCount     int64   `json:"issue_count"`
	CriticalCount  int64   `json:"critical_count"`
	AvgHealthScore float64 `json:"avg_health_score"`
	TopIssue       string  `json:"top_issue"`
}

// WeeklyTrend contains weekly trend data
type WeeklyTrend struct {
	WeekStart      time.Time `json:"week_start"`
	AnalysisCount  int64     `json:"analysis_count"`
	IssueCount     int64     `json:"issue_count"`
	AvgHealthScore float64   `json:"avg_health_score"`
	TrendDirection string    `json:"trend_direction"` // "up", "down", "stable"
}

// MonthlyTrend contains monthly trend data
type MonthlyTrend struct {
	Month          string   `json:"month"`
	AnalysisCount  int64    `json:"analysis_count"`
	IssueCount     int64    `json:"issue_count"`
	AvgHealthScore float64  `json:"avg_health_score"`
	TopIssues      []string `json:"top_issues"`
}

// EmergingIssue represents a newly detected pattern
type EmergingIssue struct {
	IssueID           string    `json:"issue_id"`
	Title             string    `json:"title"`
	FirstDetected     time.Time `json:"first_detected"`
	OccurrenceCount   int64     `json:"occurrence_count"`
	AffectedCustomers int64     `json:"affected_customers"`
	GrowthRate        float64   `json:"growth_rate"` // Occurrences per day
	Severity          string    `json:"severity"`
	VendorAffected    string    `json:"vendor_affected,omitempty"`
	SuggestedAction   string    `json:"suggested_action"`
}

// NewCustomerDB creates a new customer database
func NewCustomerDB(dbPath string) (*CustomerDB, error) {
	db := &CustomerDB{
		dbPath:       dbPath,
		autoSave:     true,
		saveInterval: 5 * time.Minute,
		stopChan:     make(chan struct{}),
	}

	// Load existing data or create new
	if err := db.load(); err != nil {
		// Initialize empty data
		db.data = &IntelligenceData{
			Version:          "1.0",
			LastUpdated:      time.Now(),
			IssuePatterns:    make(map[string]*IssuePattern),
			RemediationStats: make(map[string]*RemediationStat),
			CustomerProfiles: make(map[string]*CustomerProfile),
			TrendData: &TrendAnalysis{
				DailyStats:          make(map[string]*DailyStat),
				WeeklyTrends:        make([]*WeeklyTrend, 0),
				MonthlyTrends:       make([]*MonthlyTrend, 0),
				ServiceHealthScores: make(map[string]float64),
			},
			EmergingIssues: make([]*EmergingIssue, 0),
		}
	}

	// Start auto-save goroutine
	if db.autoSave {
		go db.autoSaveLoop()
	}

	return db, nil
}

// load reads the database from disk
func (db *CustomerDB) load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := os.ReadFile(db.dbPath)
	if err != nil {
		return err
	}

	db.data = &IntelligenceData{}
	return json.Unmarshal(data, db.data)
}

// Save writes the database to disk
func (db *CustomerDB) Save() error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	db.data.LastUpdated = time.Now()

	data, err := json.MarshalIndent(db.data, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(db.dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(db.dbPath, data, 0644)
}

// autoSaveLoop periodically saves the database
func (db *CustomerDB) autoSaveLoop() {
	ticker := time.NewTicker(db.saveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			db.Save()
		case <-db.stopChan:
			return
		}
	}
}

// Close shuts down the database
func (db *CustomerDB) Close() error {
	close(db.stopChan)
	return db.Save()
}

// RecordIssue records an issue occurrence
func (db *CustomerDB) RecordIssue(issueID, title, category string, confidence float64, customerID, vendor string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	pattern, exists := db.data.IssuePatterns[issueID]
	if !exists {
		pattern = &IssuePattern{
			IssueID:       issueID,
			Title:         title,
			Category:      category,
			FirstSeen:     time.Now(),
			RelatedIssues: make([]string, 0),
		}
		db.data.IssuePatterns[issueID] = pattern
	}

	pattern.OccurrenceCount++
	pattern.LastSeen = time.Now()
	pattern.AvgConfidence = (pattern.AvgConfidence*float64(pattern.OccurrenceCount-1) + confidence) / float64(pattern.OccurrenceCount)

	if vendor != "" {
		pattern.VendorSpecific = vendor
	}

	// Update customer profile
	db.updateCustomerIssue(customerID, issueID)

	// Update daily stats
	db.updateDailyStats(issueID, category)

	// Check for emerging issues
	db.checkEmergingIssue(pattern)
}

// RecordRemediation records a remediation attempt
func (db *CustomerDB) RecordRemediation(remediationID, issueID, description string, success bool, timeToFixMins float64, vendor string, failureReason string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	stat, exists := db.data.RemediationStats[remediationID]
	if !exists {
		stat = &RemediationStat{
			RemediationID:      remediationID,
			IssueID:            issueID,
			Description:        description,
			VendorSuccessRates: make(map[string]float64),
			FailureReasons:     make(map[string]int64),
		}
		db.data.RemediationStats[remediationID] = stat
	}

	stat.AttemptCount++
	stat.LastAttempt = time.Now()

	if success {
		stat.SuccessCount++
		stat.AvgTimeToFixMins = (stat.AvgTimeToFixMins*float64(stat.SuccessCount-1) + timeToFixMins) / float64(stat.SuccessCount)
	} else if failureReason != "" {
		stat.FailureReasons[failureReason]++
	}

	stat.SuccessRate = float64(stat.SuccessCount) / float64(stat.AttemptCount)

	// Update vendor-specific success rate
	if vendor != "" {
		vendorAttempts := int64(1)
		vendorSuccesses := int64(0)
		if success {
			vendorSuccesses = 1
		}

		if existingRate, ok := stat.VendorSuccessRates[vendor]; ok {
			// Approximate update (simplified)
			stat.VendorSuccessRates[vendor] = (existingRate + float64(vendorSuccesses)) / 2
		} else {
			stat.VendorSuccessRates[vendor] = float64(vendorSuccesses) / float64(vendorAttempts)
		}
	}

	// Update issue pattern with top remediation
	if pattern, exists := db.data.IssuePatterns[issueID]; exists {
		if stat.SuccessRate > 0.7 {
			pattern.TopRemediation = remediationID
		}
	}
}

// updateCustomerIssue updates customer profile with issue
func (db *CustomerDB) updateCustomerIssue(customerID, issueID string) {
	if customerID == "" {
		return
	}

	profile, exists := db.data.CustomerProfiles[customerID]
	if !exists {
		profile = &CustomerProfile{
			CustomerID:     customerID,
			IssueFrequency: make(map[string]int64),
			TopIssues:      make([]string, 0),
			TopServices:    make([]string, 0),
			PeakHours:      make([]int, 0),
		}
		db.data.CustomerProfiles[customerID] = profile
	}

	profile.IssueFrequency[issueID]++
	profile.LastAnalysis = time.Now()
	profile.AnalysisCount++

	// Update top issues
	db.updateTopIssues(profile)
}

// updateTopIssues updates the top issues list for a customer
func (db *CustomerDB) updateTopIssues(profile *CustomerProfile) {
	// Find top 5 issues
	type issueCount struct {
		id    string
		count int64
	}

	issues := make([]issueCount, 0, len(profile.IssueFrequency))
	for id, count := range profile.IssueFrequency {
		issues = append(issues, issueCount{id, count})
	}

	// Sort by count
	for i := 0; i < len(issues); i++ {
		for j := i + 1; j < len(issues); j++ {
			if issues[i].count < issues[j].count {
				issues[i], issues[j] = issues[j], issues[i]
			}
		}
	}

	// Take top 5
	profile.TopIssues = make([]string, 0, 5)
	for i := 0; i < 5 && i < len(issues); i++ {
		profile.TopIssues = append(profile.TopIssues, issues[i].id)
	}
}

// updateDailyStats updates daily statistics
func (db *CustomerDB) updateDailyStats(issueID, category string) {
	today := time.Now().Format("2006-01-02")

	stat, exists := db.data.TrendData.DailyStats[today]
	if !exists {
		stat = &DailyStat{
			Date: today,
		}
		db.data.TrendData.DailyStats[today] = stat
	}

	stat.AnalysisCount++
	stat.IssueCount++

	if category == "Critical" {
		stat.CriticalCount++
	}

	db.data.TrendData.TotalIssues++
}

// checkEmergingIssue checks if an issue is emerging
func (db *CustomerDB) checkEmergingIssue(pattern *IssuePattern) {
	// Check if this is a new pattern with rapid growth
	daysSinceFirst := time.Since(pattern.FirstSeen).Hours() / 24
	if daysSinceFirst < 1 {
		daysSinceFirst = 1
	}

	growthRate := float64(pattern.OccurrenceCount) / daysSinceFirst

	// If growing rapidly (>5 occurrences per day) and relatively new (<7 days)
	if growthRate > 5 && daysSinceFirst < 7 {
		// Check if already in emerging issues
		for _, emerging := range db.data.EmergingIssues {
			if emerging.IssueID == pattern.IssueID {
				emerging.OccurrenceCount = pattern.OccurrenceCount
				emerging.GrowthRate = growthRate
				return
			}
		}

		// Add new emerging issue
		db.data.EmergingIssues = append(db.data.EmergingIssues, &EmergingIssue{
			IssueID:         pattern.IssueID,
			Title:           pattern.Title,
			FirstDetected:   pattern.FirstSeen,
			OccurrenceCount: pattern.OccurrenceCount,
			GrowthRate:      growthRate,
			Severity:        "High",
			VendorAffected:  pattern.VendorSpecific,
			SuggestedAction: "Investigate root cause and consider vendor TAC engagement",
		})
	}
}

// GetSimilarCustomers finds customers with similar issue patterns
func (db *CustomerDB) GetSimilarCustomers(customerID string, limit int) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	profile, exists := db.data.CustomerProfiles[customerID]
	if !exists {
		return nil
	}

	type similarity struct {
		id    string
		score float64
	}

	similarities := make([]similarity, 0)

	for id, other := range db.data.CustomerProfiles {
		if id == customerID {
			continue
		}

		// Calculate similarity based on common issues
		commonIssues := 0
		for issueID := range profile.IssueFrequency {
			if _, exists := other.IssueFrequency[issueID]; exists {
				commonIssues++
			}
		}

		if commonIssues > 0 {
			score := float64(commonIssues) / float64(len(profile.IssueFrequency))
			similarities = append(similarities, similarity{id, score})
		}
	}

	// Sort by similarity
	for i := 0; i < len(similarities); i++ {
		for j := i + 1; j < len(similarities); j++ {
			if similarities[i].score < similarities[j].score {
				similarities[i], similarities[j] = similarities[j], similarities[i]
			}
		}
	}

	// Return top matches
	result := make([]string, 0, limit)
	for i := 0; i < limit && i < len(similarities); i++ {
		result = append(result, similarities[i].id)
	}

	return result
}

// GetRemediationRecommendation returns the best remediation for an issue
func (db *CustomerDB) GetRemediationRecommendation(issueID, vendor string) *RemediationStat {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var bestRemediation *RemediationStat
	var bestScore float64

	for _, stat := range db.data.RemediationStats {
		if stat.IssueID != issueID {
			continue
		}

		score := stat.SuccessRate

		// Boost score for vendor-specific success
		if vendor != "" {
			if vendorRate, exists := stat.VendorSuccessRates[vendor]; exists {
				score = (score + vendorRate) / 2
			}
		}

		if score > bestScore {
			bestScore = score
			bestRemediation = stat
		}
	}

	return bestRemediation
}

// GetEmergingIssues returns current emerging issues
func (db *CustomerDB) GetEmergingIssues() []*EmergingIssue {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.data.EmergingIssues
}

// GetTrendData returns trend analysis data
func (db *CustomerDB) GetTrendData() *TrendAnalysis {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.data.TrendData
}

// GetCustomerProfile returns a customer profile
func (db *CustomerDB) GetCustomerProfile(customerID string) *CustomerProfile {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.data.CustomerProfiles[customerID]
}

// GetIssuePattern returns an issue pattern
func (db *CustomerDB) GetIssuePattern(issueID string) *IssuePattern {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.data.IssuePatterns[issueID]
}
