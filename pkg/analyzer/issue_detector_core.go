package analyzer

import (
	"github.com/gocisse/sdwan-triage/pkg/models"
)

// DetectedIssue represents a specific problem identified in a stream
type DetectedIssue struct {
	ID              string
	Title           string
	TechnicalDesc   string
	BusinessImpact  string
	Severity        IssueSeverity
	Confidence      float64
	Category        IssueCategory
	RootCause       string
	AffectedService string

	// Wireshark investigation
	BaseFilter         string
	ExpandedFilter     string
	OptimizedFilter    string
	InvestigationSteps []InvestigationStep

	// Remediation
	ImmediateActions  []RemediationAction
	ShortTermFixes    []RemediationAction
	LongTermSolutions []RemediationAction

	// Metadata
	DetectionTime    string
	RelatedIssues    []string
	KnowledgeBaseRef string
}

// IssueSeverity represents the severity level
type IssueSeverity string

const (
	SeverityCritical IssueSeverity = "Critical"
	SeverityHigh     IssueSeverity = "High"
	SeverityMedium   IssueSeverity = "Medium"
	SeverityLow      IssueSeverity = "Low"
	SeverityInfo     IssueSeverity = "Info"
)

// IssueCategory groups issues by type
type IssueCategory string

const (
	CategoryM365Issues     IssueCategory = "Microsoft 365"
	CategoryDNSIssues      IssueCategory = "DNS"
	CategoryNTPIssues      IssueCategory = "NTP"
	CategorySDWANControl   IssueCategory = "SD-WAN Control Plane"
	CategorySDWANData      IssueCategory = "SD-WAN Data Plane"
	CategoryTCPIssues      IssueCategory = "TCP Transport"
	CategoryTLSIssues      IssueCategory = "TLS/SSL"
	CategoryDatabaseIssues IssueCategory = "Database Connectivity"
	CategoryVoIPIssues     IssueCategory = "VoIP/RTC"
	CategoryInfraIssues    IssueCategory = "Infrastructure"
)

// InvestigationStep represents a Wireshark analysis step
type InvestigationStep struct {
	Order              int
	Purpose            string
	DisplayFilter      string
	ExpectedNormal     string
	AbnormalSign       string
	NextStepOnNormal   string
	NextStepOnAbnormal string
	CustomColumns      []string
	ColorRule          string
}

// RemediationAction represents a specific fix
type RemediationAction struct {
	Description     string
	Commands        []string
	Verification    string
	RollbackSteps   []string
	EstimatedTime   string
	RequiresChange  bool
	SuccessRate     float64
	EscalationPoint string
}

// IssueDetector analyzes streams and detects specific problems
type IssueDetector struct {
	classifier   *AdvancedClassifier
	healthScorer *HealthScorer
	detectors    []IssueDetectorFunc
}

// IssueDetectorFunc is a function that detects specific issues
type IssueDetectorFunc func(*models.StreamData, ServiceClassification, HealthScore) []DetectedIssue

// NewIssueDetector creates a new issue detector
func NewIssueDetector() *IssueDetector {
	id := &IssueDetector{
		classifier:   NewAdvancedClassifier(),
		healthScorer: NewHealthScorer(),
		detectors:    []IssueDetectorFunc{},
	}

	// Register detection functions in priority order
	id.registerDetectors()

	return id
}

// registerDetectors registers all issue detection functions
func (id *IssueDetector) registerDetectors() {
	// High priority: Microsoft 365, DNS, SD-WAN control plane
	id.detectors = append(id.detectors, detectM365ExchangeIssues)
	id.detectors = append(id.detectors, detectM365TeamsIssues)
	id.detectors = append(id.detectors, detectM365SharePointIssues)
	id.detectors = append(id.detectors, detectM365OneDriveIssues)
	id.detectors = append(id.detectors, detectDNSIssues)
	id.detectors = append(id.detectors, detectSDWANControlPlaneIssues)

	// Medium priority: Transport layer
	id.detectors = append(id.detectors, detectTCPIssues)
	id.detectors = append(id.detectors, detectTLSIssues)

	// Lower priority: Specialized services
	id.detectors = append(id.detectors, detectNTPIssues)
	id.detectors = append(id.detectors, detectDatabaseIssues)
	id.detectors = append(id.detectors, detectSDWANDataPlaneIssues)
}

// DetectIssues analyzes a stream and returns all detected issues
func (id *IssueDetector) DetectIssues(stream *models.StreamData) []DetectedIssue {
	// Get classification and health score
	classification := id.classifier.ClassifyStream(stream)
	healthScore := id.healthScorer.ScoreStream(stream)

	// Run all detectors
	allIssues := []DetectedIssue{}
	for _, detector := range id.detectors {
		issues := detector(stream, classification, healthScore)
		allIssues = append(allIssues, issues...)
	}

	// Rank issues by severity and confidence
	rankedIssues := rankIssues(allIssues)

	return rankedIssues
}

// rankIssues sorts issues by severity and confidence
func rankIssues(issues []DetectedIssue) []DetectedIssue {
	// Simple bubble sort by severity then confidence
	for i := 0; i < len(issues); i++ {
		for j := i + 1; j < len(issues); j++ {
			if shouldSwap(issues[i], issues[j]) {
				issues[i], issues[j] = issues[j], issues[i]
			}
		}
	}
	return issues
}

func shouldSwap(a, b DetectedIssue) bool {
	// Severity priority: Critical > High > Medium > Low > Info
	severityScore := map[IssueSeverity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	aScore := severityScore[a.Severity]
	bScore := severityScore[b.Severity]

	if aScore != bScore {
		return aScore < bScore // Higher severity first
	}

	// Same severity, sort by confidence
	return a.Confidence < b.Confidence
}

// DiagnosticReport combines all analysis for a stream
type DiagnosticReport struct {
	Stream         *models.StreamData
	Classification ServiceClassification
	HealthScore    HealthScore
	DetectedIssues []DetectedIssue
	PrimaryIssue   *DetectedIssue
	CLISummary     string
	HTMLCard       string
}

// GenerateDiagnosticReport creates a complete diagnostic report
func (id *IssueDetector) GenerateDiagnosticReport(stream *models.StreamData) DiagnosticReport {
	classification := id.classifier.ClassifyStream(stream)
	healthScore := id.healthScorer.ScoreStream(stream)
	issues := id.DetectIssues(stream)

	report := DiagnosticReport{
		Stream:         stream,
		Classification: classification,
		HealthScore:    healthScore,
		DetectedIssues: issues,
	}

	// Set primary issue
	if len(issues) > 0 {
		report.PrimaryIssue = &issues[0]
	}

	// Generate CLI summary
	report.CLISummary = generateCLISummary(stream, classification, healthScore, report.PrimaryIssue)

	return report
}

// generateCLISummary creates a condensed one-line summary
func generateCLISummary(stream *models.StreamData, classification ServiceClassification, health HealthScore, primaryIssue *DetectedIssue) string {
	// Format: 🔴 Exchange: Autodiscover timeout 45s | Check: CAS array health | Fix: Restart MSExchangeAutodiscoverAppPool

	icon := health.Icon
	service := string(classification.Category)
	if service == "Unknown" {
		service = stream.Application
	}

	issue := health.PrimaryIssue
	immediateAction := "Monitor stream"

	if primaryIssue != nil {
		issue = primaryIssue.Title
		if len(primaryIssue.ImmediateActions) > 0 {
			immediateAction = primaryIssue.ImmediateActions[0].Description
		}
	}

	return icon + " " + service + ": " + issue + " | Fix: " + immediateAction
}
