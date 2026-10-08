package output

import (
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// NO_DATA is an analysis status ORTHOGONAL to health: it means no packet reached
// the detectors because there was nothing to analyze (empty capture, or the
// user's filter excluded every packet). It is not a health level, is not
// comparable with GOOD/FAIR/WARNING/CRITICAL, and healthVerdict is never asked
// for a level when it applies. This file is the single source of truth for its
// wording on every output surface.

const (
	noDataBanner   = "NETWORK HEALTH: NO DATA - No packets were available to analyze"
	noDataStatus   = "NO_DATA"
	noDataNoVerdct = "No health judgment can be made."
)

// noDataReason is the human-readable reason (without trailing advice).
func noDataReason(r *models.TriageReport) string {
	if r != nil && r.NoDataReason == models.NoDataReasonFilterMatchedNothing {
		return "no packet matched the selected filter."
	}
	return "the capture file contains no packets."
}

// noDataAdvice says what to do next.
func noDataAdvice(r *models.TriageReport) string {
	if r != nil && r.NoDataReason == models.NoDataReasonFilterMatchedNothing {
		return "Check the filter and capture again."
	}
	return "Check the capture interface, filter and timing, then capture again."
}

// noDataLines are the explanation lines shown under the NO DATA banner (nil when
// the analysis had data).
func noDataLines(r *models.TriageReport) []string {
	if !r.IsNoData() {
		return nil
	}
	return []string{
		"Reason: " + noDataReason(r),
		noDataNoVerdct + " " + noDataAdvice(r),
	}
}

// noDataText is the explanation as one string (empty when the analysis had data).
func noDataText(r *models.TriageReport) string {
	return strings.Join(noDataLines(r), "\n")
}

// noDataOneLine is a compact ASCII form for tabular exports and the PDF.
func noDataOneLine(r *models.TriageReport) string {
	if !r.IsNoData() {
		return ""
	}
	return "NO DATA: No packets were available to analyze (" + strings.TrimSuffix(noDataReason(r), ".") + "). " + noDataNoVerdct + " " + noDataAdvice(r)
}

// noDataSimpleLines is the plain-English wording for the -simple report.
func noDataSimpleLines(r *models.TriageReport) []string {
	if !r.IsNoData() {
		return nil
	}
	first := "No packets were available to analyze. No conclusion about your network can be drawn."
	if r.NoDataReason == models.NoDataReasonFilterMatchedNothing {
		first = "No packet matched the filter you selected, so nothing was analyzed. No conclusion about your network can be drawn."
	}
	return []string{first, noDataAdvice(r)}
}

// NoDataNotice is the one-line NO_DATA notice for stderr (empty when the
// analysis had data). The CLI prints it in every output mode, including -json,
// where stdout must stay pure JSON.
func NoDataNotice(r *models.TriageReport) string { return noDataOneLine(r) }
