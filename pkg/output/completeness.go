package output

import (
	"fmt"
	"strings"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// This file is the single source of truth for how the tool words the scope of
// its evidence. It only formats models.CaptureCompleteness; it never influences
// health severity (healthVerdict does not read it), RiskScore or Findings.
//
// Wording is observational. It states what was not analyzed and what may be
// missing from the capture file; it never claims packet loss in the network.

// Verdict sub-lines for GOOD. The complete-input text is the long-standing one.
const (
	goodSublineComplete = "No significant issues detected"
	goodSublinePartial  = "No significant issues observed in the analyzed packets"
)

// completenessScopeLine closes every completeness notice.
const completenessScopeLine = "Findings cover only the analyzed packets; counts may be incomplete or may reflect effects of missing counterpart packets."

// isPartialAnalysis reports whether the report carries a provable limitation.
func isPartialAnalysis(r *models.TriageReport) bool {
	return r != nil && r.Completeness.IsPartial()
}

// goodWithNoApplicableEvidence reports whether the verdict is GOOD although no
// health-relevant evidence class had any input (evidence applicability, 4.25).
// The health level itself is untouched; this only qualifies how GOOD is worded.
func goodWithNoApplicableEvidence(r *models.TriageReport) bool {
	level, ok := networkHealthOf(r)
	return ok && level == models.NetworkHealthGood && r.EvidenceCoverage.NoHealthRelevantEvidence()
}

// noApplicableEvidenceText is the qualification sentence (ASCII dash for fixed-font
// exports such as the PDF).
func noApplicableEvidenceText(ascii bool) string {
	if ascii {
		return strings.ReplaceAll(models.NoApplicableEvidenceNote, "\u2014", "-")
	}
	return models.NoApplicableEvidenceNote
}

// goodSubline is the text after "NETWORK HEALTH: GOOD - ".
func goodSubline(r *models.TriageReport) string {
	if goodWithNoApplicableEvidence(r) {
		return strings.TrimSuffix(models.NoApplicableEvidenceNote, ".")
	}
	if isPartialAnalysis(r) {
		return goodSublinePartial
	}
	return goodSublineComplete
}

// withThousands formats n with comma separators (10667 -> "10,667").
func withThousands(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 || len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// completenessLines returns the notice as lines (nil when the analysis is
// complete). The first line of each block starts with the "⚠" marker; detail
// lines are indented. Order is fixed, so output is deterministic.
func completenessLines(r *models.TriageReport) []string {
	if !isPartialAnalysis(r) {
		return nil
	}
	c := r.Completeness
	var lines []string

	if c.PacketsUnsupported > 0 || c.PacketsDecodeFailed > 0 || c.PacketsSkipped > 0 {
		if c.PacketsUnsupported > 0 && c.PacketsRead > 0 {
			pct := 100 * float64(c.PacketsUnsupported) / float64(c.PacketsRead)
			lines = append(lines, fmt.Sprintf("⚠ PARTIAL ANALYSIS: %s of %s packets (%.1f%%) were not analyzed.",
				withThousands(c.PacketsUnsupported), withThousands(c.PacketsRead), pct))
		} else {
			lines = append(lines, "⚠ PARTIAL ANALYSIS: some packets were not fully analyzed.")
		}
		for _, u := range c.UnsupportedLinkTypes {
			lines = append(lines, fmt.Sprintf("   Unsupported link type %s: %s packets.", u.Label, withThousands(u.Packets)))
		}
		if c.PacketsDecodeFailed > 0 {
			lines = append(lines, fmt.Sprintf("   %s packets could not be decoded (no link or network layer).", withThousands(c.PacketsDecodeFailed)))
		}
		if c.PacketsSkipped > 0 {
			lines = append(lines, fmt.Sprintf("   %s packets were skipped after an internal analyzer error.", withThousands(c.PacketsSkipped)))
		}
	}
	if c.ReadErrors > 0 {
		lines = append(lines, fmt.Sprintf("⚠ INCOMPLETE CAPTURE FILE: the capture ended unexpectedly (%s read error(s)).", withThousands(c.ReadErrors)))
		lines = append(lines, "   Trailing packets may be missing.")
	}
	lines = append(lines, "   "+completenessScopeLine)
	return lines
}

// completenessText is the notice as one string (empty when complete).
func completenessText(r *models.TriageReport) string {
	return strings.Join(completenessLines(r), "\n")
}

// completenessOneLine is a compact single-line form for tabular exports.
func completenessOneLine(r *models.TriageReport) string {
	if !isPartialAnalysis(r) {
		return ""
	}
	c := r.Completeness
	var parts []string
	if c.PacketsUnsupported > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d packets not analyzed (unsupported link type)", c.PacketsUnsupported, c.PacketsRead))
	}
	if c.PacketsDecodeFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d packets could not be decoded", c.PacketsDecodeFailed))
	}
	if c.PacketsSkipped > 0 {
		parts = append(parts, fmt.Sprintf("%d packets skipped after an analyzer error", c.PacketsSkipped))
	}
	if c.ReadErrors > 0 {
		parts = append(parts, fmt.Sprintf("capture file ended unexpectedly (%d read error(s)); trailing packets may be missing", c.ReadErrors))
	}
	return "PARTIAL ANALYSIS: " + strings.Join(parts, "; ") + ". " + completenessScopeLine
}

// ─── Evidence coverage display (4.26) ───────────────────────────────────────
//
// DISPLAY ONLY. The counts come straight from report.EvidenceCoverage (the same
// values the JSON carries); nothing here judges them. They show how much
// health-relevant traffic was seen, not how much is enough: there is no
// sufficiency model, threshold or confidence level.

// evidenceCoverageReminder follows the counts on every surface.
const evidenceCoverageReminder = "Counts show how much health-relevant traffic was seen; they do not measure how much is enough."

// countNoun renders "1 TCP flow" / "2 TCP flows".
func countNoun(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// evidenceCoverageCounts is the comma-separated count list (no prefix, no period).
func evidenceCoverageCounts(c *models.EvidenceCoverage) string {
	return strings.Join([]string{
		countNoun(c.TCPFlows, "TCP flow", "TCP flows"),
		countNoun(c.DNSExchanges, "DNS exchange", "DNS exchanges"),
		countNoun(c.TLSCertificates, "TLS certificate", "TLS certificates"),
		countNoun(c.StabilitySessions, "stability unit", "stability units"),
		countNoun(c.ARPBindings, "ARP binding", "ARP bindings"),
	}, ", ")
}

// evidenceCoverageLines returns the evidence line and the reminder, or nil when
// there is nothing truthful to show: NO_DATA, errors (no report) and reports whose
// coverage was never computed.
func evidenceCoverageLines(r *models.TriageReport) []string {
	if r == nil || r.IsNoData() || r.EvidenceCoverage == nil {
		return nil
	}
	return []string{
		"Evidence examined: " + evidenceCoverageCounts(r.EvidenceCoverage) + ".",
		evidenceCoverageReminder,
	}
}
