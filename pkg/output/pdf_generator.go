package output

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/gocisse/sdwan-triage/pkg/models"
)

// PDFGenerator handles PDF report generation
type PDFGenerator struct {
	wkhtmltopdfPath string
}

// NewPDFGenerator creates a new PDF generator
func NewPDFGenerator() *PDFGenerator {
	return &PDFGenerator{
		wkhtmltopdfPath: findWkhtmltopdf(),
	}
}

// findWkhtmltopdf attempts to find wkhtmltopdf in common locations
func findWkhtmltopdf() string {
	// Check if wkhtmltopdf is in PATH
	path, err := exec.LookPath("wkhtmltopdf")
	if err == nil {
		return path
	}

	// Check common installation paths
	var commonPaths []string
	switch runtime.GOOS {
	case "darwin":
		commonPaths = []string{
			"/usr/local/bin/wkhtmltopdf",
			"/opt/homebrew/bin/wkhtmltopdf",
		}
	case "linux":
		commonPaths = []string{
			"/usr/bin/wkhtmltopdf",
			"/usr/local/bin/wkhtmltopdf",
		}
	case "windows":
		commonPaths = []string{
			"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe",
			"C:\\Program Files (x86)\\wkhtmltopdf\\bin\\wkhtmltopdf.exe",
		}
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

// IsAvailable checks if PDF generation is available
func (g *PDFGenerator) IsAvailable() bool {
	return g.wkhtmltopdfPath != ""
}

// GetInstallInstructions returns installation instructions for wkhtmltopdf
func (g *PDFGenerator) GetInstallInstructions() string {
	switch runtime.GOOS {
	case "darwin":
		return "Install wkhtmltopdf: brew install wkhtmltopdf"
	case "linux":
		return "Install wkhtmltopdf: sudo apt-get install wkhtmltopdf (Debian/Ubuntu) or sudo yum install wkhtmltopdf (RHEL/CentOS)"
	case "windows":
		return "Download and install wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html"
	default:
		return "Install wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html"
	}
}

// GeneratePDFFromHTML converts an HTML file to PDF
func (g *PDFGenerator) GeneratePDFFromHTML(htmlPath, pdfPath string) error {
	if !g.IsAvailable() {
		return fmt.Errorf("wkhtmltopdf not found. %s", g.GetInstallInstructions())
	}

	// Ensure HTML file exists
	if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
		return fmt.Errorf("HTML file not found: %s", htmlPath)
	}

	// Build wkhtmltopdf command with options for better rendering
	args := []string{
		"--enable-local-file-access",
		"--page-size", "A4",
		"--orientation", "Portrait",
		"--margin-top", "10mm",
		"--margin-bottom", "10mm",
		"--margin-left", "10mm",
		"--margin-right", "10mm",
		"--encoding", "UTF-8",
		"--no-stop-slow-scripts",
		"--javascript-delay", "1000",
		"--disable-smart-shrinking",
		htmlPath,
		pdfPath,
	}

	cmd := exec.Command(g.wkhtmltopdfPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wkhtmltopdf failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

// GeneratePDF generates a PDF report directly from the TriageReport
// This first generates an HTML file, then converts it to PDF
func (g *PDFGenerator) GeneratePDF(report *models.TriageReport, pdfPath, pcapFile string) error {
	if !g.IsAvailable() {
		return fmt.Errorf("wkhtmltopdf not found. %s", g.GetInstallInstructions())
	}

	// Create a temporary HTML file
	tempDir := os.TempDir()
	tempHTML := filepath.Join(tempDir, "sdwan_triage_temp.html")

	// Generate HTML report to temp file
	if err := GenerateHTMLReport(report, tempHTML, pcapFile); err != nil {
		return fmt.Errorf("failed to generate HTML for PDF: %w", err)
	}

	// Convert HTML to PDF
	if err := g.GeneratePDFFromHTML(tempHTML, pdfPath); err != nil {
		// Clean up temp file on error
		os.Remove(tempHTML)
		return err
	}

	// Clean up temp file
	os.Remove(tempHTML)

	return nil
}

// GeneratePDFWithConfig generates a PDF with custom configuration
func (g *PDFGenerator) GeneratePDFWithConfig(report *models.TriageReport, pdfPath, pcapFile string, options PDFOptions) error {
	if !g.IsAvailable() {
		return fmt.Errorf("wkhtmltopdf not found. %s", g.GetInstallInstructions())
	}

	// Create a temporary HTML file
	tempDir := os.TempDir()
	tempHTML := filepath.Join(tempDir, "sdwan_triage_temp.html")

	// Generate HTML report to temp file
	if err := GenerateHTMLReport(report, tempHTML, pcapFile); err != nil {
		return fmt.Errorf("failed to generate HTML for PDF: %w", err)
	}

	// Build wkhtmltopdf command with custom options
	args := []string{
		"--enable-local-file-access",
		"--page-size", options.PageSize,
		"--orientation", options.Orientation,
		"--margin-top", options.MarginTop,
		"--margin-bottom", options.MarginBottom,
		"--margin-left", options.MarginLeft,
		"--margin-right", options.MarginRight,
		"--encoding", "UTF-8",
		"--no-stop-slow-scripts",
		"--javascript-delay", "1000",
	}

	if options.Grayscale {
		args = append(args, "--grayscale")
	}

	if options.LowQuality {
		args = append(args, "--lowquality")
	}

	args = append(args, tempHTML, pdfPath)

	cmd := exec.Command(g.wkhtmltopdfPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(tempHTML)
		return fmt.Errorf("wkhtmltopdf failed: %v\nOutput: %s", err, string(output))
	}

	// Clean up temp file
	os.Remove(tempHTML)

	return nil
}

// PDFOptions contains options for PDF generation
type PDFOptions struct {
	PageSize     string // "A4", "Letter", etc.
	Orientation  string // "Portrait" or "Landscape"
	MarginTop    string
	MarginBottom string
	MarginLeft   string
	MarginRight  string
	Grayscale    bool
	LowQuality   bool
}

// DefaultPDFOptions returns default PDF generation options
func DefaultPDFOptions() PDFOptions {
	return PDFOptions{
		PageSize:     "A4",
		Orientation:  "Portrait",
		MarginTop:    "10mm",
		MarginBottom: "10mm",
		MarginLeft:   "10mm",
		MarginRight:  "10mm",
		Grayscale:    false,
		LowQuality:   false,
	}
}
