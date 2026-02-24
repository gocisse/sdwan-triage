package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/google/uuid"
)

// ComparisonHandlers provides endpoints for PCAP comparison mode
type ComparisonHandlers struct {
	store interface {
		GetUploadsDir() string
	}
}

// NewComparisonHandlers creates a new comparison handler.
// Accepts any store that provides GetUploadsDir().
func NewComparisonHandlers(uploadsDir string) *ComparisonHandlers {
	return &ComparisonHandlers{
		store: &simpleUploadsDir{dir: uploadsDir},
	}
}

type simpleUploadsDir struct{ dir string }

func (s *simpleUploadsDir) GetUploadsDir() string { return s.dir }

// PostCompareUpload handles the comparison of two uploaded PCAP files.
// POST /api/compare-pcap  (multipart: file_a, file_b)
func (h *ComparisonHandlers) PostCompareUpload(c *gin.Context) {
	// Parse multipart form (max 200MB total)
	if err := c.Request.ParseMultipartForm(200 << 20); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse upload: " + err.Error()})
		return
	}

	// Get file A (LAN-side)
	fileA, headerA, err := c.Request.FormFile("file_a")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing file_a (LAN-side capture)"})
		return
	}
	defer fileA.Close()

	// Get file B (WAN-side)
	fileB, headerB, err := c.Request.FormFile("file_b")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing file_b (WAN-side capture)"})
		return
	}
	defer fileB.Close()

	// Validate extensions
	for _, hdr := range []struct {
		name string
		ext  string
	}{
		{"file_a", strings.ToLower(filepath.Ext(headerA.Filename))},
		{"file_b", strings.ToLower(filepath.Ext(headerB.Filename))},
	} {
		if hdr.ext != ".pcap" && hdr.ext != ".pcapng" && hdr.ext != ".cap" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("%s has invalid extension '%s' (must be .pcap, .pcapng, or .cap)", hdr.name, hdr.ext),
			})
			return
		}
	}

	// Save both files to temp directory
	tempDir := filepath.Join(h.store.GetUploadsDir(), "compare_"+uuid.New().String())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tempDir) // Clean up after comparison

	pathA := filepath.Join(tempDir, "a_"+headerA.Filename)
	pathB := filepath.Join(tempDir, "b_"+headerB.Filename)

	if err := saveFile(fileA, pathA); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file_a: " + err.Error()})
		return
	}
	if err := saveFile(fileB, pathB); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file_b: " + err.Error()})
		return
	}

	// Run comparison
	comp := analyzer.NewComparator(false)
	report, err := comp.Compare(pathA, pathB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Comparison failed: " + err.Error()})
		return
	}

	// Replace temp paths with original filenames in the report
	report.FileA = headerA.Filename
	report.FileB = headerB.Filename

	c.JSON(http.StatusOK, report)
}

// PostCompareJobs compares two already-analyzed jobs by their PCAP files.
// POST /api/compare-jobs  { "job_a": "uuid", "job_b": "uuid" }
// This reuses PCAPs that were already uploaded for analysis.
func (h *ComparisonHandlers) PostCompareJobs(c *gin.Context) {
	// This endpoint needs access to the full storage to look up jobs.
	// It's a simpler alternative — documented but not wired until storage is injected.
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Use /api/compare-pcap with direct file uploads"})
}

func saveFile(src io.Reader, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}
