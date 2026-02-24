// Handlers package provides HTTP and WebSocket handlers for the web application

package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/integration"
	"github.com/gocisse/sdwan-triage/pkg/intelligence"
	"github.com/gocisse/sdwan-triage/pkg/metrics"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// IntegrationConfig holds optional enterprise integration components.
// All fields are optional — if nil, the corresponding integration is skipped.
type IntegrationConfig struct {
	Metrics      *metrics.MetricsCollector
	Automation   *integration.AutomationEngine
	Intelligence *intelligence.CustomerDB
	Ticketing    integration.TicketingSystem
}

// Handlers contains all HTTP handlers
type Handlers struct {
	store        *storage.Storage
	upgrader     websocket.Upgrader
	integrations *IntegrationConfig
}

// NewHandlers creates a new handlers instance
func NewHandlers(store *storage.Storage) *Handlers {
	return &Handlers{
		store: store,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				// Allow localhost origins only
				return strings.HasPrefix(origin, "http://127.0.0.1") ||
					strings.HasPrefix(origin, "http://localhost")
			},
		},
		integrations: &IntegrationConfig{},
	}
}

// SetIntegrations injects enterprise integration components after construction.
func (h *Handlers) SetIntegrations(cfg *IntegrationConfig) {
	if cfg != nil {
		h.integrations = cfg
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

// HealthCheck returns the server health status
func (h *Handlers) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().Format(time.RFC3339),
		Version:   "4.3.0",
	})
}

// SystemStatusResponse represents system status information
type SystemStatusResponse struct {
	Status       string `json:"status"`
	Version      string `json:"version"`
	Uptime       string `json:"uptime"`
	Platform     string `json:"platform"`
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	MemoryMB     uint64 `json:"memory_mb"`
}

var startTime = time.Now()

// SystemStatus returns detailed system status
func (h *Handlers) SystemStatus(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	c.JSON(http.StatusOK, SystemStatusResponse{
		Status:       "running",
		Version:      "4.3.0",
		Uptime:       time.Since(startTime).Round(time.Second).String(),
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		MemoryMB:     m.Alloc / 1024 / 1024,
	})
}

// UploadResponse represents the file upload response
type UploadResponse struct {
	ID       string `json:"id"`
	FileName string `json:"file_name"`
	FileSize int64  `json:"file_size"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

// AllowedExtensions defines valid PCAP file extensions
var AllowedExtensions = map[string]bool{
	".pcap":   true,
	".pcapng": true,
	".cap":    true,
}

// UploadFile handles PCAP file uploads
func (h *Handlers) UploadFile(c *gin.Context) {
	// Get the file from the request
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "No file provided",
			"details": err.Error(),
		})
		return
	}
	defer file.Close()

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !AllowedExtensions[ext] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid file type",
			"details": fmt.Sprintf("Allowed types: .pcap, .pcapng, .cap. Got: %s", ext),
		})
		return
	}

	// Validate file size (500MB max)
	const maxSize = 500 << 20
	if header.Size > maxSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "File too large",
			"details": fmt.Sprintf("Maximum file size is 500MB. Got: %d MB", header.Size/1024/1024),
		})
		return
	}

	// Generate unique ID for this analysis
	id := uuid.New().String()

	// Save the file
	filePath, err := h.store.SaveUploadedFile(id, file, header.Filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to save file",
			"details": err.Error(),
		})
		return
	}

	// Create job record
	job, err := h.store.CreateJob(id, header.Filename, header.Size, filePath)
	if err != nil {
		// Clean up file on failure
		os.Remove(filePath)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create analysis job",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, UploadResponse{
		ID:       job.ID,
		FileName: job.FileName,
		FileSize: job.FileSize,
		Status:   string(job.Status),
		Message:  "File uploaded successfully. Ready for analysis.",
	})
}

// StartAnalysis begins the PCAP analysis process
func (h *Handlers) StartAnalysis(c *gin.Context) {
	id := c.Param("id")

	job, err := h.store.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Analysis job not found",
		})
		return
	}

	// Check if already running or completed
	if job.Status == storage.StatusAnalyzing {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Analysis already in progress",
		})
		return
	}

	if job.Status == storage.StatusCompleted {
		c.JSON(http.StatusConflict, gin.H{
			"error":       "Analysis already completed",
			"results_url": fmt.Sprintf("/api/results/%s", id),
		})
		return
	}

	// Start analysis in background
	go h.runAnalysis(job)

	c.JSON(http.StatusAccepted, gin.H{
		"id":      id,
		"status":  "analyzing",
		"message": "Analysis started",
		"ws_url":  fmt.Sprintf("/api/ws/%s", id),
	})
}

// GetAnalysisStatus returns the current status of an analysis job
func (h *Handlers) GetAnalysisStatus(c *gin.Context) {
	id := c.Param("id")

	job, err := h.store.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Analysis job not found",
		})
		return
	}

	c.JSON(http.StatusOK, job)
}

// CancelAnalysis cancels a running analysis
func (h *Handlers) CancelAnalysis(c *gin.Context) {
	id := c.Param("id")

	job, err := h.store.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Analysis job not found",
		})
		return
	}

	if job.Status != storage.StatusAnalyzing {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Analysis is not running",
		})
		return
	}

	if err := h.store.CancelJob(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to cancel analysis",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"status":  "cancelled",
		"message": "Analysis cancelled",
	})
}

// GetResults returns the analysis results as JSON
func (h *Handlers) GetResults(c *gin.Context) {
	id := c.Param("id")

	job, err := h.store.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Analysis job not found",
		})
		return
	}

	if job.Status != storage.StatusCompleted {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "Analysis not completed",
			"status": job.Status,
		})
		return
	}

	// Read results file
	resultsPath, err := h.store.GetResultsFile(id, "json")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Results file not found",
		})
		return
	}

	data, err := os.ReadFile(resultsPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to read results",
		})
		return
	}

	c.Data(http.StatusOK, "application/json", data)
}

// DownloadJSON downloads the JSON results file
func (h *Handlers) DownloadJSON(c *gin.Context) {
	id := c.Param("id")

	resultsPath, err := h.store.GetResultsFile(id, "json")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Results file not found",
		})
		return
	}

	job, _ := h.store.GetJob(id)
	fileName := strings.TrimSuffix(job.FileName, filepath.Ext(job.FileName)) + "_results.json"

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.File(resultsPath)
}

// DownloadHTML downloads the HTML report file
func (h *Handlers) DownloadHTML(c *gin.Context) {
	id := c.Param("id")

	htmlPath, err := h.store.GetResultsFile(id, "html")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "HTML report not found",
		})
		return
	}

	job, _ := h.store.GetJob(id)
	fileName := strings.TrimSuffix(job.FileName, filepath.Ext(job.FileName)) + "_report.html"

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.File(htmlPath)
}

// ListHistory returns the analysis history
func (h *Handlers) ListHistory(c *gin.Context) {
	// Parse pagination parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit < 1 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	jobs, total, err := h.store.ListHistory(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve history",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items":  jobs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// DeleteAnalysis deletes an analysis and its files
func (h *Handlers) DeleteAnalysis(c *gin.Context) {
	id := c.Param("id")

	if err := h.store.DeleteJob(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Analysis not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"message": "Analysis deleted successfully",
	})
}

// WebSocketHandler handles WebSocket connections for real-time progress updates
func (h *Handlers) WebSocketHandler(c *gin.Context) {
	id := c.Param("id")

	// Verify job exists
	job, err := h.store.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Analysis job not found",
		})
		return
	}

	// Upgrade to WebSocket
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// Subscribe to job updates
	updateChan := h.store.Subscribe(id)
	defer h.store.Unsubscribe(id, updateChan)

	// Send initial status
	if err := conn.WriteJSON(job); err != nil {
		return
	}

	// If job is already completed, close connection
	if job.Status == storage.StatusCompleted || job.Status == storage.StatusFailed || job.Status == storage.StatusCancelled {
		return
	}

	// Handle incoming messages (for ping/pong and close)
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	// Send updates
	for update := range updateChan {
		if err := conn.WriteJSON(update); err != nil {
			return
		}

		// Close connection when job is done
		if update.Status == storage.StatusCompleted ||
			update.Status == storage.StatusFailed ||
			update.Status == storage.StatusCancelled {
			return
		}
	}
}

// runAnalysis performs the actual PCAP analysis
func (h *Handlers) runAnalysis(job *storage.AnalysisJob) {
	// Update status to analyzing
	job.Status = storage.StatusAnalyzing
	job.Progress = 0
	job.CurrentStep = "Initializing analysis..."
	h.store.UpdateJob(job)

	// Import and use the existing analyzer
	resultsPath, htmlPath, err := h.performAnalysis(job)
	if err != nil {
		h.store.FailJob(job.ID, err.Error())
		return
	}

	// Mark as completed
	h.store.CompleteJob(job.ID, resultsPath, htmlPath)
}

// performAnalysis runs the actual analysis using the existing engine
func (h *Handlers) performAnalysis(job *storage.AnalysisJob) (string, string, error) {
	return runPCAPAnalysis(h.store, job, h.integrations)
}

// Helper function to format file size
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// runPCAPAnalysis integrates with the existing analysis engine
func runPCAPAnalysis(store *storage.Storage, job *storage.AnalysisJob, integrations *IntegrationConfig) (string, string, error) {
	return AnalyzePCAP(store, job, integrations)
}
