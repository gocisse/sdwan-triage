package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ExportPCAPRequest represents the request body for PCAP export
type ExportPCAPRequest struct {
	// Filter fields (Wireshark-like)
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	IPAddr   string `json:"ip_addr,omitempty"` // matches either direction
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Port     uint16 `json:"port,omitempty"` // matches either direction
	Protocol string `json:"protocol,omitempty"`
	// Time-based filter (epoch seconds)
	TimeStart float64 `json:"time_start,omitempty"`
	TimeEnd   float64 `json:"time_end,omitempty"`
	// Packet index filter
	PacketIndices []int `json:"packet_indices,omitempty"`
	// Raw filter expression from frontend
	FilterExpr string `json:"filter_expr,omitempty"`
}

// ExportPCAPHandlers provides endpoints for PCAP carving / export
type ExportPCAPHandlers struct {
	packetHandlers *PacketInspectionHandlers
}

// NewExportPCAPHandlers creates new export handlers
func NewExportPCAPHandlers(packetHandlers *PacketInspectionHandlers) *ExportPCAPHandlers {
	return &ExportPCAPHandlers{
		packetHandlers: packetHandlers,
	}
}

// PostExportPCAP handles POST /api/export-pcap/:jobID
// Reads the original PCAP, filters packets, writes a new PCAP, and streams it back.
func (h *ExportPCAPHandlers) PostExportPCAP(c *gin.Context) {
	jobID := c.Param("jobID")

	// Get the job to find the original PCAP path
	job, err := h.packetHandlers.store.GetJob(jobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis job not found"})
		return
	}

	if job.FilePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No PCAP file associated with this job"})
		return
	}

	// Parse request body
	var req ExportPCAPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Parse filter expression if provided (simple Wireshark-like syntax)
	if req.FilterExpr != "" {
		parseFilterExpr(&req)
	}

	// Open source capture (auto-detects pcap vs pcapng)
	capHandle, err := analyzer.OpenCapture(job.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open capture file"})
		return
	}
	defer capHandle.Close()
	reader := capHandle.Reader

	// Create temp file for filtered output
	tmpDir := os.TempDir()
	tmpFile, err := os.CreateTemp(tmpDir, "sdwan-export-*.pcap")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp file"})
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Write PCAP header
	writer := pcapgo.NewWriter(tmpFile)
	if err := writer.WriteFileHeader(65536, reader.LinkType()); err != nil {
		tmpFile.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write PCAP header"})
		return
	}

	// Build packet index set for fast lookup
	indexSet := make(map[int]bool)
	for _, idx := range req.PacketIndices {
		indexSet[idx] = true
	}
	useIndexFilter := len(indexSet) > 0

	// Filter and write packets
	packetIndex := 0
	matchedCount := 0

	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			packetIndex++
			continue
		}

		// Index-based filter
		if useIndexFilter {
			if indexSet[packetIndex] {
				if err := writer.WritePacket(ci, data); err == nil {
					matchedCount++
				}
			}
			packetIndex++
			continue
		}

		// Time-based filter
		if req.TimeStart > 0 || req.TimeEnd > 0 {
			ts := float64(ci.Timestamp.UnixNano()) / 1e9
			if req.TimeStart > 0 && ts < req.TimeStart {
				packetIndex++
				continue
			}
			if req.TimeEnd > 0 && ts > req.TimeEnd {
				packetIndex++
				continue
			}
		}

		// Parse packet for IP/port filtering
		if req.SrcIP != "" || req.DstIP != "" || req.IPAddr != "" ||
			req.SrcPort != 0 || req.DstPort != 0 || req.Port != 0 || req.Protocol != "" {

			packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			if packet == nil {
				packetIndex++
				continue
			}

			if !matchesExportFilter(packet, &req) {
				packetIndex++
				continue
			}
		}

		// Packet passed all filters — write it
		if err := writer.WritePacket(ci, data); err == nil {
			matchedCount++
		}
		packetIndex++
	}

	tmpFile.Close()

	if matchedCount == 0 {
		c.JSON(http.StatusOK, gin.H{
			"error":         "No packets matched the filter",
			"total_scanned": packetIndex,
		})
		return
	}

	// Generate a descriptive filename
	fileName := generateExportFilename(&req, matchedCount)

	// Stream the file back
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	c.Header("Content-Type", "application/vnd.tcpdump.pcap")
	c.Header("X-Packet-Count", strconv.Itoa(matchedCount))
	c.File(tmpPath)
}

// matchesExportFilter checks if a decoded packet matches the export filter criteria
func matchesExportFilter(packet gopacket.Packet, req *ExportPCAPRequest) bool {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return false
	}

	srcIP := netLayer.NetworkFlow().Src().String()
	dstIP := netLayer.NetworkFlow().Dst().String()

	// IP address filters
	if req.IPAddr != "" {
		if srcIP != req.IPAddr && dstIP != req.IPAddr {
			return false
		}
	}
	if req.SrcIP != "" {
		if srcIP != req.SrcIP {
			return false
		}
	}
	if req.DstIP != "" {
		if dstIP != req.DstIP {
			return false
		}
	}

	// Transport layer
	transLayer := packet.TransportLayer()
	if transLayer == nil {
		if req.SrcPort != 0 || req.DstPort != 0 || req.Port != 0 || req.Protocol != "" {
			return false
		}
		return true
	}

	var srcPort, dstPort uint16
	var proto string

	switch t := transLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		proto = "TCP"
	case *layers.UDP:
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		proto = "UDP"
	default:
		return req.Protocol == "" && req.SrcPort == 0 && req.DstPort == 0 && req.Port == 0
	}

	// Protocol filter
	if req.Protocol != "" && !strings.EqualFold(proto, req.Protocol) {
		return false
	}

	// Port filters
	if req.Port != 0 {
		if srcPort != req.Port && dstPort != req.Port {
			return false
		}
	}
	if req.SrcPort != 0 && srcPort != req.SrcPort {
		return false
	}
	if req.DstPort != 0 && dstPort != req.DstPort {
		return false
	}

	return true
}

// parseFilterExpr parses a simple Wireshark-like filter expression into ExportPCAPRequest fields
func parseFilterExpr(req *ExportPCAPRequest) {
	expr := strings.TrimSpace(req.FilterExpr)
	if expr == "" {
		return
	}

	// Split on && or "and"
	clauses := strings.FieldsFunc(expr, func(r rune) bool { return false })
	parts := strings.Split(expr, "&&")
	if len(parts) == 1 {
		parts = strings.Split(expr, " and ")
	}
	_ = clauses

	for _, part := range parts {
		p := strings.TrimSpace(part)

		// Try: field == value
		if idx := strings.Index(p, "=="); idx > 0 {
			field := strings.TrimSpace(p[:idx])
			value := strings.TrimSpace(p[idx+2:])
			value = strings.Trim(value, "\"'")

			switch strings.ToLower(field) {
			case "ip.src":
				req.SrcIP = value
			case "ip.dst":
				req.DstIP = value
			case "ip.addr":
				if req.IPAddr == "" {
					req.IPAddr = value
				} else {
					// Second ip.addr → treat as src+dst pair
					req.SrcIP = req.IPAddr
					req.DstIP = value
					req.IPAddr = ""
				}
			case "tcp.port", "udp.port":
				if v, err := strconv.ParseUint(value, 10, 16); err == nil {
					req.Port = uint16(v)
				}
			case "tcp.srcport", "udp.srcport":
				if v, err := strconv.ParseUint(value, 10, 16); err == nil {
					req.SrcPort = uint16(v)
				}
			case "tcp.dstport", "udp.dstport":
				if v, err := strconv.ParseUint(value, 10, 16); err == nil {
					req.DstPort = uint16(v)
				}
			case "frame.protocol":
				req.Protocol = strings.ToUpper(value)
			}
		}
	}
}

// generateExportFilename creates a descriptive filename for the carved PCAP
func generateExportFilename(req *ExportPCAPRequest, count int) string {
	parts := []string{"sdwan-triage-export"}

	if req.IPAddr != "" {
		parts = append(parts, strings.ReplaceAll(req.IPAddr, ":", "-"))
	}
	if req.SrcIP != "" {
		parts = append(parts, strings.ReplaceAll(req.SrcIP, ":", "-"))
	}
	if req.DstIP != "" {
		parts = append(parts, "to", strings.ReplaceAll(req.DstIP, ":", "-"))
	}
	if req.Port != 0 {
		parts = append(parts, fmt.Sprintf("port%d", req.Port))
	}
	if req.Protocol != "" {
		parts = append(parts, strings.ToLower(req.Protocol))
	}

	parts = append(parts, fmt.Sprintf("%dpkts", count))
	parts = append(parts, time.Now().Format("20060102_150405"))

	return strings.Join(parts, "_") + ".pcap"
}

// ─── Packet Annotations ─────────────────────────────────────────

// AnnotationRequest represents a request to annotate a packet
type AnnotationRequest struct {
	PacketIndex int    `json:"packet_index" binding:"required"`
	Note        string `json:"note" binding:"required"`
}

// AnnotationResponse represents a stored annotation
type AnnotationResponse struct {
	ID          int    `json:"id"`
	JobID       string `json:"job_id"`
	PacketIndex int    `json:"packet_index"`
	Note        string `json:"note"`
	CreatedAt   string `json:"created_at"`
	Author      string `json:"author,omitempty"`
}

// PostAnnotation stores a note for a specific packet
// POST /api/annotations/:jobID
func (h *ExportPCAPHandlers) PostAnnotation(c *gin.Context) {
	jobID := c.Param("jobID")

	var req AnnotationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// Verify job exists
	if _, err := h.packetHandlers.store.GetJob(jobID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	// Store annotation in a JSON file alongside results
	annotationsDir := filepath.Join(h.packetHandlers.store.GetDataDir(), "annotations")
	if err := os.MkdirAll(annotationsDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create annotations directory"})
		return
	}

	annotationFile := filepath.Join(annotationsDir, jobID+".json")

	// Load existing annotations
	annotations := loadAnnotations(annotationFile)

	// Add new annotation
	author := ""
	if sub, exists := c.Get("user_sub"); exists {
		author = sub.(string)
	}

	ann := AnnotationResponse{
		ID:          len(annotations) + 1,
		JobID:       jobID,
		PacketIndex: req.PacketIndex,
		Note:        req.Note,
		CreatedAt:   time.Now().Format(time.RFC3339),
		Author:      author,
	}
	annotations = append(annotations, ann)

	// Save
	if err := saveAnnotations(annotationFile, annotations); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save annotation"})
		return
	}

	c.JSON(http.StatusCreated, ann)
}

// GetAnnotations returns all annotations for a job
// GET /api/annotations/:jobID
func (h *ExportPCAPHandlers) GetAnnotations(c *gin.Context) {
	jobID := c.Param("jobID")

	annotationFile := filepath.Join(h.packetHandlers.store.GetDataDir(), "annotations", jobID+".json")
	annotations := loadAnnotations(annotationFile)

	c.JSON(http.StatusOK, gin.H{
		"annotations": annotations,
		"total":       len(annotations),
	})
}

// DeleteAnnotation deletes a specific annotation
// DELETE /api/annotations/:jobID/:annotationID
func (h *ExportPCAPHandlers) DeleteAnnotation(c *gin.Context) {
	jobID := c.Param("jobID")
	annIDStr := c.Param("annotationID")
	annID, err := strconv.Atoi(annIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid annotation ID"})
		return
	}

	annotationFile := filepath.Join(h.packetHandlers.store.GetDataDir(), "annotations", jobID+".json")
	annotations := loadAnnotations(annotationFile)

	// Find and remove
	found := false
	filtered := make([]AnnotationResponse, 0, len(annotations))
	for _, a := range annotations {
		if a.ID == annID {
			found = true
			continue
		}
		filtered = append(filtered, a)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Annotation not found"})
		return
	}

	if err := saveAnnotations(annotationFile, filtered); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save annotations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// ─── Annotation file helpers ─────────────────────────────────────

func loadAnnotations(path string) []AnnotationResponse {
	data, err := os.ReadFile(path)
	if err != nil {
		return []AnnotationResponse{}
	}

	var annotations []AnnotationResponse
	if err := jsonUnmarshalAnnotations(data, &annotations); err != nil {
		return []AnnotationResponse{}
	}
	return annotations
}

func saveAnnotations(path string, annotations []AnnotationResponse) error {
	data, err := jsonMarshalIndent(annotations)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func jsonMarshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func jsonUnmarshalAnnotations(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
