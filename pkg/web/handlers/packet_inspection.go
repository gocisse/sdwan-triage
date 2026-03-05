package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/analyzer"
	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
	"github.com/google/gopacket"
)

// PacketInspectionHandlers provides endpoints for packet inspection
type PacketInspectionHandlers struct {
	store       *storage.Storage
	packetStore *models.PacketStore
	loadedJobID string // Track which job's packets are loaded
}

// NewPacketInspectionHandlers creates new packet inspection handlers
func NewPacketInspectionHandlers(store *storage.Storage) *PacketInspectionHandlers {
	return &PacketInspectionHandlers{
		store:       store,
		packetStore: models.NewPacketStore(10000, 50*1024*1024), // 10K packets, 50MB max
	}
}

// GetPacketStore returns the packet store for external use
func (h *PacketInspectionHandlers) GetPacketStore() *models.PacketStore {
	return h.packetStore
}

// StreamResponse represents the response for a stream extraction request
type StreamResponse struct {
	StreamID        string              `json:"stream_id"`
	SrcIP           string              `json:"src_ip"`
	SrcPort         uint16              `json:"src_port"`
	DstIP           string              `json:"dst_ip"`
	DstPort         uint16              `json:"dst_port"`
	Protocol        string              `json:"protocol"`
	Application     string              `json:"application"`
	PacketCount     int                 `json:"packet_count"`
	TotalBytes      int64               `json:"total_bytes"`
	ClientData      []StreamSegmentView `json:"client_data"` // Client → Server
	ServerData      []StreamSegmentView `json:"server_data"` // Server → Client
	Packets         []PacketSummary     `json:"packets"`     // List of packet indices
	WiresharkFilter string              `json:"wireshark_filter"`
}

// StreamSegmentView represents a segment in the stream
type StreamSegmentView struct {
	PacketIndex int    `json:"packet_index"`
	Timestamp   string `json:"timestamp"`
	Length      int    `json:"length"`
	DataHex     string `json:"data_hex,omitempty"`
	DataASCII   string `json:"data_ascii,omitempty"`
	Summary     string `json:"summary"`
}

// PacketSummary represents a minimal packet view
type PacketSummary struct {
	Index     int    `json:"index"`
	Timestamp string `json:"timestamp"`
	Length    int    `json:"length"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol"`
	Summary   string `json:"summary"`
}

// PacketDetailResponse represents a full packet detail with hex dump
type PacketDetailResponse struct {
	Index           int               `json:"index"`
	Timestamp       string            `json:"timestamp"`
	Length          int               `json:"length"`
	CapLen          int               `json:"cap_len"`
	RawHex          string            `json:"raw_hex"`   // Full hex dump
	RawASCII        string            `json:"raw_ascii"` // ASCII representation
	StreamID        string            `json:"stream_id"`
	SrcIP           string            `json:"src_ip"`
	DstIP           string            `json:"dst_ip"`
	SrcPort         uint16            `json:"src_port,omitempty"`
	DstPort         uint16            `json:"dst_port,omitempty"`
	Protocol        string            `json:"protocol"`
	Layers          []LayerDetailView `json:"layers"` // Protocol layers
	WiresharkFilter string            `json:"wireshark_filter"`
}

// LayerDetailView represents a protocol layer for display
type LayerDetailView struct {
	Name       string            `json:"name"`
	Summary    string            `json:"summary"`
	Fields     map[string]string `json:"fields,omitempty"`
	Flags      map[string]string `json:"flags,omitempty"`
	RawHex     string            `json:"raw_hex,omitempty"`
	PayloadHex string            `json:"payload_hex,omitempty"`
}

// ensurePacketsLoaded loads packets for a job if not already loaded.
// Returns the job or writes an error response and returns nil.
func (h *PacketInspectionHandlers) ensurePacketsLoaded(c *gin.Context, jobID string) *storage.AnalysisJob {
	job, err := h.store.GetJob(jobID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Analysis job not found"})
		return nil
	}
	if job.Status != storage.StatusCompleted {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Analysis not completed"})
		return nil
	}
	// Reload if different job or empty store
	if h.loadedJobID != jobID || h.packetStore.GetPacketCount() == 0 {
		h.packetStore.Clear()
		if err := h.loadPacketsFromPCAP(job.FilePath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load packets: " + err.Error()})
			return nil
		}
		h.loadedJobID = jobID
	}
	return job
}

// GetStream returns the reassembled stream data
// GET /api/stream/:jobID/*streamID
func (h *PacketInspectionHandlers) GetStream(c *gin.Context) {
	jobID := c.Param("jobID")
	streamID := c.Param("streamID")

	// Gin wildcard params include a leading "/" — strip it
	streamID = strings.TrimPrefix(streamID, "/")

	if h.ensurePacketsLoaded(c, jobID) == nil {
		return
	}

	// Try exact match first
	packets := h.packetStore.GetPacketsByStream(streamID)

	// If not found, try the normalized (canonical) form where the lower
	// tuple comes first, since the frontend may send src->dst while the
	// backend stored dst->src.
	if len(packets) == 0 {
		normalized := normalizeStreamKey(streamID)
		if normalized != streamID {
			packets = h.packetStore.GetPacketsByStream(normalized)
			if len(packets) > 0 {
				streamID = normalized
			}
		}
	}

	if len(packets) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Stream not found"})
		return
	}

	// Build response
	response := h.buildStreamResponse(streamID, packets)
	c.JSON(http.StatusOK, response)
}

// GetPacket returns detailed packet information with hex dump
// GET /api/packet/:jobID/:packetIndex
func (h *PacketInspectionHandlers) GetPacket(c *gin.Context) {
	jobID := c.Param("jobID")
	packetIndexStr := c.Param("packetIndex")

	var packetIndex int
	if _, err := fmt.Sscanf(packetIndexStr, "%d", &packetIndex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid packet index"})
		return
	}

	if h.ensurePacketsLoaded(c, jobID) == nil {
		return
	}

	// Get packet
	packet, err := h.packetStore.GetPacket(packetIndex)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Build response
	response := h.buildPacketResponse(packet)
	c.JSON(http.StatusOK, response)
}

// ListPackets returns a paginated list of packets
// GET /api/packets/:jobID
func (h *PacketInspectionHandlers) ListPackets(c *gin.Context) {
	jobID := c.Param("jobID")

	if h.ensurePacketsLoaded(c, jobID) == nil {
		return
	}

	// Get pagination params
	offset := 0
	limit := 100
	if o := c.Query("offset"); o != "" {
		fmt.Sscanf(o, "%d", &offset)
	}
	if l := c.Query("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
		if limit > 500 {
			limit = 500
		}
	}

	// Filter by stream if provided
	streamFilter := c.Query("stream")

	// Build packet list — iterate all packets safely
	allPackets := h.packetStore.GetAllPackets()
	var summaries []PacketSummary
	skipped := 0
	for _, packet := range allPackets {
		if streamFilter != "" && packet.StreamID != streamFilter {
			continue
		}
		// Apply offset
		if skipped < offset {
			skipped++
			continue
		}
		if len(summaries) >= limit {
			break
		}

		summary := PacketSummary{
			Index:     packet.Index,
			Timestamp: packet.Timestamp.Format("15:04:05.000000"),
			Length:    packet.Length,
			SrcIP:     packet.SrcIP,
			DstIP:     packet.DstIP,
			SrcPort:   packet.SrcPort,
			DstPort:   packet.DstPort,
			Protocol:  packet.Protocol,
		}

		// Build summary
		if packet.IsTCP {
			summary.Summary = fmt.Sprintf("%s:%d → %s:%d TCP", packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
			if packet.IsHTTP {
				summary.Summary += " (HTTP)"
			} else if packet.IsTLS {
				summary.Summary += " (TLS)"
			}
		} else if packet.IsUDP {
			summary.Summary = fmt.Sprintf("%s:%d → %s:%d UDP", packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort)
			if packet.IsDNS {
				summary.Summary += " (DNS)"
			}
		} else if packet.IsICMP {
			summary.Summary = fmt.Sprintf("%s → %s ICMP", packet.SrcIP, packet.DstIP)
		} else {
			summary.Summary = fmt.Sprintf("%s → %s %s", packet.SrcIP, packet.DstIP, packet.Protocol)
		}

		summaries = append(summaries, summary)
	}

	c.JSON(http.StatusOK, gin.H{
		"packets": summaries,
		"total":   h.packetStore.GetPacketCount(),
		"offset":  offset,
		"limit":   limit,
	})
}

// ListStreams returns all streams in the PCAP
// GET /api/streams/:jobID
func (h *PacketInspectionHandlers) ListStreams(c *gin.Context) {
	jobID := c.Param("jobID")

	if h.ensurePacketsLoaded(c, jobID) == nil {
		return
	}

	// Aggregate streams — iterate all packets safely
	allPackets := h.packetStore.GetAllPackets()
	streamMap := make(map[string]*StreamInfo)
	for _, packet := range allPackets {
		if packet.StreamID == "" {
			continue
		}

		info, exists := streamMap[packet.StreamID]
		if !exists {
			info = &StreamInfo{
				StreamID:    packet.StreamID,
				SrcIP:       packet.SrcIP,
				SrcPort:     packet.SrcPort,
				DstIP:       packet.DstIP,
				DstPort:     packet.DstPort,
				Protocol:    packet.Protocol,
				PacketCount: 0,
				TotalBytes:  0,
			}
			streamMap[packet.StreamID] = info
		}
		info.PacketCount++
		info.TotalBytes += int64(packet.Length)

		// Detect application
		if packet.IsHTTP {
			info.Application = "HTTP"
		} else if packet.IsTLS {
			info.Application = "TLS"
		} else if packet.IsDNS {
			info.Application = "DNS"
		}
	}

	// Convert to sorted list
	streams := make([]*StreamInfo, 0, len(streamMap))
	for _, info := range streamMap {
		streams = append(streams, info)
	}

	// Sort by packet count descending
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].PacketCount > streams[j].PacketCount
	})

	c.JSON(http.StatusOK, gin.H{
		"streams": streams,
		"total":   len(streams),
	})
}

// StreamInfo represents minimal stream information
type StreamInfo struct {
	StreamID    string `json:"stream_id"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    string `json:"protocol"`
	Application string `json:"application"`
	PacketCount int    `json:"packet_count"`
	TotalBytes  int64  `json:"total_bytes"`
}

// loadPacketsFromPCAP loads packets from a PCAP file into the store
func (h *PacketInspectionHandlers) loadPacketsFromPCAP(filePath string) error {
	capHandle, err := analyzer.OpenCapture(filePath)
	if err != nil {
		return err
	}
	defer capHandle.Close()
	reader := capHandle.Reader

	index := 0
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			break // EOF or error
		}

		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.Default)
		if packet == nil {
			continue
		}

		if packet.Metadata() != nil {
			packet.Metadata().Timestamp = ci.Timestamp
			packet.Metadata().CaptureLength = ci.CaptureLength
			packet.Metadata().Length = ci.Length
		}

		h.packetStore.AddPacket(packet, index)
		index++
	}

	return nil
}

// buildStreamResponse creates a StreamResponse from packets
func (h *PacketInspectionHandlers) buildStreamResponse(streamID string, packets []*models.RawPacket) *StreamResponse {
	if len(packets) == 0 {
		return nil
	}

	// Determine protocol
	protocol := "TCP"
	if strings.HasSuffix(streamID, "/UDP") {
		protocol = "UDP"
	}

	response := &StreamResponse{
		StreamID:    streamID,
		Protocol:    protocol,
		PacketCount: len(packets),
		ClientData:  make([]StreamSegmentView, 0),
		ServerData:  make([]StreamSegmentView, 0),
		Packets:     make([]PacketSummary, 0),
	}

	// Use first packet to set endpoints and generate Wireshark filter
	p := packets[0]
	response.SrcIP = p.SrcIP
	response.SrcPort = p.SrcPort
	response.DstIP = p.DstIP
	response.DstPort = p.DstPort
	if protocol == "TCP" {
		response.WiresharkFilter = fmt.Sprintf(
			"(ip.addr == %s && ip.addr == %s) && (tcp.port == %d && tcp.port == %d)",
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort)
	} else {
		response.WiresharkFilter = fmt.Sprintf(
			"(ip.addr == %s && ip.addr == %s) && (udp.port == %d && udp.port == %d)",
			p.SrcIP, p.DstIP, p.SrcPort, p.DstPort)
	}

	// Sort packets by timestamp
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].Timestamp.Before(packets[j].Timestamp)
	})

	// Process each packet
	for _, p := range packets {
		response.TotalBytes += int64(p.Length)

		summary := PacketSummary{
			Index:     p.Index,
			Timestamp: p.Timestamp.Format("15:04:05.000000"),
			Length:    p.Length,
			SrcIP:     p.SrcIP,
			DstIP:     p.DstIP,
			SrcPort:   p.SrcPort,
			DstPort:   p.DstPort,
			Protocol:  p.Protocol,
		}
		response.Packets = append(response.Packets, summary)

		// Determine direction and add to appropriate list
		if p.SrcIP == response.SrcIP && p.SrcPort == response.SrcPort {
			// Client → Server
			seg := StreamSegmentView{
				PacketIndex: p.Index,
				Timestamp:   p.Timestamp.Format("15:04:05.000000"),
				Length:      p.Length,
				Summary:     fmt.Sprintf("→ %s:%d (%d bytes)", p.DstIP, p.DstPort, p.Length),
			}
			if p.TransportLayer != nil && p.TransportLayer.PayloadHex != "" {
				seg.DataHex = p.TransportLayer.PayloadHex
			}
			if p.ApplicationLayer != nil {
				seg.Summary = fmt.Sprintf("→ %s (%s)", p.DstIP, p.ApplicationLayer.Name)
			}
			response.ClientData = append(response.ClientData, seg)
		} else {
			// Server → Client
			seg := StreamSegmentView{
				PacketIndex: p.Index,
				Timestamp:   p.Timestamp.Format("15:04:05.000000"),
				Length:      p.Length,
				Summary:     fmt.Sprintf("← %s:%d (%d bytes)", p.SrcIP, p.SrcPort, p.Length),
			}
			if p.TransportLayer != nil && p.TransportLayer.PayloadHex != "" {
				seg.DataHex = p.TransportLayer.PayloadHex
			}
			if p.ApplicationLayer != nil {
				seg.Summary = fmt.Sprintf("← %s (%s)", p.SrcIP, p.ApplicationLayer.Name)
			}
			response.ServerData = append(response.ServerData, seg)
		}

		// Detect application
		if p.IsHTTP {
			response.Application = "HTTP"
		} else if p.IsTLS {
			response.Application = "TLS"
		} else if p.IsDNS {
			response.Application = "DNS"
		}
	}

	return response
}

// buildPacketResponse creates a PacketDetailResponse from a RawPacket
func (h *PacketInspectionHandlers) buildPacketResponse(p *models.RawPacket) *PacketDetailResponse {
	response := &PacketDetailResponse{
		Index:     p.Index,
		Timestamp: p.Timestamp.Format("15:04:05.000000"),
		Length:    p.Length,
		CapLen:    p.CapLen,
		RawHex:    p.RawHex,
		RawASCII:  formatASCII(p.RawData),
		StreamID:  p.StreamID,
		SrcIP:     p.SrcIP,
		DstIP:     p.DstIP,
		SrcPort:   p.SrcPort,
		DstPort:   p.DstPort,
		Protocol:  p.Protocol,
		Layers:    make([]LayerDetailView, 0),
	}

	// Build Wireshark filter
	if p.IsTCP {
		response.WiresharkFilter = fmt.Sprintf("tcp.port == %d || tcp.port == %d", p.SrcPort, p.DstPort)
	} else if p.IsUDP {
		response.WiresharkFilter = fmt.Sprintf("udp.port == %d || udp.port == %d", p.SrcPort, p.DstPort)
	} else if p.IsICMP {
		response.WiresharkFilter = "icmp"
	}

	// Add layers
	if p.LinkLayer != nil {
		response.Layers = append(response.Layers, LayerDetailView{
			Name:    p.LinkLayer.Name,
			Summary: p.LinkLayer.Summary,
			Fields:  p.LinkLayer.Fields,
		})
	}

	if p.NetworkLayer != nil {
		response.Layers = append(response.Layers, LayerDetailView{
			Name:    p.NetworkLayer.Name,
			Summary: p.NetworkLayer.Summary,
			Fields:  p.NetworkLayer.Fields,
			Flags:   p.NetworkLayer.Flags,
		})
	}

	if p.TransportLayer != nil {
		response.Layers = append(response.Layers, LayerDetailView{
			Name:       p.TransportLayer.Name,
			Summary:    p.TransportLayer.Summary,
			Fields:     p.TransportLayer.Fields,
			Flags:      p.TransportLayer.Flags,
			PayloadHex: p.TransportLayer.PayloadHex,
		})
	}

	if p.ApplicationLayer != nil {
		response.Layers = append(response.Layers, LayerDetailView{
			Name:    p.ApplicationLayer.Name,
			Summary: p.ApplicationLayer.Summary,
			RawHex:  p.ApplicationLayer.RawHex,
		})
	}

	return response
}

// normalizeStreamKey takes a stream key like "A:P->B:Q/PROTO" and returns the
// canonical form where the lexicographically lower endpoint comes first.
// This matches the normalizeStreamID logic in models/packet_store.go.
func normalizeStreamKey(key string) string {
	// Split off protocol suffix: "A:P->B:Q/TCP" → ("A:P->B:Q", "TCP")
	slashIdx := strings.LastIndex(key, "/")
	if slashIdx < 0 {
		return key
	}
	proto := key[slashIdx+1:]
	body := key[:slashIdx]

	// Split endpoints: "A:P->B:Q" → ("A:P", "B:Q")
	parts := strings.SplitN(body, "->", 2)
	if len(parts) != 2 {
		return key
	}
	src, dst := parts[0], parts[1]

	// Canonical order: lower tuple first
	if src < dst {
		return fmt.Sprintf("%s->%s/%s", src, dst, proto)
	}
	return fmt.Sprintf("%s->%s/%s", dst, src, proto)
}

// formatASCII converts bytes to ASCII with non-printables as dots
func formatASCII(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			result.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			result.WriteByte(b)
		} else {
			result.WriteByte('.')
		}
	}
	return result.String()
}

// SavePacketStoreToJob saves packet store data to the job's results directory
func (h *PacketInspectionHandlers) SavePacketStoreToJob(jobID string) error {
	resultsDir := filepath.Join(h.store.GetResultsDir(), jobID)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return err
	}

	// Save packet index
	indexPath := filepath.Join(resultsDir, "packet_index.json")
	data, err := json.MarshalIndent(h.packetStore.GetStreamIDs(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(indexPath, data, 0644)
}
