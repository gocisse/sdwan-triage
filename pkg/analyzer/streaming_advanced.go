package analyzer

import (
	"context"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// AdvancedStreamingConfig configures the streaming processor
type AdvancedStreamingConfig struct {
	// Memory limits
	MaxMemoryMB        int64 // Maximum memory usage in MB (default: 512)
	MaxStreamsInMemory int   // Maximum concurrent streams (default: 10000)
	MaxBytesPerStream  int   // Maximum bytes per stream direction (default: 10KB)

	// Processing options
	WorkerCount int // Number of parallel workers (default: NumCPU)
	BatchSize   int // Packets per batch for processing (default: 1000)

	// Early termination
	HealthyStreamThreshold float64 // Skip detailed analysis if score > this (default: 90)

	// Eviction policy
	EvictionPolicy EvictionPolicy

	// Progress callback
	ProgressCallback func(processed, total uint64, memoryMB int64)
}

// EvictionPolicy determines how streams are evicted when memory is full
type EvictionPolicy int

const (
	EvictOldest   EvictionPolicy = iota // Evict oldest inactive streams
	EvictSmallest                       // Evict smallest streams first
	EvictHealthy                        // Evict healthy streams first (keep problematic ones)
)

// DefaultAdvancedStreamingConfig returns sensible defaults
func DefaultAdvancedStreamingConfig() AdvancedStreamingConfig {
	return AdvancedStreamingConfig{
		MaxMemoryMB:            512,
		MaxStreamsInMemory:     10000,
		MaxBytesPerStream:      10 * 1024,
		WorkerCount:            runtime.NumCPU(),
		BatchSize:              1000,
		HealthyStreamThreshold: 90.0,
		EvictionPolicy:         EvictHealthy,
	}
}

// AdvancedStreamingProcessor handles large PCAP files with constant memory usage
type AdvancedStreamingProcessor struct {
	config        AdvancedStreamingConfig
	classifier    *AdvancedClassifier
	healthScorer  *HealthScorer
	issueDetector *IssueDetector

	// Stream storage with eviction
	streams     map[string]*models.StreamData
	streamsMu   sync.RWMutex
	streamOrder []string // For LRU eviction

	// Statistics
	stats AdvancedStreamingStats

	// Worker pool
	packetChan chan gopacket.Packet
	resultChan chan *StreamResult
	workerWg   sync.WaitGroup

	// Memory tracking
	currentMemory int64
}

// AdvancedStreamingStats tracks processing statistics
type AdvancedStreamingStats struct {
	PacketsProcessed uint64
	PacketsDropped   uint64
	StreamsCreated   uint64
	StreamsEvicted   uint64
	StreamsCompleted uint64
	BytesProcessed   uint64
	ProcessingTimeMs int64
	PeakMemoryMB     int64
	IssuesDetected   uint64
	HealthyStreams   uint64
	DegradedStreams  uint64
	CriticalStreams  uint64
}

// StreamResult contains analysis results for a stream
type StreamResult struct {
	Stream          *models.StreamData
	Classification  ServiceClassification
	HealthScore     HealthScore
	Issues          []DetectedIssue
	EarlyTerminated bool
}

// NewAdvancedStreamingProcessor creates a new streaming processor
func NewAdvancedStreamingProcessor(config AdvancedStreamingConfig) *AdvancedStreamingProcessor {
	if config.WorkerCount <= 0 {
		config.WorkerCount = runtime.NumCPU()
	}
	if config.MaxStreamsInMemory <= 0 {
		config.MaxStreamsInMemory = 10000
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 1000
	}

	return &AdvancedStreamingProcessor{
		config:        config,
		classifier:    NewAdvancedClassifier(),
		healthScorer:  NewHealthScorer(),
		issueDetector: NewIssueDetector(),
		streams:       make(map[string]*models.StreamData),
		streamOrder:   make([]string, 0, config.MaxStreamsInMemory),
		packetChan:    make(chan gopacket.Packet, config.BatchSize*2),
		resultChan:    make(chan *StreamResult, config.WorkerCount*2),
	}
}

// ProcessFile processes a PCAP file with streaming analysis
func (sp *AdvancedStreamingProcessor) ProcessFile(ctx context.Context, filename string) (*AdvancedStreamingReport, error) {
	startTime := time.Now()

	// Get file size for progress tracking
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	fileSize := fileInfo.Size()

	// Open PCAP file
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	handle, err := pcapgo.NewReader(file)
	if err != nil {
		return nil, err
	}

	// Start worker pool
	sp.startWorkers(ctx)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	var bytesRead int64
	lastProgress := time.Now()

	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			sp.stopWorkers()
			return nil, ctx.Err()
		default:
		}

		// Track progress
		if packet.Metadata() != nil {
			bytesRead += int64(packet.Metadata().CaptureLength)
		}

		// Process packet
		sp.processPacket(packet)
		atomic.AddUint64(&sp.stats.PacketsProcessed, 1)

		// Memory check and eviction
		if sp.shouldEvict() {
			sp.evictStreams()
		}

		// Progress callback
		if sp.config.ProgressCallback != nil && time.Since(lastProgress) > 500*time.Millisecond {
			sp.config.ProgressCallback(
				atomic.LoadUint64(&sp.stats.PacketsProcessed),
				uint64(fileSize),
				atomic.LoadInt64(&sp.currentMemory)/(1024*1024),
			)
			lastProgress = time.Now()
		}
	}

	// Finalize all streams
	sp.finalizeAllStreams()

	// Stop workers
	sp.stopWorkers()

	// Build report
	sp.stats.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	return sp.buildReport(), nil
}

// processPacket handles a single packet
func (sp *AdvancedStreamingProcessor) processPacket(packet gopacket.Packet) {
	// Extract flow key
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer == nil || transportLayer == nil {
		return
	}

	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var protocol string

	// Get IP addresses
	if ipv4, ok := networkLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6, ok := networkLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}

	// Get ports and protocol
	if tcp, ok := transportLayer.(*layers.TCP); ok {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = "TCP"
	} else if udp, ok := transportLayer.(*layers.UDP); ok {
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = "UDP"
	} else {
		return
	}

	// Create flow key (bidirectional)
	flowKey := createFlowKey(srcIP, srcPort, dstIP, dstPort, protocol)

	// Get or create stream
	sp.streamsMu.Lock()
	stream, exists := sp.streams[flowKey]
	if !exists {
		stream = &models.StreamData{
			FlowID:    flowKey,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Protocol:  protocol,
			FirstSeen: packet.Metadata().Timestamp,
			Segments:  make([]models.StreamSegment, 0),
		}
		sp.streams[flowKey] = stream
		sp.streamOrder = append(sp.streamOrder, flowKey)
		atomic.AddUint64(&sp.stats.StreamsCreated, 1)
	}
	sp.streamsMu.Unlock()

	// Update stream with packet data
	sp.updateStream(stream, packet, srcIP, srcPort)
}

// updateStream adds packet data to a stream
func (sp *AdvancedStreamingProcessor) updateStream(stream *models.StreamData, packet gopacket.Packet, srcIP string, srcPort uint16) {
	sp.streamsMu.Lock()
	defer sp.streamsMu.Unlock()

	// Determine direction
	direction := "client_to_server"
	if srcIP == stream.DstIP && srcPort == stream.DstPort {
		direction = "server_to_client"
	}

	// Get payload
	appLayer := packet.ApplicationLayer()
	var payload []byte
	if appLayer != nil {
		payload = appLayer.Payload()
	}

	// Check if we should add this segment (memory limit)
	if int(stream.TotalBytes)+len(payload) > sp.config.MaxBytesPerStream*2 {
		// Stream at capacity, just update stats
		stream.TotalBytes += uint64(len(payload))
		stream.PacketCount++
		stream.LastSeen = packet.Metadata().Timestamp
		return
	}

	// Create segment
	segment := models.StreamSegment{
		Direction: direction,
		Timestamp: packet.Metadata().Timestamp,
		Data:      payload,
		Length:    len(payload),
	}

	// Check for TCP flags
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.RST {
			segment.HasReset = true
		}
		segment.SeqNum = tcp.Seq
	}

	// Calculate gap from previous segment
	if len(stream.Segments) > 0 {
		lastSeg := stream.Segments[len(stream.Segments)-1]
		segment.GapFromPrev = packet.Metadata().Timestamp.Sub(lastSeg.Timestamp).Seconds()
	}

	stream.Segments = append(stream.Segments, segment)
	stream.TotalBytes += uint64(len(payload))
	stream.PacketCount++
	stream.LastSeen = packet.Metadata().Timestamp
	stream.Duration = stream.LastSeen.Sub(stream.FirstSeen).Seconds()

	// Update memory tracking
	atomic.AddInt64(&sp.currentMemory, int64(len(payload)+100)) // payload + overhead
}

// shouldEvict checks if we need to evict streams
func (sp *AdvancedStreamingProcessor) shouldEvict() bool {
	sp.streamsMu.RLock()
	streamCount := len(sp.streams)
	sp.streamsMu.RUnlock()

	memoryMB := atomic.LoadInt64(&sp.currentMemory) / (1024 * 1024)

	return streamCount >= sp.config.MaxStreamsInMemory || memoryMB >= sp.config.MaxMemoryMB
}

// evictStreams removes streams based on eviction policy
func (sp *AdvancedStreamingProcessor) evictStreams() {
	sp.streamsMu.Lock()
	defer sp.streamsMu.Unlock()

	// Evict 10% of streams
	evictCount := len(sp.streams) / 10
	if evictCount < 1 {
		evictCount = 1
	}

	switch sp.config.EvictionPolicy {
	case EvictOldest:
		sp.evictOldest(evictCount)
	case EvictSmallest:
		sp.evictSmallest(evictCount)
	case EvictHealthy:
		sp.evictHealthy(evictCount)
	}
}

// evictOldest removes the oldest streams
func (sp *AdvancedStreamingProcessor) evictOldest(count int) {
	for i := 0; i < count && len(sp.streamOrder) > 0; i++ {
		key := sp.streamOrder[0]
		sp.streamOrder = sp.streamOrder[1:]

		if stream, exists := sp.streams[key]; exists {
			atomic.AddInt64(&sp.currentMemory, -int64(stream.TotalBytes+100))
			delete(sp.streams, key)
			atomic.AddUint64(&sp.stats.StreamsEvicted, 1)
		}
	}
}

// evictSmallest removes the smallest streams
func (sp *AdvancedStreamingProcessor) evictSmallest(count int) {
	// Find smallest streams
	type streamSize struct {
		key  string
		size uint64
	}

	sizes := make([]streamSize, 0, len(sp.streams))
	for key, stream := range sp.streams {
		sizes = append(sizes, streamSize{key, stream.TotalBytes})
	}

	// Sort by size (bubble sort for simplicity)
	for i := 0; i < len(sizes); i++ {
		for j := i + 1; j < len(sizes); j++ {
			if sizes[i].size > sizes[j].size {
				sizes[i], sizes[j] = sizes[j], sizes[i]
			}
		}
	}

	// Evict smallest
	for i := 0; i < count && i < len(sizes); i++ {
		key := sizes[i].key
		if stream, exists := sp.streams[key]; exists {
			atomic.AddInt64(&sp.currentMemory, -int64(stream.TotalBytes+100))
			delete(sp.streams, key)
			atomic.AddUint64(&sp.stats.StreamsEvicted, 1)
		}
	}
}

// evictHealthy removes healthy streams first (keep problematic ones)
func (sp *AdvancedStreamingProcessor) evictHealthy(count int) {
	evicted := 0

	for key, stream := range sp.streams {
		if evicted >= count {
			break
		}

		// Quick health check
		score := sp.healthScorer.ScoreStream(stream)
		if score.Score >= sp.config.HealthyStreamThreshold {
			atomic.AddInt64(&sp.currentMemory, -int64(stream.TotalBytes+100))
			delete(sp.streams, key)
			atomic.AddUint64(&sp.stats.StreamsEvicted, 1)
			evicted++
		}
	}

	// If not enough healthy streams, evict oldest
	if evicted < count {
		sp.evictOldest(count - evicted)
	}
}

// startWorkers starts the worker pool
func (sp *AdvancedStreamingProcessor) startWorkers(ctx context.Context) {
	for i := 0; i < sp.config.WorkerCount; i++ {
		sp.workerWg.Add(1)
		go sp.worker(ctx)
	}
}

// stopWorkers stops the worker pool
func (sp *AdvancedStreamingProcessor) stopWorkers() {
	close(sp.packetChan)
	sp.workerWg.Wait()
	close(sp.resultChan)
}

// worker processes streams in parallel
func (sp *AdvancedStreamingProcessor) worker(ctx context.Context) {
	defer sp.workerWg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-sp.packetChan:
			if !ok {
				return
			}
			sp.processPacket(packet)
		}
	}
}

// finalizeAllStreams completes analysis on all streams
func (sp *AdvancedStreamingProcessor) finalizeAllStreams() {
	sp.streamsMu.RLock()
	streams := make([]*models.StreamData, 0, len(sp.streams))
	for _, stream := range sp.streams {
		streams = append(streams, stream)
	}
	sp.streamsMu.RUnlock()

	for _, stream := range streams {
		// Classify
		classification := sp.classifier.ClassifyStream(stream)

		// Score health
		healthScore := sp.healthScorer.ScoreStream(stream)

		// Early termination for healthy streams
		if healthScore.Score >= sp.config.HealthyStreamThreshold {
			atomic.AddUint64(&sp.stats.HealthyStreams, 1)
			continue
		}

		// Detect issues for non-healthy streams
		issues := sp.issueDetector.DetectIssues(stream)
		atomic.AddUint64(&sp.stats.IssuesDetected, uint64(len(issues)))

		// Track health distribution
		switch healthScore.Status {
		case HealthStatusDegraded:
			atomic.AddUint64(&sp.stats.DegradedStreams, 1)
		case HealthStatusCritical:
			atomic.AddUint64(&sp.stats.CriticalStreams, 1)
		}

		// Store classification in stream for later use
		stream.Application = string(classification.Category)
	}
}

// buildReport creates the final streaming report
func (sp *AdvancedStreamingProcessor) buildReport() *AdvancedStreamingReport {
	sp.streamsMu.RLock()
	defer sp.streamsMu.RUnlock()

	// Collect all streams
	streams := make([]*models.StreamData, 0, len(sp.streams))
	for _, stream := range sp.streams {
		streams = append(streams, stream)
	}

	// Sort by total bytes (largest first)
	for i := 0; i < len(streams); i++ {
		for j := i + 1; j < len(streams); j++ {
			if streams[i].TotalBytes < streams[j].TotalBytes {
				streams[i], streams[j] = streams[j], streams[i]
			}
		}
	}

	return &AdvancedStreamingReport{
		Streams: streams,
		Stats:   sp.stats,
	}
}

// AdvancedStreamingReport contains the final analysis results
type AdvancedStreamingReport struct {
	Streams []*models.StreamData
	Stats   AdvancedStreamingStats
}

// createFlowKey creates a bidirectional flow key
func createFlowKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string) string {
	// Normalize to ensure bidirectional matching
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	return srcIP + ":" + portToString(srcPort) + "-" + dstIP + ":" + portToString(dstPort) + "-" + protocol
}

func portToString(port uint16) string {
	if port == 0 {
		return "0"
	}
	s := ""
	for port > 0 {
		s = string(rune('0'+port%10)) + s
		port /= 10
	}
	return s
}

// GetStats returns current processing statistics
func (sp *AdvancedStreamingProcessor) GetStats() AdvancedStreamingStats {
	return AdvancedStreamingStats{
		PacketsProcessed: atomic.LoadUint64(&sp.stats.PacketsProcessed),
		PacketsDropped:   atomic.LoadUint64(&sp.stats.PacketsDropped),
		StreamsCreated:   atomic.LoadUint64(&sp.stats.StreamsCreated),
		StreamsEvicted:   atomic.LoadUint64(&sp.stats.StreamsEvicted),
		StreamsCompleted: atomic.LoadUint64(&sp.stats.StreamsCompleted),
		BytesProcessed:   atomic.LoadUint64(&sp.stats.BytesProcessed),
		ProcessingTimeMs: atomic.LoadInt64(&sp.stats.ProcessingTimeMs),
		PeakMemoryMB:     atomic.LoadInt64(&sp.stats.PeakMemoryMB),
		IssuesDetected:   atomic.LoadUint64(&sp.stats.IssuesDetected),
		HealthyStreams:   atomic.LoadUint64(&sp.stats.HealthyStreams),
		DegradedStreams:  atomic.LoadUint64(&sp.stats.DegradedStreams),
		CriticalStreams:  atomic.LoadUint64(&sp.stats.CriticalStreams),
	}
}

// ProcessReader processes a PCAP from an io.Reader (for streaming input)
func (sp *AdvancedStreamingProcessor) ProcessReader(ctx context.Context, reader io.Reader) (*AdvancedStreamingReport, error) {
	// Create temporary file for pcap library compatibility
	tmpFile, err := os.CreateTemp("", "sdwan-triage-*.pcap")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Copy reader to temp file
	if _, err := io.Copy(tmpFile, reader); err != nil {
		return nil, err
	}

	// Process the temp file
	return sp.ProcessFile(ctx, tmpFile.Name())
}
