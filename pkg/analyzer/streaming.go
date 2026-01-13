package analyzer

import (
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/gocisse/sdwan-triage/pkg/models"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// StreamingProcessor handles large PCAP files with memory-efficient streaming
type StreamingProcessor struct {
	*Processor
	batchSize   int
	maxMemoryMB int
}

// NewStreamingProcessor creates a processor optimized for large files
func NewStreamingProcessor(qosEnabled bool, verbose bool) *StreamingProcessor {
	return &StreamingProcessor{
		Processor:   NewProcessorWithOptions(qosEnabled, verbose),
		batchSize:   1000,
		maxMemoryMB: 512,
	}
}

// SetBatchSize configures the number of packets to process before cleanup
func (sp *StreamingProcessor) SetBatchSize(size int) {
	if size > 0 {
		sp.batchSize = size
	}
}

// SetMaxMemory configures the memory threshold for GC triggers (in MB)
func (sp *StreamingProcessor) SetMaxMemory(mb int) {
	if mb > 0 {
		sp.maxMemoryMB = mb
	}
}

// ProcessStreaming processes PCAP with memory optimization for large files
func (sp *StreamingProcessor) ProcessStreaming(reader *pcapgo.Reader, state *models.AnalysisState, report *models.TriageReport, filter *models.Filter) error {
	packetCount := 0
	batchCount := 0
	startTime := time.Now()
	lastGC := time.Now()

	sp.logDebug("Starting streaming processing (batch size: %d, max memory: %d MB)", sp.batchSize, sp.maxMemoryMB)

	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			sp.logWarning("Error reading packet %d: %v", packetCount+1, err)
			sp.errorCount++
			continue
		}

		// Decode packet with lazy decoding for better performance
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})

		if packet == nil {
			sp.skippedPackets++
			continue
		}

		// Process packet through all analyzers (using embedded Processor)
		sp.Processor.analyzePacket(packet, state, report)

		packetCount++
		batchCount++

		// Periodic cleanup and progress reporting
		if batchCount >= sp.batchSize {
			sp.performBatchCleanup(state, packetCount, startTime, &lastGC)
			batchCount = 0
		}
	}

	// Final cleanup
	sp.performFinalCleanup(state)

	elapsed := time.Since(startTime)
	sp.logDebug("Streaming processing complete: %d packets in %v", packetCount, elapsed)

	return nil
}

// performBatchCleanup performs periodic memory cleanup
func (sp *StreamingProcessor) performBatchCleanup(state *models.AnalysisState, packetCount int, startTime time.Time, lastGC *time.Time) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memoryMB := m.Alloc / 1024 / 1024

	if memoryMB > uint64(sp.maxMemoryMB) && time.Since(*lastGC) > 5*time.Second {
		sp.logDebug("Memory threshold exceeded (%d MB), triggering GC", memoryMB)
		runtime.GC()
		*lastGC = time.Now()
	}

	if sp.verbose {
		elapsed := time.Since(startTime)
		pps := float64(packetCount) / elapsed.Seconds()
		fmt.Printf("\rProcessed %d packets (%.0f pps, %d MB)...", packetCount, pps, memoryMB)
	}
}

// performFinalCleanup cleans up state maps to free memory
func (sp *StreamingProcessor) performFinalCleanup(state *models.AnalysisState) {
	sp.cleanupOldFlows(state)
	runtime.GC()
	sp.logDebug("Final cleanup complete")
}

// cleanupOldFlows removes stale flow entries to free memory
func (sp *StreamingProcessor) cleanupOldFlows(state *models.AnalysisState) {
	// Clean up TCP flows with no data
	for key, flow := range state.TCPFlows {
		if flow.TotalBytes == 0 {
			delete(state.TCPFlows, key)
		}
	}

	// Clean up old sent times to prevent memory bloat
	for _, flow := range state.TCPFlows {
		if len(flow.SentTimes) > 1000 {
			flow.SentTimes = make(map[uint32]time.Time)
		}
	}

	sp.logDebug("Cleaned up flow state (TCP flows: %d)", len(state.TCPFlows))
}
