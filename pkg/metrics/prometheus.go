package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector collects and exposes Prometheus-compatible metrics
type MetricsCollector struct {
	mu sync.RWMutex

	// Analysis metrics
	analysisTotal        uint64
	analysisSuccessful   uint64
	analysisFailed       uint64
	analysisLatencySum   int64
	analysisLatencyCount uint64

	// Stream metrics
	streamsProcessed uint64
	streamsHealthy   uint64
	streamsDegraded  uint64
	streamsCritical  uint64

	// Issue metrics
	issuesDetected   uint64
	issuesBySeverity map[string]uint64
	issuesByCategory map[string]uint64

	// Remediation metrics
	remediationsAttempted  uint64
	remediationsSuccessful uint64
	remediationsFailed     uint64

	// Performance metrics
	memoryUsageBytes int64
	goroutineCount   int64
	workerPoolActive int32
	workerPoolQueued int32

	// Service classification metrics
	classificationByService map[string]uint64

	// Vendor-specific metrics
	vendorIssues map[string]uint64

	// Custom labels
	labels map[string]string
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		issuesBySeverity:        make(map[string]uint64),
		issuesByCategory:        make(map[string]uint64),
		classificationByService: make(map[string]uint64),
		vendorIssues:            make(map[string]uint64),
		labels:                  make(map[string]string),
	}
}

// SetLabel sets a custom label for all metrics
func (mc *MetricsCollector) SetLabel(key, value string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.labels[key] = value
}

// RecordAnalysis records an analysis operation
func (mc *MetricsCollector) RecordAnalysis(success bool, latencyMs int64) {
	atomic.AddUint64(&mc.analysisTotal, 1)
	if success {
		atomic.AddUint64(&mc.analysisSuccessful, 1)
	} else {
		atomic.AddUint64(&mc.analysisFailed, 1)
	}
	atomic.AddInt64(&mc.analysisLatencySum, latencyMs)
	atomic.AddUint64(&mc.analysisLatencyCount, 1)
}

// RecordStream records a stream processing result
func (mc *MetricsCollector) RecordStream(healthStatus string) {
	atomic.AddUint64(&mc.streamsProcessed, 1)

	switch healthStatus {
	case "Healthy":
		atomic.AddUint64(&mc.streamsHealthy, 1)
	case "Degraded":
		atomic.AddUint64(&mc.streamsDegraded, 1)
	case "Critical":
		atomic.AddUint64(&mc.streamsCritical, 1)
	}
}

// RecordIssue records a detected issue
func (mc *MetricsCollector) RecordIssue(severity, category string) {
	atomic.AddUint64(&mc.issuesDetected, 1)

	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.issuesBySeverity[severity]++
	mc.issuesByCategory[category]++
}

// RecordRemediation records a remediation attempt
func (mc *MetricsCollector) RecordRemediation(success bool) {
	atomic.AddUint64(&mc.remediationsAttempted, 1)
	if success {
		atomic.AddUint64(&mc.remediationsSuccessful, 1)
	} else {
		atomic.AddUint64(&mc.remediationsFailed, 1)
	}
}

// RecordClassification records a service classification
func (mc *MetricsCollector) RecordClassification(service string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.classificationByService[service]++
}

// RecordVendorIssue records a vendor-specific issue
func (mc *MetricsCollector) RecordVendorIssue(vendor string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.vendorIssues[vendor]++
}

// UpdateMemoryUsage updates memory usage metric
func (mc *MetricsCollector) UpdateMemoryUsage(bytes int64) {
	atomic.StoreInt64(&mc.memoryUsageBytes, bytes)
}

// UpdateGoroutineCount updates goroutine count metric
func (mc *MetricsCollector) UpdateGoroutineCount(count int64) {
	atomic.StoreInt64(&mc.goroutineCount, count)
}

// UpdateWorkerPool updates worker pool metrics
func (mc *MetricsCollector) UpdateWorkerPool(active, queued int32) {
	atomic.StoreInt32(&mc.workerPoolActive, active)
	atomic.StoreInt32(&mc.workerPoolQueued, queued)
}

// PrometheusHandler returns an HTTP handler for Prometheus scraping
func (mc *MetricsCollector) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		mc.mu.RLock()
		defer mc.mu.RUnlock()

		// Build labels string
		labelStr := mc.buildLabels()

		// Analysis metrics
		fmt.Fprintf(w, "# HELP sdwan_analysis_total Total number of PCAP analyses\n")
		fmt.Fprintf(w, "# TYPE sdwan_analysis_total counter\n")
		fmt.Fprintf(w, "sdwan_analysis_total%s %d\n", labelStr, atomic.LoadUint64(&mc.analysisTotal))

		fmt.Fprintf(w, "# HELP sdwan_analysis_successful_total Successful analyses\n")
		fmt.Fprintf(w, "# TYPE sdwan_analysis_successful_total counter\n")
		fmt.Fprintf(w, "sdwan_analysis_successful_total%s %d\n", labelStr, atomic.LoadUint64(&mc.analysisSuccessful))

		fmt.Fprintf(w, "# HELP sdwan_analysis_failed_total Failed analyses\n")
		fmt.Fprintf(w, "# TYPE sdwan_analysis_failed_total counter\n")
		fmt.Fprintf(w, "sdwan_analysis_failed_total%s %d\n", labelStr, atomic.LoadUint64(&mc.analysisFailed))

		// Analysis latency
		latencyCount := atomic.LoadUint64(&mc.analysisLatencyCount)
		if latencyCount > 0 {
			avgLatency := float64(atomic.LoadInt64(&mc.analysisLatencySum)) / float64(latencyCount)
			fmt.Fprintf(w, "# HELP sdwan_analysis_latency_ms Average analysis latency in milliseconds\n")
			fmt.Fprintf(w, "# TYPE sdwan_analysis_latency_ms gauge\n")
			fmt.Fprintf(w, "sdwan_analysis_latency_ms%s %.2f\n", labelStr, avgLatency)
		}

		// Stream metrics
		fmt.Fprintf(w, "# HELP sdwan_streams_processed_total Total streams processed\n")
		fmt.Fprintf(w, "# TYPE sdwan_streams_processed_total counter\n")
		fmt.Fprintf(w, "sdwan_streams_processed_total%s %d\n", labelStr, atomic.LoadUint64(&mc.streamsProcessed))

		fmt.Fprintf(w, "# HELP sdwan_streams_by_health Streams by health status\n")
		fmt.Fprintf(w, "# TYPE sdwan_streams_by_health gauge\n")
		fmt.Fprintf(w, "sdwan_streams_by_health{status=\"healthy\"%s} %d\n", mc.appendLabels(), atomic.LoadUint64(&mc.streamsHealthy))
		fmt.Fprintf(w, "sdwan_streams_by_health{status=\"degraded\"%s} %d\n", mc.appendLabels(), atomic.LoadUint64(&mc.streamsDegraded))
		fmt.Fprintf(w, "sdwan_streams_by_health{status=\"critical\"%s} %d\n", mc.appendLabels(), atomic.LoadUint64(&mc.streamsCritical))

		// Issue metrics
		fmt.Fprintf(w, "# HELP sdwan_issues_detected_total Total issues detected\n")
		fmt.Fprintf(w, "# TYPE sdwan_issues_detected_total counter\n")
		fmt.Fprintf(w, "sdwan_issues_detected_total%s %d\n", labelStr, atomic.LoadUint64(&mc.issuesDetected))

		fmt.Fprintf(w, "# HELP sdwan_issues_by_severity Issues by severity level\n")
		fmt.Fprintf(w, "# TYPE sdwan_issues_by_severity gauge\n")
		for severity, count := range mc.issuesBySeverity {
			fmt.Fprintf(w, "sdwan_issues_by_severity{severity=\"%s\"%s} %d\n", severity, mc.appendLabels(), count)
		}

		fmt.Fprintf(w, "# HELP sdwan_issues_by_category Issues by category\n")
		fmt.Fprintf(w, "# TYPE sdwan_issues_by_category gauge\n")
		for category, count := range mc.issuesByCategory {
			fmt.Fprintf(w, "sdwan_issues_by_category{category=\"%s\"%s} %d\n", category, mc.appendLabels(), count)
		}

		// Remediation metrics
		fmt.Fprintf(w, "# HELP sdwan_remediations_attempted_total Total remediation attempts\n")
		fmt.Fprintf(w, "# TYPE sdwan_remediations_attempted_total counter\n")
		fmt.Fprintf(w, "sdwan_remediations_attempted_total%s %d\n", labelStr, atomic.LoadUint64(&mc.remediationsAttempted))

		fmt.Fprintf(w, "# HELP sdwan_remediations_successful_total Successful remediations\n")
		fmt.Fprintf(w, "# TYPE sdwan_remediations_successful_total counter\n")
		fmt.Fprintf(w, "sdwan_remediations_successful_total%s %d\n", labelStr, atomic.LoadUint64(&mc.remediationsSuccessful))

		// Success rate
		attempted := atomic.LoadUint64(&mc.remediationsAttempted)
		if attempted > 0 {
			successRate := float64(atomic.LoadUint64(&mc.remediationsSuccessful)) / float64(attempted)
			fmt.Fprintf(w, "# HELP sdwan_remediation_success_rate Remediation success rate\n")
			fmt.Fprintf(w, "# TYPE sdwan_remediation_success_rate gauge\n")
			fmt.Fprintf(w, "sdwan_remediation_success_rate%s %.4f\n", labelStr, successRate)
		}

		// Classification metrics
		fmt.Fprintf(w, "# HELP sdwan_classification_by_service Streams classified by service\n")
		fmt.Fprintf(w, "# TYPE sdwan_classification_by_service gauge\n")
		for service, count := range mc.classificationByService {
			fmt.Fprintf(w, "sdwan_classification_by_service{service=\"%s\"%s} %d\n", service, mc.appendLabels(), count)
		}

		// Vendor-specific metrics
		fmt.Fprintf(w, "# HELP sdwan_vendor_issues Issues by SD-WAN vendor\n")
		fmt.Fprintf(w, "# TYPE sdwan_vendor_issues gauge\n")
		for vendor, count := range mc.vendorIssues {
			fmt.Fprintf(w, "sdwan_vendor_issues{vendor=\"%s\"%s} %d\n", vendor, mc.appendLabels(), count)
		}

		// Performance metrics
		fmt.Fprintf(w, "# HELP sdwan_memory_usage_bytes Current memory usage in bytes\n")
		fmt.Fprintf(w, "# TYPE sdwan_memory_usage_bytes gauge\n")
		fmt.Fprintf(w, "sdwan_memory_usage_bytes%s %d\n", labelStr, atomic.LoadInt64(&mc.memoryUsageBytes))

		fmt.Fprintf(w, "# HELP sdwan_goroutine_count Current number of goroutines\n")
		fmt.Fprintf(w, "# TYPE sdwan_goroutine_count gauge\n")
		fmt.Fprintf(w, "sdwan_goroutine_count%s %d\n", labelStr, atomic.LoadInt64(&mc.goroutineCount))

		fmt.Fprintf(w, "# HELP sdwan_worker_pool_active Active workers in pool\n")
		fmt.Fprintf(w, "# TYPE sdwan_worker_pool_active gauge\n")
		fmt.Fprintf(w, "sdwan_worker_pool_active%s %d\n", labelStr, atomic.LoadInt32(&mc.workerPoolActive))

		fmt.Fprintf(w, "# HELP sdwan_worker_pool_queued Queued tasks in worker pool\n")
		fmt.Fprintf(w, "# TYPE sdwan_worker_pool_queued gauge\n")
		fmt.Fprintf(w, "sdwan_worker_pool_queued%s %d\n", labelStr, atomic.LoadInt32(&mc.workerPoolQueued))
	}
}

// buildLabels builds the labels string for metrics
func (mc *MetricsCollector) buildLabels() string {
	if len(mc.labels) == 0 {
		return ""
	}

	result := "{"
	first := true
	for k, v := range mc.labels {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("%s=\"%s\"", k, v)
		first = false
	}
	result += "}"
	return result
}

// appendLabels returns labels to append to existing labels
func (mc *MetricsCollector) appendLabels() string {
	if len(mc.labels) == 0 {
		return ""
	}

	result := ""
	for k, v := range mc.labels {
		result += fmt.Sprintf(",%s=\"%s\"", k, v)
	}
	return result
}

// Reset resets all metrics
func (mc *MetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	atomic.StoreUint64(&mc.analysisTotal, 0)
	atomic.StoreUint64(&mc.analysisSuccessful, 0)
	atomic.StoreUint64(&mc.analysisFailed, 0)
	atomic.StoreInt64(&mc.analysisLatencySum, 0)
	atomic.StoreUint64(&mc.analysisLatencyCount, 0)
	atomic.StoreUint64(&mc.streamsProcessed, 0)
	atomic.StoreUint64(&mc.streamsHealthy, 0)
	atomic.StoreUint64(&mc.streamsDegraded, 0)
	atomic.StoreUint64(&mc.streamsCritical, 0)
	atomic.StoreUint64(&mc.issuesDetected, 0)
	atomic.StoreUint64(&mc.remediationsAttempted, 0)
	atomic.StoreUint64(&mc.remediationsSuccessful, 0)
	atomic.StoreUint64(&mc.remediationsFailed, 0)

	mc.issuesBySeverity = make(map[string]uint64)
	mc.issuesByCategory = make(map[string]uint64)
	mc.classificationByService = make(map[string]uint64)
	mc.vendorIssues = make(map[string]uint64)
}

// MetricsServer runs an HTTP server for Prometheus scraping
type MetricsServer struct {
	collector *MetricsCollector
	server    *http.Server
}

// NewMetricsServer creates a new metrics server
func NewMetricsServer(collector *MetricsCollector, addr string) *MetricsServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", collector.PrometheusHandler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	return &MetricsServer{
		collector: collector,
		server: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Start starts the metrics server
func (ms *MetricsServer) Start() error {
	return ms.server.ListenAndServe()
}

// Stop stops the metrics server
func (ms *MetricsServer) Stop() error {
	return ms.server.Close()
}

// Global metrics collector instance
var globalCollector *MetricsCollector
var globalCollectorOnce sync.Once

// GetGlobalCollector returns the global metrics collector
func GetGlobalCollector() *MetricsCollector {
	globalCollectorOnce.Do(func() {
		globalCollector = NewMetricsCollector()
	})
	return globalCollector
}
