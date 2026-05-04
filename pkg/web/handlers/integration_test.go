package handlers

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
)

// ─── Minimal PCAP Fixture ──────────────────────────────────────────
// buildMinimalPCAP constructs a valid libpcap file with a single TCP SYN
// packet (Ethernet II → IPv4 → TCP). This avoids depending on external
// fixture files and is ~100 bytes total.
func buildMinimalPCAP() []byte {
	var buf bytes.Buffer

	// ── Global Header (24 bytes) ──
	binary.Write(&buf, binary.LittleEndian, uint32(0xa1b2c3d4)) // magic
	binary.Write(&buf, binary.LittleEndian, uint16(2))          // major
	binary.Write(&buf, binary.LittleEndian, uint16(4))          // minor
	binary.Write(&buf, binary.LittleEndian, int32(0))           // thiszone
	binary.Write(&buf, binary.LittleEndian, uint32(0))          // sigfigs
	binary.Write(&buf, binary.LittleEndian, uint32(65535))      // snaplen
	binary.Write(&buf, binary.LittleEndian, uint32(1))          // Ethernet

	// ── Packet: Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes ──
	pkt := make([]byte, 54)
	// Ethernet: dst=ff:ff:ff:ff:ff:ff, src=00:11:22:33:44:55, type=0x0800
	for i := 0; i < 6; i++ {
		pkt[i] = 0xff
	}
	pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11] = 0x00, 0x11, 0x22, 0x33, 0x44, 0x55
	pkt[12], pkt[13] = 0x08, 0x00 // IPv4

	// IPv4 header (20 bytes at offset 14)
	pkt[14] = 0x45           // version=4, IHL=5
	pkt[15] = 0x00           // DSCP/ECN
	pkt[16], pkt[17] = 0, 40 // total length = 40 (20 IP + 20 TCP)
	pkt[22] = 64             // TTL
	pkt[23] = 6              // Protocol = TCP
	// Src IP: 192.168.1.10
	pkt[26], pkt[27], pkt[28], pkt[29] = 192, 168, 1, 10
	// Dst IP: 10.0.0.1
	pkt[30], pkt[31], pkt[32], pkt[33] = 10, 0, 0, 1

	// TCP header (20 bytes at offset 34)
	pkt[34], pkt[35] = 0xD9, 0x03 // src port 55555
	pkt[36], pkt[37] = 0x01, 0xBB // dst port 443
	pkt[46] = 0x50                // data offset = 5 (20 bytes)
	pkt[47] = 0x02                // flags = SYN

	// Packet record header (16 bytes)
	ts := uint32(time.Now().Unix())
	binary.Write(&buf, binary.LittleEndian, ts)         // ts_sec
	binary.Write(&buf, binary.LittleEndian, uint32(0))  // ts_usec
	binary.Write(&buf, binary.LittleEndian, uint32(54)) // incl_len
	binary.Write(&buf, binary.LittleEndian, uint32(54)) // orig_len
	buf.Write(pkt)

	return buf.Bytes()
}

// ─── Test Helpers ──────────────────────────────────────────────────

// setupTestRouter creates a gin router with handler routes but no auth
// middleware, backed by a real (temp-dir) storage instance.
func setupTestRouter(t *testing.T) (*gin.Engine, *Handlers, *storage.Storage) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStorage()
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	h := NewHandlers(store)

	r := gin.New()
	r.Use(gin.Recovery())
	api := r.Group("/api")
	{
		api.GET("/health", h.HealthCheck)
		api.POST("/upload", h.UploadFile)
		api.POST("/analyze/:id", h.StartAnalysis)
		api.GET("/analyze/:id/status", h.GetAnalysisStatus)
		api.GET("/results/:id", h.GetResults)
		api.GET("/results/:id/pdf", h.DownloadPDF)
	}
	return r, h, store
}

// uploadPCAP posts a multipart upload with the embedded PCAP fixture.
func uploadPCAP(t *testing.T, router *gin.Engine) string {
	t.Helper()
	pcapData := buildMinimalPCAP()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "test.pcap")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(pcapData)); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("POST /upload: want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal upload response: %v", err)
	}
	if resp.ID == "" {
		t.Fatal("upload returned empty ID")
	}
	return resp.ID
}

// ─── Integration Tests ─────────────────────────────────────────────

func TestHealthCheck(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /health: want 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal health: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("health status = %q, want %q", resp.Status, "healthy")
	}
}

func TestUploadFile(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	id := uploadPCAP(t, router)
	t.Logf("Uploaded job ID: %s", id)
}

func TestUploadRejectsNonPCAP(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "malicious.exe")
	part.Write([]byte("not a pcap"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /upload .exe: want 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStartAnalysisAndPoll(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	id := uploadPCAP(t, router)

	// Start analysis
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/analyze/%s", id), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /analyze: want 202, got %d: %s", w.Code, w.Body.String())
	}

	// Poll status until completed or timeout
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/analyze/%s/status", id), nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("GET /analyze/status: want 200, got %d", w.Code)
		}

		var job storage.AnalysisJob
		if err := json.Unmarshal(w.Body.Bytes(), &job); err != nil {
			t.Fatalf("unmarshal status: %v", err)
		}

		if job.Status == storage.StatusCompleted {
			t.Logf("Analysis completed in %v", time.Since(deadline.Add(-15*time.Second)))
			return
		}
		if job.Status == storage.StatusFailed {
			t.Fatalf("Analysis failed: %s", job.Error)
		}
	}
	t.Fatal("Analysis did not complete within 15s")
}

func TestFullPipeline_Upload_Analyze_Results(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	id := uploadPCAP(t, router)

	// Start analysis
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/analyze/%s", id), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /analyze: want 202, got %d: %s", w.Code, w.Body.String())
	}

	// Wait for completion
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/analyze/%s/status", id), nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		var job storage.AnalysisJob
		json.Unmarshal(w.Body.Bytes(), &job)
		if job.Status == storage.StatusCompleted {
			break
		}
		if job.Status == storage.StatusFailed {
			t.Fatalf("Analysis failed: %s", job.Error)
		}
	}

	// GET /results/:id — should return JSON
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/results/%s", id), nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /results: want 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Verify JSON structure has essential fields
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal results: %v", err)
	}

	for _, key := range []string{"risk_score", "risk_level"} {
		if _, ok := result[key]; !ok {
			t.Errorf("results JSON missing key %q", key)
		}
	}
}

func TestGetResults_NotFound(t *testing.T) {
	router, _, _ := setupTestRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/results/nonexistent-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /results/bad-id: want 404, got %d", w.Code)
	}
}

func TestGetPDF_NotCompleted(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	id := uploadPCAP(t, router)

	// Try to get PDF before analysis completes
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/results/%s/pdf", id), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail — analysis not completed yet
	if w.Code == http.StatusOK {
		t.Fatal("GET /results/:id/pdf should not return 200 before analysis completes")
	}
}

func TestDuplicateAnalysisStart(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	id := uploadPCAP(t, router)

	// Start analysis first time
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/analyze/%s", id), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("First POST /analyze: want 202, got %d", w.Code)
	}

	// Try to start again — should get 409 (analyzing or completed)
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/analyze/%s", id), nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Accept either 409 Conflict (still analyzing or already completed)
	if w.Code != http.StatusConflict {
		// If the analysis completed between the two requests, that's also
		// a valid conflict scenario — the handler returns 409 for both states.
		// On very fast machines the 1-packet analysis can finish before the
		// second request. Poll once to confirm it completed:
		time.Sleep(200 * time.Millisecond)
		req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/analyze/%s", id), nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("Duplicate POST /analyze: want 409, got %d: %s", w.Code, w.Body.String())
		}
	}
}

// ─── Cleanup ────────────────────────────────────────────────────────

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	// Suppress gin debug noise
	gin.DefaultWriter = io.Discard
	// Clean up any leftover test data
	os.Exit(m.Run())
}

// unused import guard
var _ = filepath.Base
