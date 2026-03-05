package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/pkg/database"
	"github.com/gocisse/sdwan-triage/pkg/integration"
	"github.com/gocisse/sdwan-triage/pkg/intelligence"
	"github.com/gocisse/sdwan-triage/pkg/metrics"
	"github.com/gocisse/sdwan-triage/pkg/middleware"
	"github.com/gocisse/sdwan-triage/pkg/web/handlers"
	"github.com/gocisse/sdwan-triage/pkg/web/storage"
)

const (
	defaultWebPort   = 8080
	serverAddress    = "127.0.0.1"
	maxUploadSize    = 500 << 20 // 500MB
	portRetryRange   = 10
	shutdownTimeout  = 30 * time.Second
	serverStartDelay = 200 * time.Millisecond
)

// findAvailablePort tries the requested port, then scans up to portRetryRange ports above it.
func findAvailablePort(startPort int) (int, error) {
	for port := startPort; port < startPort+portRetryRange; port++ {
		addr := fmt.Sprintf("%s:%d", serverAddress, port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available port found in range %d-%d", startPort, startPort+portRetryRange-1)
}

// openBrowser opens the default browser to the specified URL (cross-platform).
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "darwin":
		err = exec.Command("open", url).Start()
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	if err != nil {
		log.Printf("Failed to open browser: %v", err)
		fmt.Printf("Please open your browser and navigate to: %s\n", url)
	}
}

// IntegrationOptions holds CLI flags for enterprise integrations.
type IntegrationOptions struct {
	ServiceNowURL      string
	ServiceNowUser     string
	ServiceNowPassword string
}

// runWebServer starts the unified web server with embedded React frontend.
func runWebServer(port int, noBrowser bool, intOpts *IntegrationOptions) {
	// Initialize storage (embedded Redis — zero external deps)
	store, err := storage.NewStorage()
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// ── Security Foundation: SQLite user database ──────────────
	dbPath := filepath.Join(store.GetDataDir(), "sdwan.db")
	userDB, err := database.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize user database: %v", err)
	}
	defer userDB.Close()
	log.Printf("[INIT] User database initialized at %s", dbPath)

	authCfg := middleware.NewAuthConfig(userDB)
	log.Println("[INIT] JWT authentication enabled")

	// Gin in release mode — no debug noise
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// CORS — allow any localhost origin for development
	router.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			return strings.HasPrefix(origin, "http://127.0.0.1") ||
				strings.HasPrefix(origin, "http://localhost")
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "Content-Length", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length", "Content-Disposition", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.MaxMultipartMemory = maxUploadSize

	// ── Enterprise Integrations ─────────────────────────────────
	intCfg := initIntegrations(store, intOpts)

	// Wire up API handlers (reuses existing web/backend/handlers)
	h := handlers.NewHandlers(store)
	h.SetIntegrations(intCfg)

	// Wire up packet inspection handlers
	packetHandlers := handlers.NewPacketInspectionHandlers(store)

	// Wire up comparison handlers
	comparisonHandlers := handlers.NewComparisonHandlers(store.GetUploadsDir())

	// Wire up export/annotation handlers
	exportHandlers := handlers.NewExportPCAPHandlers(packetHandlers)

	api := router.Group("/api")

	// ── Public endpoints (no auth required) ────────────────────
	api.GET("/health", h.HealthCheck)
	api.POST("/login", handleLogin(authCfg))

	// ── Protected endpoints (JWT required) ─────────────────────
	protected := api.Group("")
	protected.Use(authCfg.RequireAuth())
	{
		protected.GET("/status", h.SystemStatus)
		protected.POST("/upload", h.UploadFile)
		protected.POST("/analyze/:id", h.StartAnalysis)
		protected.GET("/analyze/:id/status", h.GetAnalysisStatus)
		protected.POST("/analyze/:id/cancel", h.CancelAnalysis)
		protected.GET("/results/:id", h.GetResults)
		protected.GET("/results/:id/json", h.DownloadJSON)
		protected.GET("/results/:id/html", h.DownloadHTML)
		protected.GET("/history", h.ListHistory)
		protected.DELETE("/history/:id", h.DeleteAnalysis)
		protected.GET("/topology/:id", h.GetTopology)
		protected.POST("/wizard/:id", h.PostWizard)
		protected.POST("/compare", h.PostCompare)
		protected.POST("/compare-pcap", comparisonHandlers.PostCompareUpload)
		protected.GET("/trends", h.GetTrends)
		protected.GET("/ws/:id", h.WebSocketHandler)

		// ── Packet Inspection endpoints ──────────────────────────
		protected.GET("/packets/:jobID", packetHandlers.ListPackets)
		protected.GET("/packet/:jobID/:packetIndex", packetHandlers.GetPacket)
		protected.GET("/streams/:jobID", packetHandlers.ListStreams)
		protected.GET("/stream/:jobID/*streamID", packetHandlers.GetStream)

		// ── PCAP Export & Annotation endpoints ──────────────────
		protected.POST("/export-pcap/:jobID", exportHandlers.PostExportPCAP)
		protected.GET("/annotations/:jobID", exportHandlers.GetAnnotations)
		protected.POST("/annotations/:jobID", exportHandlers.PostAnnotation)
		protected.DELETE("/annotations/:jobID/:annotationID", exportHandlers.DeleteAnnotation)

		// ── Auth management endpoints ────────────────────────
		protected.GET("/auth/me", handleMe(authCfg))
		protected.POST("/auth/change-password", handleChangePassword(authCfg))

		// Admin-only user management
		admin := protected.Group("/auth/users")
		admin.Use(middleware.RequireRole(database.RoleAdmin))
		{
			admin.GET("", handleListUsers(authCfg))
			admin.POST("", handleCreateUser(authCfg))
		}
	}

	// Prometheus metrics endpoint (outside /api group — standard path)
	if intCfg.Metrics != nil {
		router.GET("/metrics", gin.WrapH(intCfg.Metrics.PrometheusHandler()))
	}

	// Serve embedded React frontend
	mountFrontend(router)

	// Find an available port (auto-retry if busy)
	actualPort, err := findAvailablePort(port)
	if err != nil {
		log.Fatalf("Failed to find available port: %v", err)
	}
	if actualPort != port {
		log.Printf("Port %d in use, using port %d instead", port, actualPort)
	}

	serverAddr := fmt.Sprintf("%s:%d", serverAddress, actualPort)
	serverURL := fmt.Sprintf("http://%s", serverAddr)

	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in background goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	time.Sleep(serverStartDelay)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Printf("║       SD-WAN Triage v%-40s║\n", version)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Server running at: %-40s ║\n", serverURL)
	fmt.Println("║  Press Ctrl+C to stop the server                             ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if !noBrowser {
		openBrowser(serverURL)
	}

	// Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Gracefully shut down enterprise integrations
	shutdownIntegrations(intCfg)

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	fmt.Println("Server stopped gracefully")
}

// initIntegrations initializes all enterprise integration components.
// Each component is optional — if initialization fails, it logs a warning and continues.
func initIntegrations(store *storage.Storage, opts *IntegrationOptions) *handlers.IntegrationConfig {
	cfg := &handlers.IntegrationConfig{}

	// 1. Prometheus Metrics — always enabled
	cfg.Metrics = metrics.GetGlobalCollector()
	cfg.Metrics.SetLabel("instance", "sdwan-triage")
	cfg.Metrics.SetLabel("version", version)
	log.Println("[INIT] Prometheus metrics collector initialized")

	// 2. Automation Engine — always enabled with default triggers
	automationEngine := integration.NewAutomationEngine()
	for _, trigger := range integration.CreateDefaultTriggers() {
		automationEngine.RegisterTrigger(trigger)
	}
	automationEngine.Start()
	cfg.Automation = automationEngine
	log.Println("[INIT] Automation engine started with default triggers")

	// Drain automation results in background (log them)
	go func() {
		for result := range automationEngine.Results() {
			if result.Success {
				log.Printf("[AUTOMATION] %s: %s", result.ActionType, result.Message)
			} else {
				log.Printf("[AUTOMATION] %s FAILED: %s", result.ActionType, result.Error)
			}
		}
	}()

	// 3. Customer Intelligence DB — persisted to data directory
	dbPath := filepath.Join(store.GetDataDir(), "intelligence.json")
	intelDB, err := intelligence.NewCustomerDB(dbPath)
	if err != nil {
		log.Printf("[INIT] Warning: Customer intelligence DB failed to initialize: %v", err)
	} else {
		cfg.Intelligence = intelDB
		log.Printf("[INIT] Customer intelligence DB initialized at %s", dbPath)
	}

	// 4. ServiceNow Ticketing — only if credentials are provided
	if opts != nil && opts.ServiceNowURL != "" && opts.ServiceNowUser != "" {
		snowClient := integration.NewServiceNowClient(
			opts.ServiceNowURL,
			opts.ServiceNowUser,
			opts.ServiceNowPassword,
		)
		cfg.Ticketing = snowClient
		// Wire ticketing into automation engine so "create_ticket" actions work
		automationEngine.SetTicketingClient(snowClient)
		log.Printf("[INIT] ServiceNow integration enabled (URL: %s)", opts.ServiceNowURL)
	} else {
		log.Println("[INIT] ServiceNow integration disabled (no credentials provided)")
	}

	return cfg
}

// shutdownIntegrations gracefully shuts down all enterprise integration components.
func shutdownIntegrations(cfg *handlers.IntegrationConfig) {
	if cfg == nil {
		return
	}
	if cfg.Automation != nil {
		cfg.Automation.Stop()
		log.Println("[SHUTDOWN] Automation engine stopped")
	}
	if cfg.Intelligence != nil {
		if err := cfg.Intelligence.Close(); err != nil {
			log.Printf("[SHUTDOWN] Warning: Intelligence DB close error: %v", err)
		} else {
			log.Println("[SHUTDOWN] Customer intelligence DB saved and closed")
		}
	}
}

// mountFrontend serves the embedded React build from frontendFS (defined in embed.go).
func mountFrontend(router *gin.Engine) {
	// frontendFS embeds "all:dist" — files are at dist/index.html, dist/assets/*, etc.
	distFS, err := fs.Sub(frontendFS, "dist")
	if err != nil {
		log.Printf("Warning: Embedded frontend not available (%v), running API-only", err)
		return
	}

	// Check if index.html exists inside the embedded FS
	if _, err := fs.Stat(distFS, "index.html"); err != nil {
		log.Printf("Warning: Embedded frontend has no index.html, running API-only")
		return
	}

	// Serve /assets/* directly
	assetsFS, err := fs.Sub(distFS, "assets")
	if err != nil {
		log.Printf("Warning: Assets directory not found in embedded frontend")
	} else {
		router.StaticFS("/assets", http.FS(assetsFS))
	}

	// Serve favicon
	router.GET("/favicon.svg", func(c *gin.Context) {
		data, err := fs.ReadFile(distFS, "favicon.svg")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "image/svg+xml", data)
	})

	// Serve logo
	router.GET("/logo.png", func(c *gin.Context) {
		data, err := fs.ReadFile(distFS, "logo.png")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "image/png", data)
	})

	// Read index.html once at startup for SPA serving
	indexHTML, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		log.Printf("Warning: Could not read index.html from embedded frontend")
		return
	}

	// Serve index.html for root
	router.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	})

	// SPA fallback: serve index.html for all non-API, non-asset routes
	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api") {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}
		if strings.HasPrefix(path, "/assets") {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	})
}
