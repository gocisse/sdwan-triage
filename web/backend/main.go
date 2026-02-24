// SD-WAN Triage Web Application - Main Entry Point
// This is the main server that provides a web interface for PCAP analysis.
// It uses Gin for HTTP, embedded miniredis for storage, and Gorilla WebSocket for real-time updates.

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gocisse/sdwan-triage/web/backend/handlers"
	"github.com/gocisse/sdwan-triage/web/backend/storage"
)

//go:embed static/*
var staticFiles embed.FS

const (
	DefaultPort   = 8080
	ServerAddress = "127.0.0.1"
	MaxUploadSize = 500 << 20 // 500MB
)

// findAvailablePort tries the requested port, then scans up to 10 ports above it
func findAvailablePort(startPort int) (int, error) {
	for port := startPort; port < startPort+10; port++ {
		addr := fmt.Sprintf("%s:%d", ServerAddress, port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available port found in range %d-%d", startPort, startPort+9)
}

func main() {
	// Parse command-line flags
	portFlag := flag.Int("port", DefaultPort, "HTTP server port (auto-selects next available if in use)")
	noBrowser := flag.Bool("no-browser", false, "Do not auto-open browser")
	flag.Parse()

	// Initialize storage (embedded Redis)
	store, err := storage.NewStorage()
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	// Set Gin to release mode for production
	gin.SetMode(gin.ReleaseMode)

	// Create Gin router
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Configure CORS - allow any localhost/127.0.0.1 origin (any port) for development
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

	// Set max multipart memory for file uploads
	router.MaxMultipartMemory = MaxUploadSize

	// Initialize handlers
	h := handlers.NewHandlers(store)

	// API Routes
	api := router.Group("/api")
	{
		// Health check
		api.GET("/health", h.HealthCheck)
		api.GET("/status", h.SystemStatus)

		// File upload
		api.POST("/upload", h.UploadFile)

		// Analysis
		api.POST("/analyze/:id", h.StartAnalysis)
		api.GET("/analyze/:id/status", h.GetAnalysisStatus)
		api.POST("/analyze/:id/cancel", h.CancelAnalysis)

		// Results
		api.GET("/results/:id", h.GetResults)
		api.GET("/results/:id/json", h.DownloadJSON)
		api.GET("/results/:id/html", h.DownloadHTML)

		// History
		api.GET("/history", h.ListHistory)
		api.DELETE("/history/:id", h.DeleteAnalysis)

		// Enhanced endpoints
		api.GET("/topology/:id", h.GetTopology)
		api.POST("/wizard/:id", h.PostWizard)
		api.POST("/compare", h.PostCompare)
		api.GET("/trends", h.GetTrends)

		// WebSocket for real-time progress
		api.GET("/ws/:id", h.WebSocketHandler)
	}

	// Serve static files (embedded React build)
	staticSubFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Printf("Warning: Static files not embedded, running in development mode")
	} else {
		// Create a sub-filesystem for assets
		assetsFS, err := fs.Sub(staticSubFS, "assets")
		if err != nil {
			log.Printf("Warning: Assets directory not found")
		} else {
			router.StaticFS("/assets", http.FS(assetsFS))
		}

		// Serve favicon
		router.GET("/favicon.svg", func(c *gin.Context) {
			faviconFile, err := staticFiles.ReadFile("static/favicon.svg")
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			c.Data(http.StatusOK, "image/svg+xml", faviconFile)
		})

		// Serve index.html for root path
		router.GET("/", func(c *gin.Context) {
			indexFile, err := staticFiles.ReadFile("static/index.html")
			if err != nil {
				c.String(http.StatusInternalServerError, "Failed to load application")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", indexFile)
		})

		// Serve index.html for all non-API routes (SPA support)
		router.NoRoute(func(c *gin.Context) {
			// Check if it's an API route
			if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
				c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
				return
			}

			// Serve index.html for SPA routing
			indexFile, err := staticFiles.ReadFile("static/index.html")
			if err != nil {
				c.String(http.StatusInternalServerError, "Failed to load application")
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", indexFile)
		})
	}

	// Find available port
	port, err := findAvailablePort(*portFlag)
	if err != nil {
		log.Fatalf("Failed to find available port: %v", err)
	}
	if port != *portFlag {
		log.Printf("Port %d in use, using port %d instead", *portFlag, port)
	}

	serverAddr := fmt.Sprintf("%s:%d", ServerAddress, port)
	serverURL := fmt.Sprintf("http://%s", serverAddr)

	// Create server
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  300 * time.Second, // Long timeout for large file uploads
		WriteTimeout: 300 * time.Second, // Long timeout for large file uploads
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait briefly for server to start, then print banner and open browser
	time.Sleep(200 * time.Millisecond)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║           SD-WAN Triage Web Application v4.3.0               ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Server running at: %-40s ║\n", serverURL)
	fmt.Println("║  Press Ctrl+C to stop the server                             ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if !*noBrowser {
		openBrowser(serverURL)
	}

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nShutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	fmt.Println("Server stopped gracefully")
}

// openBrowser opens the default browser to the specified URL
func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		log.Printf("Failed to open browser: %v", err)
		fmt.Printf("Please open your browser and navigate to: %s\n", url)
	}
}
