# SD-WAN Triage Web Application

A complete web interface for the SD-WAN Triage network analysis tool. This application runs locally on your machine with no external dependencies required.

## Features

- **Zero-Install Deployment**: Single executable file - just download and run
- **Drag-and-Drop Upload**: Easy PCAP file upload with progress tracking
- **Real-Time Analysis**: WebSocket-powered live progress updates
- **Interactive Dashboard**: Beautiful visualizations of analysis results
- **LAN Protocol Detection**: VRRP, CDP, LLDP, HSRP, STP with flapping detection
- **Security Analysis**: DDoS, DNS anomalies, TLS weaknesses, ARP conflicts
- **Performance Metrics**: TCP handshakes, retransmissions, packet loss
- **Analysis History**: Persistent storage of all analyses
- **Mobile-Friendly**: Responsive design optimized for all devices

## Quick Start

### Download and Run

1. Download the appropriate binary for your platform from the releases
2. Make it executable (macOS/Linux): `chmod +x sdwan-triage-web-*`
3. Double-click or run from terminal
4. Your browser will automatically open to `http://127.0.0.1:8080`

### Supported Platforms

- **macOS** (Intel and Apple Silicon)
- **Linux** (amd64 and arm64)
- **Windows** (64-bit)

## Usage

### Upload and Analyze

1. Open the application in your browser
2. Drag and drop a PCAP file onto the upload zone
3. Click "Start Analysis"
4. Watch real-time progress as your capture is analyzed
5. View results in the interactive dashboard

### Supported File Types

- `.pcap` - Standard PCAP format
- `.pcapng` - PCAP Next Generation format
- `.cap` - Capture file format

### Maximum File Size

500 MB per file

## Development

### Prerequisites

- Go 1.21 or later
- Node.js 18 or later
- npm 9 or later

### Project Structure

```
web/
├── backend/
│   ├── main.go              # Application entry point
│   ├── handlers/            # HTTP and WebSocket handlers
│   │   ├── handlers.go      # Main handlers
│   │   └── analyzer.go      # Analysis integration
│   ├── storage/             # Embedded Redis storage
│   │   └── storage.go       # Storage layer
│   └── static/              # Embedded frontend (built)
├── frontend/
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── pages/           # Route pages
│   │   ├── hooks/           # Custom React hooks
│   │   ├── types/           # TypeScript interfaces
│   │   ├── api/             # API client
│   │   └── utils/           # Utility functions
│   ├── public/              # Static assets
│   └── package.json         # Frontend dependencies
├── build.sh                 # Build script
└── README.md               # This file
```

### Running in Development Mode

**Backend:**
```bash
cd web/backend
go run .
```

**Frontend:**
```bash
cd web/frontend
npm install
npm run dev
```

The frontend dev server runs on `http://localhost:3000` and proxies API requests to the backend on port 8080.

### Building for Production

```bash
cd web
./build.sh
```

This will:
1. Build the React frontend
2. Embed it into the Go binary
3. Cross-compile for all platforms
4. Create ZIP archives with checksums

## API Endpoints

### Health & Status
- `GET /api/health` - Health check
- `GET /api/status` - System status

### File Upload
- `POST /api/upload` - Upload PCAP file

### Analysis
- `POST /api/analyze/:id` - Start analysis
- `GET /api/analyze/:id/status` - Get analysis status
- `POST /api/analyze/:id/cancel` - Cancel analysis

### Results
- `GET /api/results/:id` - Get JSON results
- `GET /api/results/:id/json` - Download JSON file
- `GET /api/results/:id/html` - Download HTML report

### History
- `GET /api/history` - List all analyses
- `DELETE /api/history/:id` - Delete analysis

### WebSocket
- `GET /api/ws/:id` - Real-time progress updates

## Technology Stack

### Backend
- **Go** - Server language
- **Gin** - HTTP framework
- **Gorilla WebSocket** - WebSocket support
- **miniredis** - Embedded Redis for storage
- **gopacket** - Packet analysis

### Frontend
- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Lucide React** - Icons
- **React Router** - Navigation

## Data Storage

Analysis data is stored in:
- **macOS/Linux**: `~/.sdwan-triage/`
- **Windows**: `%USERPROFILE%\.sdwan-triage\`

This includes:
- Uploaded PCAP files
- Analysis results (JSON)
- Generated HTML reports
- History database

## Security Considerations

- Runs only on localhost (127.0.0.1)
- CORS restricted to localhost origins
- File type validation before processing
- File size limits enforced
- Path traversal prevention

## Troubleshooting

### Port Already in Use

If port 8080 is already in use, the application will fail to start. Close any other applications using that port.

### Browser Doesn't Open

If your browser doesn't open automatically, manually navigate to:
```
http://127.0.0.1:8080
```

### Analysis Fails

Check that:
- The PCAP file is valid and not corrupted
- The file is not larger than 500MB
- You have sufficient disk space

## License

See the main project LICENSE file.

## Version

4.3.0
