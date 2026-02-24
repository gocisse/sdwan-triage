# SD-WAN Triage v4.3.1 — Unified Binary & Enhanced Vendor Support

**Release Date:** February 22, 2026
**Tag:** `v4.3.1`

---

## Highlights

### 1. Unified Single Binary — Zero Install

The web interface is now **embedded directly into the Go binary**. No `npm install`, no Node.js, no separate frontend build. Download one file, run it, open your browser.

```bash
./sdwan-triage -web
# → Opens http://127.0.0.1:8080 with the full React dashboard
```

**Architecture:** React frontend is compiled at build time via `//go:embed` and served by the Gin HTTP server. The same binary still supports full CLI mode for automation pipelines.

### 2. JWT Authentication & User Management

All `/api/*` endpoints are now protected with JWT-based authentication. A persistent SQLite database (`modernc.org/sqlite`, pure Go, no CGO) stores user credentials with bcrypt-hashed passwords.

- **Default user:** `admin` / `admin` (seeded on first startup with a prominent warning)
- **Login page:** Modern dark-themed UI shown before any protected content
- **Token lifecycle:** 24-hour expiry, auto-logout on 401, per-instance random HMAC-SHA256 secret
- **Role-based access:** `admin`, `analyst`, `viewer` roles with middleware enforcement
- **Password management:** Change password via the user dropdown menu in the header
- **Admin endpoints:** `GET /api/auth/users`, `POST /api/auth/users` (admin-only)

### 3. VeloCloud Vendor Runbooks — Deep `debug.py` Support

The Troubleshooting Wizard now includes **vendor-specific runbooks** for VMware VeloCloud SD-WAN. When a VeloCloud tunnel issue is detected, the wizard provides:

- Exact `debug.py` CLI commands to run on the Edge
- Step-by-step GUI navigation paths
- Safety warnings for production environments
- ELI5 (Explain Like I'm 5) explanations for junior engineers

Vendor runbooks take priority over generic knowledge base entries. If a vendor-specific runbook exists for a finding, it is shown first.

### 4. Enterprise Integrations — Wired & Operational

Four enterprise packages are now initialized at startup and wired into the post-analysis pipeline:

| Integration | Status | Description |
|---|---|---|
| **Prometheus Metrics** | Always enabled | Counters/gauges at `GET /metrics` |
| **Automation Engine** | Always enabled | Default triggers for critical findings |
| **ServiceNow Ticketing** | Opt-in via flags | Auto-creates tickets for Critical risk findings |
| **Customer Intelligence DB** | Always enabled | Anonymized stats persisted to `intelligence.json` |

```bash
# Enable ServiceNow integration
./sdwan-triage -web -servicenow-url https://instance.service-now.com \
  -servicenow-user api_user -servicenow-password secret
```

---

## What's Changed

### New Files

| File | Purpose |
|---|---|
| `pkg/database/database.go` | SQLite user DB — init, migrate, seed, CRUD |
| `pkg/middleware/auth.go` | JWT generation, validation, Gin middleware |
| `cmd/sdwan-triage/auth_handlers.go` | Login, me, change-password, user management handlers |
| `web/frontend/src/auth/AuthContext.tsx` | React auth state management + 401 interception |
| `web/frontend/src/pages/LoginPage.tsx` | Login form UI |
| `web/frontend/src/components/ChangePasswordModal.tsx` | Change password modal |

### Modified Files

| File | Change |
|---|---|
| `cmd/sdwan-triage/webserver.go` | SQLite init, auth middleware on all protected routes, login endpoint |
| `cmd/sdwan-triage/main.go` | ServiceNow CLI flags |
| `web/frontend/src/api/client.ts` | Auto-attach JWT to all requests, 401 event dispatch |
| `web/frontend/src/hooks/useWebSocket.ts` | JWT token in WS URL, HTTP polling fallback |
| `web/frontend/src/components/Layout.tsx` | User dropdown menu with Change Password + Sign Out |
| `web/frontend/src/App.tsx` | Auth gate — login required before any route |
| `web/frontend/src/main.tsx` | AuthProvider wrapper |
| `web/frontend/src/data/vendorRunbooks.ts` | VeloCloud `debug.py` runbook entries |
| `web/frontend/src/components/dashboard/WizardModal.tsx` | Vendor runbook priority lookup |
| `pkg/web/handlers/analyzer.go` | Post-analysis hooks for all integrations |

### Dependencies Added

| Package | Version | Purpose |
|---|---|---|
| `modernc.org/sqlite` | v1.46.1 | Pure Go SQLite (no CGO) |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 | JWT token signing/validation |
| `golang.org/x/crypto` | v0.48.0 | bcrypt password hashing |

---

## Build Artifacts

| Platform | File | Size |
|---|---|---|
| Linux x64 | `sdwan-triage-v4.3.1-linux-amd64.tar.gz` | ~9.2 MB |
| macOS Intel | `sdwan-triage-v4.3.1-darwin-amd64.tar.gz` | ~9.4 MB |
| macOS ARM | `sdwan-triage-v4.3.1-darwin-arm64.tar.gz` | ~8.9 MB |
| Windows x64 | `sdwan-triage-v4.3.1-windows-amd64.zip` | ~9.4 MB |

SHA-256 checksums in `checksums-v4.3.1.txt`.

---

## Upgrade Notes

- **From v4.3.0:** Drop-in replacement. The binary now includes the web frontend — no separate `npm` build needed. On first run with `-web`, a `sdwan.db` file is created in `~/.sdwan-triage/` with the default admin user.
- **Breaking:** API endpoints now require a JWT `Authorization: Bearer <token>` header. Scripts calling the API must first `POST /api/login` to obtain a token.
- **Default credentials:** Change the `admin` password immediately after first login.

---

## Security Notes

- JWT secret is randomly generated per process start (not persisted). All tokens invalidate on restart.
- Passwords are bcrypt-hashed (cost 10).
- SQLite database is stored locally at `~/.sdwan-triage/sdwan.db`.
- WebSocket authentication uses `?token=` query parameter (standard pattern for browser WS connections).

---

**Full Changelog:** v4.3.0...v4.3.1
