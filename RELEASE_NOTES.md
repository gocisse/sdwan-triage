<p align="center">
  <img src="Pharaoh.svg.png" alt="SD-WAN Triage" width="100" />
</p>

# SD-WAN Triage v6.0.0.2 — Final Polish Release

Patch release achieving **100% test pass rate**, adding **Dark/Light theme toggle**, and **API rate limiting** for production hardening.

---

## What's New in v6.0.0.2

### 🐛 Bug Fixes — 100% Test Pass Rate

- **Fixed `TestDetectorRegistry_PanicRecovery` hang**: Mutex deadlock when a detector panics while holding `report.Mu`. Restructured goroutine to guarantee `Unlock()` via deferred inner function.
- **Fixed `TestGetFailurePattern` assertion drift**: Test data produced 25% success rate which missed the `< 25%` integer threshold. Adjusted to 12.5% to correctly trigger "High failure rate" path.

### 🌗 Dark/Light Theme Toggle (Gap §2.4)

- `darkMode: 'class'` enabled in Tailwind config
- New `ThemeContext.tsx` with `useTheme()` hook and `localStorage` persistence
- Sun/Moon toggle button in header navbar
- Full Layout (header, nav, footer, menus, cards) updated with `dark:` variant classes
- Default: dark theme (existing design preserved)

### 🛡️ API Rate Limiting (Gap §2.6)

- Self-contained in-process token-bucket rate limiter — no external dependencies
- 100 requests/minute per IP, configurable
- Background cleanup of stale visitor entries
- Proper `429 Too Many Requests` with `Retry-After` header
- 4 unit tests: burst, per-IP isolation, replenishment, cleanup

### 🏗️ Carried from v6.0.0

- Modular ResultsPage architecture (orchestrator + 3 sub-components)
- 5-step onboarding tour with spotlight and keyboard navigation
- Keyboard shortcuts modal (`?` key)
- Animated skeleton loading states
- OOM guard in processor (1 GB heap limit)
- Global error toast notifications
- 207 frontend tests, 8 backend integration tests, 7 streaming comparator tests

---

## Test Results

| Suite | Result |
|-------|--------|
| `pkg/analyzer` | ✅ All pass (no hang) |
| `pkg/detector` | ✅ All pass |
| `pkg/web/handlers` | ✅ All pass |
| `pkg/middleware` | ✅ 4 rate limiter tests pass |
| Frontend (vitest) | ✅ 207 tests, 6 files |
| `tsc --noEmit` | ✅ |
| `vite build` | ✅ |
| `go build ./...` | ✅ |

---

## Download

| Platform | Download |
|----------|----------|
| **macOS (Apple Silicon)** | `sdwan-triage-v6.0.0.2-darwin-arm64.tar.gz` |
| **macOS (Intel)** | `sdwan-triage-v6.0.0.2-darwin-amd64.tar.gz` |
| **Linux (x86_64)** | `sdwan-triage-v6.0.0.2-linux-amd64.tar.gz` |
| **Windows (x86_64)** | `sdwan-triage-v6.0.0.2-windows-amd64.zip` |

Verify integrity: `shasum -a 256 -c checksums-v6.0.0.2.txt`

---

**Full Changelog:** [v6.0.0...v6.0.0.2](https://github.com/gocisse/sdwan-triage/compare/v6.0.0...v6.0.0.2)
