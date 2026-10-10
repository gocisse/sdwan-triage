# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project purpose

SD-WAN Triage is a single-binary Go tool for offline PCAP forensic analysis.

The core product goal is:

> **Give a network engineer the answer faster.**

It is intended to help network engineers investigate problems such as:

* packet loss
* TCP retransmissions and connection problems
* UDP problems
* DNS failures
* TLS issues
* unreachable sites, URLs, or databases
* SD-WAN-specific network problems
* security/threat indicators

The tool must prioritize **correctness, explainability, evidence, and useful conclusions** over feature count.

The project runs either as:

* CLI — text/JSON/CSV/HTML/PDF reports
* local web server (`-web`) — embedded React dashboard

Module path: `github.com/gocisse/sdwan-triage`

Go version: 1.25

---

# Claude operating rules

## 1. Do not perform broad refactors without explicit approval

Do not interpret a request to "analyze", "audit", "improve", "clean up", or "modernize" as permission to modify the repository.

For analysis/audit tasks:

* make no source changes
* make no configuration changes
* do not delete files
* do not rename files
* do not move packages
* do not change APIs
* do not create speculative abstractions

First produce findings and recommendations.

For implementation tasks, make the smallest change that satisfies the explicitly requested phase.

Do not combine unrelated cleanup with feature work.

---

## 2. Preserve working behavior unless the task explicitly changes it

This repository has undergone several architecture and detector-correctness phases.

Existing code may look redundant or old because some migrations are intentionally incremental.

Before deleting or replacing something:

1. search for all references
2. determine whether it is reachable from the live CLI/web paths
3. inspect tests and build scripts
4. determine whether it is intentionally retained for compatibility
5. report the evidence
6. only delete it when the task explicitly authorizes deletion

Never delete code merely because it "looks unused".

---

## 3. Git discipline

Work on the current branch unless explicitly instructed otherwise.

Before making substantial changes:

* inspect `git status`
* inspect the current commit
* understand the local changes

Do not overwrite or discard existing user changes.

Do not run destructive commands such as:

* `git reset --hard`
* `git clean -fd`
* `git checkout -- <file>`
* mass file deletion

unless explicitly authorized.

Keep implementation phases small and reviewable.

When a requested phase is complete:

* run the relevant tests
* run formatting/linting where appropriate
* inspect the diff
* summarize what changed
* identify any remaining risks

Do not create commits unless explicitly requested.

---

## 4. PCAP analysis correctness is more important than code elegance

This is a network-forensics tool.

A detector must not report a problem merely because a packet pattern looks suspicious.

Prefer:

**packet evidence → state/correlation → interpretation → finding**

over:

**packet pattern → finding**

When modifying detection logic:

* use packet timestamps, never wall-clock time, for capture evidence
* preserve protocol semantics
* distinguish retransmission from normal TCP behavior
* account for keep-alives and zero/low-payload packets
* correlate events using the appropriate flow/client/session identity
* avoid treating independent protocol fields as correlated merely because they occur close together
* avoid introducing false positives to improve recall

When uncertain about protocol behavior, state the uncertainty and validate against packet captures or authoritative protocol behavior rather than guessing.

---

## 5. Tests are part of the implementation

For detector or analyzer changes, tests should normally accompany the change.

Prefer the existing deterministic golden/regression test infrastructure:

`pkg/analyzer/golden_test.go`

Use synthetic PCAPs when they provide precise control over the scenario.

Use real/vendor PCAPs when validating behavior against real traffic.

A successful build is not sufficient evidence that a network-analysis change is correct.

For meaningful detector changes, validate:

1. unit/regression behavior
2. end-to-end analyzer behavior
3. relevant PCAP evidence where available
4. absence of obvious regressions in existing golden tests

Do not weaken or remove a test simply because the new implementation makes it fail.

If expected behavior changes, explain why.

---

## 6. Do not optimize for fewer lines of code

Do not simplify the code merely to make it smaller.

The objective is:

* fewer false positives
* trustworthy findings
* understandable architecture
* maintainable detector logic
* one clear analysis engine
* predictable CLI/web behavior

A longer implementation may be preferable if it makes protocol behavior or evidence explicit.

---

# Architecture

## Entry points

CLI:

`cmd/sdwan-triage/main.go`

Web server:

`cmd/sdwan-triage/webserver.go`

Both ultimately use the same analysis engine.

The desired architectural direction is:

```text
                    ┌── CLI
PCAP → Analyzer ────┤
                    └── Web/API
```

There should be one authoritative analysis engine and one authoritative report model.

Do not create a second analysis pipeline for the web frontend.

---

## Analysis pipeline

`pkg/analyzer`

`Processor.Process` reads packets through `PacketReader` / `OpenCapture`, applies `models.Filter`, and feeds packets to the detector registry.

`buildDetectorRegistry()` in `processor.go` is the central detector wiring location.

Detector execution is currently sequential.

Do not reintroduce per-packet goroutines or unnecessary locking inside detectors without explicit evidence that the architecture requires it.

After packet processing, `finalizeReport` builds summaries, risk score, and recommendations.

---

## Detectors

Protocol/threat detectors exist primarily under:

* `pkg/detector`
* `pkg/detectors`

Analyzer-level logic also exists in:

`pkg/analyzer`

Shared mutable analysis state is held by `models.AnalysisState`.

Results accumulate in:

`models.TriageReport`

When migrating detector architecture, preserve behavioral compatibility until the replacement is proven equivalent or intentionally changes behavior.

---

## Time handling

Previous releases contained bugs caused by comparing packet evidence against wall-clock `time.Now()`.

For packet-analysis behavior:

**capture timestamps are authoritative.**

Do not introduce wall-clock time into evidence calculations, timeout detection, stream eviction, certificate validity analysis, DDoS windows, handshake timing, or similar forensic logic unless there is a clearly documented reason.

---

## Typed event layer (`pkg/events`) — Phase 3, in progress

Detectors are being migrated to **dual-write**: they keep populating `TriageReport` as before *and* emit typed `events.Event`s via `report.Emit(...)`.

* `Event` records WHAT was observed and WHEN (capture time). It deliberately carries **no severity, confidence or recommendation** — those belong to the later Finding/Diagnosis layer.
* `Kind` is a dotted, namespaced string (`tcp.retransmission`, `bfd.down`, `dns.anomaly`, `tunnel.observed`, `traffic.gap`, ...). The vocabulary is intentionally small and only covers signals an existing detector produces. Each Kind's `Values`/`Attrs` contract is documented in `pkg/events/event.go`; keep it there when adding a Kind.
* `Processor` creates a `Recorder` (the `Emitter`) writing to a bounded `Index` (`MaxEvents`, default 100k; overflow is **dropped and counted**, never evicted). `Recorder.SetCurrentPacket` is called per packet, so events emitted without a Timestamp get the current packet's capture time. **Finalize-time emitters run after the last packet and must set `Timestamp` explicitly.**
* `Index` is not concurrency-safe (pipeline is single-threaded) and sorts lazily by `(Timestamp, ID)`; correlation (`pkg/analyzer/correlator.go`) now queries it.
* Tests: `events_golden_test.go`, `dualwrite_test.go`, `correlation_golden_test.go`, `phase31_evidence_test.go` in `pkg/analyzer`; synthetic packets come from `internal/testpcap`.

## LAN/WAN comparison

`comparator.go` and `comparator_streaming.go` correlate two captures using a streaming/memory-bounded approach.

Do not replace this with an unbounded in-memory design without explicit approval.

---

## Output

`pkg/output` renders reports including:

* HTML
* PDF
* CSV
* plain/simple output
* Wireshark filters

`pkg/safety` contains junior-mode guidance and validation/escalation workflows.

---

## Web

The live web layer is:

* `cmd/sdwan-triage/webserver.go`
* `pkg/web`
* `pkg/middleware`
* `pkg/database`
* `web/frontend`

`web/frontend` is the React/TypeScript/Vite/Tailwind frontend.

The frontend should consume the same authoritative report produced by the analyzer.

Do not duplicate analyzer logic in TypeScript.

---

## Legacy or potentially obsolete code

The repository contains older architecture and generated/build artifacts.

Potentially obsolete code must be treated as **unverified legacy**, not automatically as dead code.

Before removing any such area:

* prove whether it is reachable
* check imports/references
* check build scripts
* check tests
* check CI/release scripts
* check documentation where relevant

Removal should be an explicit, reviewable phase.

---

# Commands

```bash
make build
make build-backend
make build-all
make test
make test-race
make lint
make run ARGS='capture.pcap'
make run-web
make frontend-dev
```

Build gotchas:

* `make build`/`build-backend` require the frontend to be built and copied into `cmd/sdwan-triage/dist` first (`copy-dist`, which runs `npm install` + `npm run build`); that directory is what gets embedded in the binary. Plain `go build ./cmd/sdwan-triage` uses whatever is already there.
* `make test` uses `-v -timeout 60s`; `make lint` is only `go fmt` + `go vet`.
* `build/`, `sdwan-triage`, `cmd/sdwan-triage/dist/`, `releases/` are build artifacts and show up as modified in `git status` after builds — don't include them in diffs/commits of source work.

Single Go test:

```bash
go test ./pkg/analyzer -run TestName -count=1
```

Frontend:

```bash
cd web/frontend
npm run lint
npm test
```

---

# Testing notes

`pkg/analyzer/golden_test.go` runs deterministic end-to-end scenarios using generated PCAPs and the standard `Processor`.

Prefer extending this infrastructure for detector-correctness regressions.

Helper programs:

* `tools/generate_samples`
* `tools/testpcap`

PCAP files are generally not committed.

Vendor-PCAP regression harness (`pkg/analyzer/vendor_regression_test.go`, snapshots in `pkg/analyzer/testdata/vendor/`):

* Run: `SDWAN_VENDOR_PCAP_DIR=/path/to/VendorTestFile go test ./pkg/analyzer -run VendorRegression -count=1 -v`. Unset = loud skip; set but PCAPs missing = failure.
* Snapshots are rewritten only with `SDWAN_UPDATE_SNAPSHOTS=1` (plus the directory variable); review the diff first.
* Snapshots pin **current behavior, not verified truth**: green means "unchanged", never "correct". Nondeterministic fields are intentionally not protected (see the test header).

Committed binaries and build artifacts are not authoritative source code.

---

# Change workflow

For a non-trivial implementation phase:

### Before coding

1. inspect repository state
2. identify relevant architecture
3. identify existing tests
4. identify affected callers
5. state the intended change and its boundaries

### During coding

* keep changes focused
* avoid unrelated cleanup
* preserve existing behavior unless intentionally changed
* add or update tests
* do not introduce speculative abstractions

### After coding

Run the smallest relevant validation first, then broader validation as appropriate.

Inspect:

```bash
git diff
git status
```

Report:

* files changed
* behavior changed
* tests added/changed
* tests executed
* known limitations
* whether a real PCAP validation is still required

Do not claim a change is correct merely because it compiles.

---

# Important project principle

This project is a network-engineering tool, not a generic software architecture exercise.

A cleaner architecture that produces less trustworthy network conclusions is a regression.

When there is a conflict between:

* architectural elegance
* implementation simplicity
* detection accuracy
* evidence quality

prefer **detection accuracy and evidence quality**.

The goal is not to make the repository look professional.

The goal is to make the tool **trustworthy, understandable, and faster at answering a network engineer's question**.


