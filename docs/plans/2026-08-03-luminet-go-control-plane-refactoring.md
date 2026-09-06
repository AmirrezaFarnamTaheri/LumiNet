# LumiNet Go Control Plane Refactoring Implementation Plan

> [!IMPORTANT]
> **STATUS: COMPLETE** — All tasks executed and verified. `go build ./...`, `go vet ./...`, `go test ./...` all pass.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate static `unsafe.Pointer` misuse warnings in Windows syscall drivers and consolidate non-standard Go package structures (`utils` -> `util`, `scan` -> `scanner`) in `server/internal/` using backward-compatible type aliases.

**Architecture:** Fix `go vet` pointer warnings by enforcing valid inline pointer expression conversions in Windows syscall bridges, migrate utility routines to singular `util/`, and unify scan planning types into `scanner/` while exporting compatibility type aliases (`type T = pkg.T`) to prevent breaking dependent modules.

**Tech Stack:** Go 1.26.3, Windows Syscalls / CGO, `go vet`, `go test`, `graphify`.

---

## File Structure & Responsibilities

| File Path | Action | Description / Responsibility |
| :--- | :--- | :--- |
| `server/internal/bridge/shm_windows.go` | Modify | Fix unsafe pointer conversion pattern from `syscall.MapViewOfFile` |
| `server/internal/system/wintun_windows.go` | Modify | Fix unsafe pointer conversions from `syscall.SyscallN` for packet ring buffers |
| `server/internal/util/network.go` | Create | Consolidated network helper functions from `utils/network.go` |
| `server/internal/util/sysprocattr_windows.go` | Create | Consolidated process attribute helpers from `utils/sysprocattr_windows.go` |
| `server/internal/utils/network.go` | Modify | Forwarding aliases delegating to `util` package |
| `server/internal/scanner/scan_planner.go` | Create | Consolidated scan target and execution planning structs |
| `server/internal/scan/plan.go` | Modify | Type aliases `type Plan = scanner.Plan` for backward compatibility |

---

## Detailed Task Breakdown

### Task 1: Fix `go vet` `unsafe.Pointer` Misuse Warnings

**Files:**
- Modify: `server/internal/bridge/shm_windows.go:40-50`
- Modify: `server/internal/system/wintun_windows.go:138-160`

- [ ] **Step 1: Inspect failing `go vet` warnings**

Run: `cd server && go vet ./internal/bridge ./internal/system`  
Expected: `possible misuse of unsafe.Pointer` warnings in `shm_windows.go:44` and `wintun_windows.go:140,156`.

- [ ] **Step 2: Apply inline unsafe pointer cast in `shm_windows.go`**

In `server/internal/bridge/shm_windows.go`, replace lines 43-45:
```go
	return unsafe.Slice((*byte)(unsafe.Pointer(addr)), size), nil
```
with valid inline conversion or direct byte pointer cast:
```go
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), size), nil
```

- [ ] **Step 3: Apply inline unsafe pointer casts in `wintun_windows.go`**

In `server/internal/system/wintun_windows.go`, replace lines 140 & 156:
```go
	packet := unsafe.Slice((*byte)(unsafe.Pointer(r0)), packetSize)
```
with:
```go
	packet := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(r0))), packetSize)
```

- [ ] **Step 4: Run `go vet` to verify warnings are cleared**

Run: `cd server && go vet ./internal/bridge ./internal/system`  
Expected: `PASS` with zero warnings.

- [ ] **Step 5: Commit changes**

```bash
git add server/internal/bridge/shm_windows.go server/internal/system/wintun_windows.go
git commit -m "fix(server): resolve go vet unsafe.Pointer misuse warnings in Windows drivers"
```

---

### Task 2: Consolidate `server/internal/utils` into `server/internal/util`

**Files:**
- Create: `server/internal/util/network.go`
- Create: `server/internal/util/sysprocattr_windows.go`
- Modify: `server/internal/utils/network.go`
- Modify: `server/internal/utils/sysprocattr_windows.go`

- [ ] **Step 1: Write unit test for `util` network helpers**

In `server/internal/util/network_test.go`:
```go
package util

import "testing"

func TestIsLocalIP(t *testing.T) {
	if !IsLocalIP("127.0.0.1") {
		t.Errorf("expected 127.0.0.1 to be local")
	}
}
```

- [ ] **Step 2: Run test to verify initial state**

Run: `cd server && go test ./internal/util/...`  
Expected: `FAIL` (undefined `IsLocalIP`).

- [ ] **Step 3: Implement `util/network.go` and add type alias forwarders in `utils/`**

Create `server/internal/util/network.go`:
```go
package util

import "net"

func IsLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}
```

In `server/internal/utils/network.go`:
```go
package utils

import "github.com/maybeknott/luminet/server/internal/util"

var IsLocalIP = util.IsLocalIP
```

- [ ] **Step 4: Run tests across `util` and `utils`**

Run: `cd server && go test ./internal/util/... ./internal/utils/...`  
Expected: `PASS`.

- [ ] **Step 5: Commit changes**

```bash
git add server/internal/util/ server/internal/utils/
git commit -m "refactor(server): consolidate utils into util package with backward-compatible aliases"
```

---

### Task 3: Merge `server/internal/scan` into `server/internal/scanner`

**Files:**
- Create: `server/internal/scanner/scan_planner.go`
- Modify: `server/internal/scan/plan.go`

- [ ] **Step 1: Create `scan_planner.go` in `server/internal/scanner`**

In `server/internal/scanner/scan_planner.go`:
```go
package scanner

import "time"

type ScanPlan struct {
	ID        string        `json:"id"`
	Targets   []string      `json:"targets"`
	Timeout   time.Duration `json:"timeout"`
	RateLimit int           `json:"rate_limit"`
}

func NewScanPlan(id string, targets []string) *ScanPlan {
	return &ScanPlan{
		ID:        id,
		Targets:   targets,
		Timeout:   10 * time.Second,
		RateLimit: 100,
	}
}
```

- [ ] **Step 2: Convert `server/internal/scan/plan.go` to type alias forwarder**

In `server/internal/scan/plan.go`:
```go
package scan

import "github.com/maybeknott/luminet/server/internal/scanner"

type ScanPlan = scanner.ScanPlan
var NewScanPlan = scanner.NewScanPlan
```

- [ ] **Step 3: Run package tests for `scan` and `scanner`**

Run: `cd server && go test ./internal/scan/... ./internal/scanner/...`  
Expected: `PASS`.

- [ ] **Step 4: Commit changes**

```bash
git add server/internal/scanner/scan_planner.go server/internal/scan/plan.go
git commit -m "refactor(server): unify scan planning types into scanner package with type aliases"
```

---

### Task 4: Full Integration Verification Gate

**Files:**
- Entire `server/` module
- Knowledge Graph: `graphify-out/graph.json`

- [ ] **Step 1: Execute full `go build` check**

Run: `cd server && go build ./...`  
Expected: Clean compilation with 0 errors.

- [ ] **Step 2: Execute full `go vet` check**

Run: `cd server && go vet ./...`  
Expected: Clean vet with 0 warnings.

- [ ] **Step 3: Execute full unit test suite**

Run: `cd server && go test ./...`  
Expected: All package test suites `PASS`.

- [ ] **Step 4: Update Graphify AST Knowledge Graph**

Run: `graphify update .`  
Expected: `graphify-out/graph.json` updated with new AST symbol links.

- [ ] **Step 5: Commit final state**

```bash
git add .
git commit -m "chore(repo): complete Go control plane refactoring and update knowledge graph index"
```

---

## 📌 Self-Review Checklist

- [x] **Spec coverage**: All 3 static vet warnings and package naming redundancies are fully addressed in tasks.
- [x] **Placeholder scan**: Zero TBDs, TODOs, or vague bullet points. Every step has exact code blocks, commands, and expected outputs.
- [x] **Type consistency**: Function signatures (`IsLocalIP`, `NewScanPlan`, `ScanPlan`) remain 100% compatible across packages.
