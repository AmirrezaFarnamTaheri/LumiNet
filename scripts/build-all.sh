#!/usr/bin/env bash
# ============================================================================
# LumiNet — Full Build Script (Linux / macOS)
# ============================================================================
#
# Usage:
#   ./scripts/build-all.sh              # Release build
#   ./scripts/build-all.sh --debug      # Debug build
#   ./scripts/build-all.sh --verbose    # Verbose output
# ============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
CONFIGURATION="release"
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)      CONFIGURATION="debug"; shift ;;
        --verbose)    VERBOSE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--debug] [--verbose]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$ROOT_DIR/src/packages/lumicore"
SERVER_DIR="$ROOT_DIR/src/apps/daemon"
WEB_DIR="$ROOT_DIR/src/packages/control-ui"
DESKTOP_DIR="$ROOT_DIR/src/apps/desktop"
BUILD_DIR="$ROOT_DIR/build"
BIN_NAME="luminet"
LINK_RESOLVER="$ROOT_DIR/scripts/checks/lumicore_link.py"

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helpers ────────────────────────────────────────────────────────────────

step_header() {
    local emoji="$1"
    local message="$2"
    echo ""
    echo -e "${DIM}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "  ${CYAN}${emoji} ${message}${RESET}"
    echo -e "${DIM}══════════════════════════════════════════════════════════════${RESET}"
}

success() {
    echo -e "  ${GREEN}✅ $1${RESET}"
}

fail() {
    echo -e "  ${RED}❌ FAILED: $1${RESET}"
    exit 1
}

assert_command() {
    if ! command -v "$1" &>/dev/null; then
        echo -e "  ${RED}❌ Required command not found: $1${RESET}"
        echo -e "     Please install $1 and ensure it is on your PATH."
        exit 1
    fi
}

elapsed_since() {
    local start="$1"
    local now
    now=$(date +%s)
    local diff=$((now - start))
    echo -e "  ${DIM}⏱  Completed in ${diff}s${RESET}"
}

# ── Determine shared library extension ─────────────────────────────────────
case "$(uname -s)" in
    Darwin*) SHARED_EXT=".dylib" ;;
    *)       SHARED_EXT=".so" ;;
esac

# ── Preamble ───────────────────────────────────────────────────────────────
TOTAL_START=$(date +%s)

echo ""
echo -e "  ${MAGENTA}🌐 LumiNet Build System${RESET}"
echo -e "     ${DIM}Configuration: ${CONFIGURATION}${RESET}"
echo -e "     ${DIM}Platform:      $(uname -s) ($(uname -m))${RESET}"
echo ""

# ── Prerequisite Checks ───────────────────────────────────────────────────
step_header "🔍" "Checking prerequisites..."
assert_command "cargo"
assert_command "go"
assert_command "python3"
assert_command "npm"
success "All prerequisites found"

# ── Step 1: Build Rust Core ───────────────────────────────────────────────
step_header "🦀" "Step 1/3 — Building Rust core library"
STEP_START=$(date +%s)

cargo_args=("build" "--locked")
if [ "$CONFIGURATION" = "release" ]; then
    cargo_args+=("--release")
fi
if [ "$VERBOSE" = true ]; then
    cargo_args+=("--verbose")
fi

(cd "$CORE_DIR" && cargo "${cargo_args[@]}") || fail "Rust build"
elapsed_since "$STEP_START"
success "Rust core library built"

# ── Step 2: Build Shared Control UI ───────────────────────────────────────
step_header "🌐" "Step 2/3 — Building shared control UI"
STEP_START=$(date +%s)
(cd "$WEB_DIR" && npm ci && npm run build) || fail "Control UI build"
elapsed_since "$STEP_START"
success "Control UI bundle built"

# ── Step 3: Build Go Host Products ────────────────────────────────────────
step_header "🐹" "Step 3/3 — Building daemon, watchdog, and desktop"
STEP_START=$(date +%s)

mkdir -p "$BUILD_DIR"

# Version info
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "v0.0.0-dev")
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(git show -s --format=%cI HEAD 2>/dev/null || echo "unknown")
BUILDINFO_PKG="github.com/maybeknott/luminet/contracts/buildinfo"

LDFLAGS="-s -w -X ${BUILDINFO_PKG}.Version=${VERSION} -X ${BUILDINFO_PKG}.Commit=${COMMIT} -X ${BUILDINFO_PKG}.BuildDate=${BUILD_DATE}"
LUMICORE_LDFLAGS=$(python3 "$LINK_RESOLVER" --profile "$CONFIGURATION") || fail "LumiCore link resolution"

(cd "$SERVER_DIR" && \
    CGO_ENABLED=1 CGO_LDFLAGS="$LUMICORE_LDFLAGS" go build \
        -trimpath \
        -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/$BIN_NAME" \
        .) \
    || fail "Go build"

(cd "$SERVER_DIR" && \
    CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags "$LDFLAGS" \
        -o "$BUILD_DIR/watchdog" \
        ./cmd/watchdog) \
    || fail "Go watchdog build"

(cd "$DESKTOP_DIR" && \
    go build \
        -trimpath \
        -o "$BUILD_DIR/luminet-desktop" \
        .) \
    || fail "Go desktop build"

elapsed_since "$STEP_START"
success "Go daemon built: $BUILD_DIR/$BIN_NAME"
success "Go watchdog built: $BUILD_DIR/watchdog"
success "Go desktop built: $BUILD_DIR/luminet-desktop"

# ── Summary ────────────────────────────────────────────────────────────────
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "  ${GREEN}🎉 BUILD SUCCESSFUL${RESET}"
echo -e "${GREEN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "  Binary:  $BUILD_DIR/$BIN_NAME"
echo -e "  Config:  $CONFIGURATION"
echo -e "  Time:    $((TOTAL_ELAPSED / 60))m $((TOTAL_ELAPSED % 60))s"
echo ""
