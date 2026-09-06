#!/bin/bash
# LumiNet Native Mobile Library Compilation Orchestrator
#
# Binds the mobilebind wrapper package (NOT the raw proxy package)
# to produce the supported Android AAR artifact.

# Set error handling
set -e

# Resolve all outputs from the repository root so source-layout depth cannot
# redirect generated artifacts into src/.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/build/mobile"
APP_LIB_DIR="$ROOT_DIR/src/apps/android/app/libs"
mkdir -p "$OUT_DIR" "$APP_LIB_DIR"

echo "Checking requirements..."

# Check Go
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed or not in PATH."
    exit 1
fi

# Check gomobile
if ! command -v gomobile &> /dev/null; then
    echo "ERROR: gomobile is not installed or not in PATH."
    echo "Please run: go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20260709172247-6129f5bee9d5 && gomobile init"
    exit 1
fi

echo "Requirements check passed."
echo "Starting compilation..."

# Target the mobilebind wrapper package (gobind-compatible surface)
TARGET_PKG="github.com/maybeknott/luminet/internal/adapters/mobilebind"

# Android Build
echo "Building Android AAR library..."
cd "$ROOT_DIR/src/apps/daemon"
gomobile bind -v -androidapi 21 -ldflags="-s -w" -o "$OUT_DIR/luminet.aar" -javapkg=com.luminet -target=android "$TARGET_PKG"
cp "$OUT_DIR/luminet.aar" "$APP_LIB_DIR/luminet.aar"
echo "Android AAR compiled successfully: $OUT_DIR/luminet.aar"
echo "Android app dependency updated: $APP_LIB_DIR/luminet.aar"


# iOS is not a current shipped host. Future iOS delivery must add a real host,
# verification lane, and release artifact before reintroducing framework output.

echo "Mobile compilation batch completed successfully!"
