#Requires -Version 5.1
<#
.SYNOPSIS
    LumiNet - Full Build Script (Windows)

.DESCRIPTION
    Builds the complete LumiNet application:
      Step 1: Build Rust core library (cargo build --release --locked --target x86_64-pc-windows-gnu)
      Step 2: Build the shared control UI
      Step 3: Build Go daemon + watchdog + desktop binaries

.EXAMPLE
    .\scripts\build-all.ps1
    .\scripts\build-all.ps1 -Configuration Debug
#>

[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [switch]$Gui
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Constants ──────────────────────────────────────────────────────────────
$RootDir    = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$CoreDir    = Join-Path $RootDir "src/packages/lumicore"
$ServerDir  = Join-Path $RootDir "src/apps/daemon"
$WebDir     = Join-Path $RootDir "src/packages/control-ui"
$DesktopDir = Join-Path $RootDir "src/apps/desktop"
$BuildDir   = Join-Path $RootDir "build"
$BinName    = "luminet.exe"
$LinkResolver = Join-Path $RootDir "scripts\checks\lumicore_link.py"

# -- Helpers ────────────────────────────────────────────────────────────────

function Write-StepHeader([string]$Tag, [string]$Message) {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor DarkGray
    Write-Host "  $Tag $Message" -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor DarkGray
}

function Write-Success([string]$Message) {
    Write-Host "  [+] $Message" -ForegroundColor Green
}

function Write-StepTime([System.Diagnostics.Stopwatch]$Timer) {
    $elapsed = $Timer.Elapsed
    Write-Host "  Elapsed: $($elapsed.TotalSeconds.ToString('F1'))s" -ForegroundColor DarkGray
}

function Assert-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "  [-] Required command not found: $Name" -ForegroundColor Red
        Write-Host "     Please install $Name and ensure it is on your PATH." -ForegroundColor Yellow
        exit 1
    }
}

function Invoke-Step([string]$Description, [scriptblock]$Action) {
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "Command exited with code $LASTEXITCODE"
        }
    }
    catch {
        Write-Host ""
        Write-Host "  [-] FAILED: $Description" -ForegroundColor Red
        Write-Host "     Error: $_" -ForegroundColor Red
        exit 1
    }
    finally {
        $timer.Stop()
        Write-StepTime $timer
    }
}

# -- Preamble ───────────────────────────────────────────────────────────────
$totalTimer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host ""
Write-Host "  LumiNet Build System" -ForegroundColor Magenta
Write-Host "     Configuration: $Configuration" -ForegroundColor DarkGray
Write-Host "     Platform:      Windows ($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor DarkGray
Write-Host ""

# -- Prerequisite Checks ───────────────────────────────────────────────────
Write-StepHeader "[*]" "Checking prerequisites..."
if (-not (Get-Command "gcc" -ErrorAction SilentlyContinue)) {
    $scoopMingw = Join-Path $env:USERPROFILE "scoop\apps\mingw\current\bin"
    if (Test-Path $scoopMingw) {
        $env:PATH = "$scoopMingw;$env:PATH"
    }
}
Assert-Command "cargo"
Assert-Command "go"
Assert-Command "gcc"
Assert-Command "npm"
Assert-Command "python"

Write-Success "All prerequisites found"

# -- Step 1: Build Rust Core ───────────────────────────────────────────────
Write-StepHeader "[1/3]" "Building Rust core library (GNU target)"
Invoke-Step "Rust build" {
    Push-Location $CoreDir
    try {
        $cargoArgs = @("build", "--locked", "--target", "x86_64-pc-windows-gnu")
        if ($Configuration -eq "Release") {
            $cargoArgs += "--release"
        }
        if ($PSBoundParameters.ContainsKey('Verbose')) {
            $cargoArgs += "--verbose"
        }
        
        # Try offline build first to avoid network delays / SSL timeouts
        Write-Host "  [*] Attempting offline Rust build..." -ForegroundColor Gray
        & cargo @($cargoArgs + "--offline")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [*] Offline build failed/cache missing. Retrying online..." -ForegroundColor Yellow
            & cargo @cargoArgs
        }

    }
    finally {
        Pop-Location
    }
}
Write-Success "Rust core library built"

# -- Step 2: Build Shared Control UI ───────────────────────────────────────
Write-StepHeader "[2/3]" "Building shared control UI"
Invoke-Step "Control UI build" {
    Push-Location $WebDir
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw "control UI build failed" }
    }
    finally {
        Pop-Location
    }
}
Write-Success "Control UI bundle built"

# -- Step 3: Build Go Host Products ────────────────────────────────────────
Write-StepHeader "[3/3]" "Building daemon, watchdog, and desktop"

# Ensure build directory exists
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

Invoke-Step "Go build" {
    Push-Location $ServerDir
    try {
        $env:CGO_ENABLED = "1"
        $linkProfile = if ($Configuration -eq "Release") { "release" } else { "debug" }
        $env:CGO_LDFLAGS = (& python $LinkResolver --profile $linkProfile --target "x86_64-pc-windows-gnu")
        if ($LASTEXITCODE -ne 0) { throw "LumiCore link resolution failed" }

        # Compute version info
        $version = "v0.0.0-dev"
        try { $version = (git describe --tags --always --dirty 2>$null) } catch {}
        $commit = "unknown"
        try { $commit = (git rev-parse HEAD 2>$null) } catch {}
        $buildDate = "unknown"
        try { $buildDate = (git show -s --format=%cI HEAD 2>$null) } catch {}
        $buildInfoPkg = "github.com/maybeknott/luminet/contracts/buildinfo"

        $ldflags = "-s -w -X $buildInfoPkg.Version=$version -X $buildInfoPkg.Commit=$commit -X $buildInfoPkg.BuildDate=$buildDate"
        if ($Gui) {
            $ldflags += " -H windowsgui"
        }
        $outPath = Join-Path $BuildDir $BinName
        $watchdogOutPath = Join-Path $BuildDir "watchdog.exe"

        & go build -trimpath -ldflags $ldflags -o $outPath .
        if ($LASTEXITCODE -ne 0) { throw "daemon build failed" }
        $env:CGO_ENABLED = "0"
        Remove-Item Env:CGO_LDFLAGS -ErrorAction SilentlyContinue
        & go build -trimpath -ldflags $ldflags -o $watchdogOutPath ./cmd/watchdog
        if ($LASTEXITCODE -ne 0) { throw "watchdog build failed" }
    }
    finally {
        Pop-Location
    }

    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_LDFLAGS -ErrorAction SilentlyContinue
    Push-Location $DesktopDir
    try {
        $desktopOutPath = Join-Path $BuildDir "luminet-desktop.exe"
        & go build -trimpath -o $desktopOutPath .
        if ($LASTEXITCODE -ne 0) { throw "desktop build failed" }
    }
    finally {
        Pop-Location
    }
}
Write-Success "Go daemon built: $BuildDir\$BinName"
Write-Success "Go watchdog built: $BuildDir\watchdog.exe"
Write-Success "Go desktop built: $BuildDir\luminet-desktop.exe"

# -- Summary ────────────────────────────────────────────────────────────────
$totalTimer.Stop()
$totalElapsed = $totalTimer.Elapsed

Write-Host ""
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
Write-Host "==============================================================" -ForegroundColor Green
Write-Host "  Binary:  $BuildDir\$BinName" -ForegroundColor White
Write-Host "  Config:  $Configuration" -ForegroundColor White
Write-Host "  Time:    $($totalElapsed.Minutes)m $($totalElapsed.Seconds)s" -ForegroundColor White
Write-Host ""
