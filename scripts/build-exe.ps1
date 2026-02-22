#!/usr/bin/env pwsh
param(
    [string]$RepoPath = "",
    [string]$VenvPath = ".venv",
    [string]$PythonCmd = "",
    [ValidateSet("spec", "direct")]
    [string]$Mode = "spec",
    [string]$EntryScript = "adb_automation_tool.py",
    [string]$SpecFile = "adb_automation_tool.spec",
    [string]$Name = "adb_automation_tool",
    [string]$Icon = "",
    [switch]$OneDir,
    [switch]$Console,
    [switch]$Clean,
    [switch]$InstallPyInstaller,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Info([string]$Message) { Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Warn([string]$Message) { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Ok([string]$Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

function Test-PythonCommand([string]$CommandName) {
    try {
        & $CommandName -c "import sys" *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = if ([string]::IsNullOrWhiteSpace($RepoPath)) {
    Resolve-Path (Join-Path $scriptDir "..")
} else {
    Resolve-Path $RepoPath
}
$repoRoot = $repoRoot.Path

$entryPath = Join-Path $repoRoot $EntryScript
$specPath = Join-Path $repoRoot $SpecFile

if ($Mode -eq "spec") {
    if (-not (Test-Path $specPath)) {
        Fail "No se encontro spec: $specPath"
    }
} else {
    if (-not (Test-Path $entryPath)) {
        Fail "No se encontro entry script: $entryPath"
    }
    if (-not [string]::IsNullOrWhiteSpace($Icon)) {
        $iconCandidate = if (Test-Path $Icon) { $Icon } else { Join-Path $repoRoot $Icon }
        if (-not (Test-Path $iconCandidate)) {
            Fail "No se encontro icon: $Icon"
        }
        $Icon = (Resolve-Path $iconCandidate).Path
    }
}

$pythonBin = $null
if (-not [string]::IsNullOrWhiteSpace($PythonCmd)) {
    $hasPythonCmd = (Test-Path $PythonCmd) -or ($null -ne (Get-Command $PythonCmd -ErrorAction SilentlyContinue))
    if (-not $hasPythonCmd) {
        Fail "No se encontro el comando Python: $PythonCmd"
    }
    if (-not (Test-PythonCommand $PythonCmd)) {
        Fail "El comando Python indicado no se puede ejecutar: $PythonCmd"
    }
    $pythonBin = $PythonCmd
} else {
    $venvPython = Join-Path $repoRoot "$VenvPath/Scripts/python.exe"
    $pythonCandidates = @()
    if (Test-Path $venvPython) {
        $pythonCandidates += $venvPython
    }
    $pythonCandidates += @("py", "python", "python3")

    foreach ($candidate in $pythonCandidates) {
        $candidateExists = (Test-Path $candidate) -or ($null -ne (Get-Command $candidate -ErrorAction SilentlyContinue))
        if ($candidateExists -and (Test-PythonCommand $candidate)) {
            $pythonBin = $candidate
            break
        }
    }

    if ($null -eq $pythonBin) {
        Fail "No hay Python ejecutable. Instala Python o crea el venv en '$VenvPath'."
    }
}

$pyInstallerOk = $true
try {
    & $pythonBin -c "import PyInstaller,sys;print(PyInstaller.__version__)" *> $null
    if ($LASTEXITCODE -ne 0) { $pyInstallerOk = $false }
} catch {
    $pyInstallerOk = $false
}

if (-not $pyInstallerOk) {
    if ($InstallPyInstaller) {
        Info "Instalando/actualizando PyInstaller..."
        & $pythonBin -m pip install --upgrade pyinstaller
        if ($LASTEXITCODE -ne 0) {
            Fail "No se pudo instalar PyInstaller."
        }
    } else {
        Fail "PyInstaller no esta disponible. Ejecuta '.\build-exe -InstallPyInstaller' o instala manualmente con '$pythonBin -m pip install --upgrade pyinstaller'."
    }
}

$pyVersion = (& $pythonBin -c "import sys;print(sys.version.split()[0])").Trim()
$pyInstallerVersion = (& $pythonBin -c "import PyInstaller;print(PyInstaller.__version__)").Trim()

Write-Host ""
Write-Host "[PRE-FLIGHT BUILD]" -ForegroundColor DarkGray
Write-Host "Repo: $repoRoot"
Write-Host "Python: $pythonBin (v$pyVersion)"
Write-Host "PyInstaller: $pyInstallerVersion"
Write-Host "Mode: $Mode"
if ($Mode -eq "spec") {
    Write-Host "Spec: $SpecFile"
} else {
    $layout = if ($OneDir) { "onedir" } else { "onefile" }
    $consoleState = if ($Console) { "enabled" } else { "disabled" }
    Write-Host "Entry: $EntryScript"
    Write-Host "Name: $Name"
    Write-Host "Layout: $layout"
    Write-Host "Console: $consoleState"
}
Write-Host "Clean build dirs: $($Clean.IsPresent)"

if (-not $Yes) {
    $confirm = Read-Host "Continue build? [Y/n]"
    if ($confirm -match "^[Nn]$") {
        Warn "Build cancelado."
        exit 0
    }
}

if ($Clean) {
    Info "Limpiando build/ y dist/..."
    Remove-Item -Force -Recurse (Join-Path $repoRoot "build") -ErrorAction SilentlyContinue
    Remove-Item -Force -Recurse (Join-Path $repoRoot "dist") -ErrorAction SilentlyContinue
}

$pyArgs = @("-m", "PyInstaller", "--noconfirm")
if ($Clean) {
    $pyArgs += "--clean"
}

if ($Mode -eq "spec") {
    $pyArgs += $specPath
} else {
    if ($OneDir) {
        $pyArgs += "--onedir"
    } else {
        $pyArgs += "--onefile"
    }
    if ($Console) {
        $pyArgs += "--console"
    } else {
        $pyArgs += "--windowed"
    }
    $pyArgs += @("--name", $Name)
    if (-not [string]::IsNullOrWhiteSpace($Icon)) {
        $pyArgs += @("--icon", $Icon)
    }
    $pyArgs += $entryPath
}

Info "Ejecutando build..."
Push-Location $repoRoot
& $pythonBin @pyArgs
$exitCode = $LASTEXITCODE
Pop-Location

if ($exitCode -ne 0) {
    Fail "PyInstaller termino con codigo $exitCode."
}

$artifactCandidates = @(
    (Join-Path $repoRoot "dist/$Name.exe"),
    (Join-Path $repoRoot "dist/$Name"),
    (Join-Path $repoRoot "dist/$Name/$Name.exe"),
    (Join-Path $repoRoot "dist/adb_automation_tool.exe")
)
$artifact = $artifactCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($null -ne $artifact) {
    Ok "Build completado."
    Write-Host "Artifact: $artifact" -ForegroundColor Green
} else {
    Warn "Build finalizado, pero no se encontro artifact esperado."
    Warn "Revisa manualmente la carpeta dist/."
}
