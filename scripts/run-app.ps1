#!/usr/bin/env pwsh
param(
    [switch]$Intel,
    [string]$VenvPath = ".venv",
    [string]$PythonCmd = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AppArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$mainScriptRel = if ($Intel) { "smart_intel_scan.py" } else { "adb_automation_tool.py" }
$mainScript = Join-Path $repoRoot $mainScriptRel

if (-not (Test-Path $mainScript)) {
    Fail "No se encontro el script: $mainScript"
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

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    Write-Warning "adb no esta en PATH. Algunas funciones pueden fallar."
}

$commandLine = "$pythonBin $mainScript"
$resolvedAppArgs = @()
if ($null -ne $AppArgs) {
    $resolvedAppArgs = @($AppArgs)
}

if ($resolvedAppArgs.Length -gt 0) {
    $commandLine = "$commandLine $($resolvedAppArgs -join ' ')"
}
Write-Host "[INFO] Repo root: $repoRoot" -ForegroundColor DarkCyan
Write-Host "[INFO] Running: $commandLine" -ForegroundColor Cyan

Push-Location $repoRoot
& $pythonBin $mainScript @resolvedAppArgs
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "La aplicacion termino con codigo $LASTEXITCODE"
}
Pop-Location
