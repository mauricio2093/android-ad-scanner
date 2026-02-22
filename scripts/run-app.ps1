#!/usr/bin/env pwsh
param(
    [switch]$Intel,
    [string]$VenvPath = ".venv",
    [string]$PythonCmd = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AppArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

$mainScript = if ($Intel) { "smart_intel_scan.py" } else { "adb_automation_tool.py" }

if (-not (Test-Path $mainScript)) {
    Fail "No se encontro el script: $mainScript"
}

$pythonBin = $null
if (-not [string]::IsNullOrWhiteSpace($PythonCmd)) {
    if (-not (Get-Command $PythonCmd -ErrorAction SilentlyContinue)) {
        Fail "No se encontro el comando Python: $PythonCmd"
    }
    $pythonBin = $PythonCmd
} else {
    $venvPython = Join-Path $VenvPath "Scripts/python.exe"
    if (Test-Path $venvPython) {
        $pythonBin = $venvPython
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonBin = "python"
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $pythonBin = "py"
    } else {
        Fail "No hay Python disponible (python o py)."
    }
}

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    Write-Warning "adb no esta en PATH. Algunas funciones pueden fallar."
}

$commandLine = "$pythonBin $mainScript"
if ($AppArgs.Count -gt 0) {
    $commandLine = "$commandLine $($AppArgs -join ' ')"
}
Write-Host "[INFO] Running: $commandLine" -ForegroundColor Cyan

& $pythonBin $mainScript @AppArgs
if ($LASTEXITCODE -ne 0) {
    Fail "La aplicacion termino con codigo $LASTEXITCODE"
}
