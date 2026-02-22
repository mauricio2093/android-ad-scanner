#!/usr/bin/env pwsh
param(
    [string]$Version = "",
    [string]$Remote = "origin",
    [string]$Branch = "",
    [string]$RepoPath = "",
    [switch]$YesPull,
    [switch]$NoPull,
    [switch]$YesPush,
    [switch]$NoPush
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ColorSection = "Cyan"
$script:ColorInfo = "Blue"
$script:ColorWarn = "Yellow"
$script:ColorOk = "Green"
$script:ColorChoice = "Magenta"
$script:ColorDim = "DarkGray"

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "[$Title]" -ForegroundColor $script:ColorSection
}

function Write-InfoMsg([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor $script:ColorInfo
}

function Write-WarnMsg([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor $script:ColorWarn
}

function Write-OkMsg([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor $script:ColorOk
}

function Write-Choice([string]$Text) {
    Write-Host $Text -ForegroundColor $script:ColorChoice
}

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

function Ask-YesNo {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [bool]$DefaultYes = $true
    )

    $hint = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    while ($true) {
        $answer = Read-Host "$Prompt $hint"
        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $DefaultYes
        }

        switch ($answer.Trim().ToLowerInvariant()) {
            "y" { return $true }
            "yes" { return $true }
            "n" { return $false }
            "no" { return $false }
            default { Write-WarnMsg "Responde y/n" }
        }
    }
}

function Run-Git {
    param([Parameter(Mandatory = $true)][string[]]$Args)

    $output = & git @Args 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $joined = $Args -join " "
        Fail ("git $joined`n$output")
    }
    return $output
}

function Normalize-Tag([string]$InputVersion) {
    if ($InputVersion -notmatch '^(v)?\d+\.\d+\.\d+$') {
        return $null
    }
    if ($InputVersion.StartsWith("v")) {
        return $InputVersion
    }
    return "v$InputVersion"
}

function Get-NextPatchTag([string]$BaseTag) {
    if ($BaseTag -match '^(v)?(\d+)\.(\d+)\.(\d+)$') {
        $major = [int]$Matches[2]
        $minor = [int]$Matches[3]
        $patch = [int]$Matches[4] + 1
        return "v$major.$minor.$patch"
    }
    return "v0.0.1"
}

function Get-ChangedFiles {
    $lines = @(& git status --porcelain)
    $set = [System.Collections.Generic.HashSet[string]]::new()
    $files = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.Length -lt 4) {
            continue
        }

        $path = $line.Substring(3)
        if ($path -match ' -> ') {
            $path = ($path -split ' -> ')[-1]
        }

        if (-not [string]::IsNullOrWhiteSpace($path) -and $set.Add($path)) {
            [void]$files.Add($path)
        }
    }

    return @($files)
}

function Parse-Selection {
    param(
        [Parameter(Mandatory = $true)][string]$InputText,
        [Parameter(Mandatory = $true)][int]$MaxIndex
    )

    $selected = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($rawToken in ($InputText -split ',')) {
        $token = $rawToken.Trim()
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if ($token -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            if ($start -gt $end) {
                $temp = $start
                $start = $end
                $end = $temp
            }
            for ($i = $start; $i -le $end; $i++) {
                if ($i -ge 1 -and $i -le $MaxIndex) {
                    [void]$selected.Add($i)
                }
            }
            continue
        }

        if ($token -match '^\d+$') {
            $idx = [int]$token
            if ($idx -ge 1 -and $idx -le $MaxIndex) {
                [void]$selected.Add($idx)
            }
            continue
        }

        Write-WarnMsg "indice invalido: $token"
    }

    return @($selected | Sort-Object)
}

function Stage-BootstrapSelection {
    param(
        [Parameter(Mandatory = $true)][string]$Selection,
        [Parameter(Mandatory = $true)][string[]]$ChangedFiles
    )

    $selectedCount = 0
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($rawToken in ($Selection -split ",")) {
        $token = $rawToken.Trim()
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if ($token -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            if ($start -gt $end) {
                $temp = $start
                $start = $end
                $end = $temp
            }
            for ($i = $start; $i -le $end; $i++) {
                if ($i -ge 1 -and $i -le $ChangedFiles.Count -and $seen.Add($i)) {
                    Run-Git @("add", "-A", "--", $ChangedFiles[$i - 1]) | Out-Null
                    $selectedCount++
                }
            }
            continue
        }

        if ($token -match '^\d+$') {
            $idx = [int]$token
            if ($idx -ge 1 -and $idx -le $ChangedFiles.Count -and $seen.Add($idx)) {
                Run-Git @("add", "-A", "--", $ChangedFiles[$idx - 1]) | Out-Null
                $selectedCount++
            } else {
                Write-WarnMsg "indice invalido: $token"
            }
            continue
        }

        if (Test-Path $token) {
            Run-Git @("add", "-A", "--", $token) | Out-Null
            $selectedCount++
        } else {
            Write-WarnMsg "ruta no encontrada: $token"
        }
    }

    return $selectedCount
}

function Show-BootstrapStageMenu {
    while ($true) {
        Write-Section "FIRST COMMIT STAGING"
        Write-Choice "1) Stage all project files"
        if (Test-Path "README.md") {
            Write-Choice "2) Stage only README.md"
        } else {
            Write-Choice "2) Stage only README.md (not found)"
        }
        Write-Choice "3) Select specific files/folders"
        Write-Choice "4) Cancel bootstrap"

        $choice = (Read-Host "Choose option [1/2/3/4]").Trim()
        switch ($choice) {
            "1" {
                Run-Git @("add", "-A") | Out-Null
            }
            "2" {
                if (Test-Path "README.md") {
                    Run-Git @("add", "README.md") | Out-Null
                } else {
                    Write-WarnMsg "README.md no existe"
                    continue
                }
            }
            "3" {
                $changed = @(Get-ChangedFiles)
                if ($changed.Count -eq 0) {
                    Write-WarnMsg "no hay archivos pendientes para seleccionar"
                    continue
                }
                Write-Host "Archivos detectados:" -ForegroundColor $script:ColorDim
                for ($i = 0; $i -lt $changed.Count; $i++) {
                    "{0,3}) {1}" -f ($i + 1), $changed[$i] | Write-Host
                }
                $selection = Read-Host "Select indexes/ranges and/or paths (example: 1,3-5,src,README.md)"
                $count = Stage-BootstrapSelection -Selection $selection -ChangedFiles $changed
                if ($count -eq 0) {
                    Write-WarnMsg "no se seleccionaron rutas validas"
                    continue
                }
            }
            "4" {
                Write-WarnMsg "bootstrap cancelado por usuario"
                return $false
            }
            default {
                Write-WarnMsg "opcion invalida"
                continue
            }
        }

        & git diff --cached --quiet
        if ($LASTEXITCODE -eq 0) {
            Write-WarnMsg "no hay cambios staged aun"
            continue
        }

        Write-Section "FIRST COMMIT PREVIEW"
        & git diff --cached --name-status
        return $true
    }
}

function Update-RepoState {
    $script:upstream = ((& git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>$null) -join "`n").Trim()
    if (-not [string]::IsNullOrWhiteSpace($script:upstream)) {
        $script:ahead = [int](((Run-Git @("rev-list", "--count", "$script:upstream..HEAD")) -join "`n").Trim())
        $script:behind = [int](((Run-Git @("rev-list", "--count", "HEAD..$script:upstream")) -join "`n").Trim())
    } else {
        $script:ahead = 0
        $script:behind = 0
    }

    $script:stagedFiles = @(& git diff --cached --name-only | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $script:unstagedFiles = @(& git diff --name-only | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $script:untrackedFiles = @(& git ls-files --others --exclude-standard | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Show-DetailedStatus {
    Write-Section "DETAILED STATUS"
    Write-Host "Short status:" -ForegroundColor $script:ColorDim
    $statusShortLocal = @(& git status --short)
    if ($statusShortLocal.Count -gt 0) {
        $statusShortLocal | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "  clean"
    }

    if ($script:stagedFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "Staged diff:" -ForegroundColor $script:ColorDim
        & git diff --cached --name-status
    }

    if ($script:unstagedFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "Unstaged diff:" -ForegroundColor $script:ColorDim
        & git diff --name-status
    }

    if ($script:untrackedFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "Untracked files:" -ForegroundColor $script:ColorDim
        $script:untrackedFiles | ForEach-Object { Write-Host "?? $_" }
    }

    if (-not [string]::IsNullOrWhiteSpace($script:upstream) -and $script:ahead -gt 0) {
        Write-Host ""
        Write-Host "Local commits not pushed:"
        & git --no-pager log --oneline "$script:upstream..HEAD"
    }
}

function Show-PreflightMenu {
    Write-Section "PRE-FLIGHT CONTROL CENTER"
    Write-Choice "1) Continue workflow"
    Write-Choice "2) Show detailed status report"
    Write-Choice "3) Reset staged index (unstage all)"
    Write-Choice "4) Soft reset last local commit (HEAD~1, keep staged)"
    Write-Choice "5) Mixed reset last local commit (HEAD~1, keep unstaged)"
    Write-Choice "6) Cancel flow"
    Write-Host "Choose an option. Tip: use 2 to inspect, then 1 to continue." -ForegroundColor $script:ColorDim
}

function Read-NonEmptyOrDefault {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [string]$DefaultValue = ""
    )

    while ($true) {
        if ([string]::IsNullOrWhiteSpace($DefaultValue)) {
            $value = (Read-Host $Prompt).Trim()
        } else {
            $value = (Read-Host "$Prompt [$DefaultValue]").Trim()
            if ([string]::IsNullOrWhiteSpace($value)) {
                $value = $DefaultValue
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }
}

function Test-HasCommits {
    & git rev-parse --verify HEAD *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-CurrentBranchName {
    $branch = ((& git symbolic-ref --quiet --short HEAD 2>$null) -join "`n").Trim()
    if (-not [string]::IsNullOrWhiteSpace($branch)) {
        return $branch
    }
    $branch = ((& git rev-parse --abbrev-ref HEAD 2>$null) -join "`n").Trim()
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($branch) -and $branch -ne "HEAD") {
        return $branch
    }
    return ""
}

function Ensure-GitIdentity {
    $gitName = ((& git config --get user.name 2>$null) -join "`n").Trim()
    $gitEmail = ((& git config --get user.email 2>$null) -join "`n").Trim()

    if (-not [string]::IsNullOrWhiteSpace($gitName) -and -not [string]::IsNullOrWhiteSpace($gitEmail)) {
        return
    }

    Write-Section "GIT IDENTITY SETUP"
    Write-WarnMsg "git user.name / user.email no estan configurados para este repositorio."

    if ([string]::IsNullOrWhiteSpace($gitName)) {
        $gitName = Read-NonEmptyOrDefault -Prompt "Git user.name (local repo)"
        Run-Git @("config", "user.name", $gitName) | Out-Null
        Write-OkMsg "configurado user.name=$gitName"
    }

    if ([string]::IsNullOrWhiteSpace($gitEmail)) {
        $gitEmail = Read-NonEmptyOrDefault -Prompt "Git user.email (local repo)"
        Run-Git @("config", "user.email", $gitEmail) | Out-Null
        Write-OkMsg "configurado user.email=$gitEmail"
    }
}

function Resolve-RepoRoot([string]$PreferredPath) {
    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        [void]$candidates.Add($PreferredPath)
    }

    [void]$candidates.Add((Get-Location).Path)

    $scriptDir = Split-Path -Parent $PSCommandPath
    if (-not [string]::IsNullOrWhiteSpace($scriptDir)) {
        [void]$candidates.Add($scriptDir)
        $parent1 = Split-Path -Parent $scriptDir
        if (-not [string]::IsNullOrWhiteSpace($parent1)) {
            [void]$candidates.Add($parent1)
            $parent2 = Split-Path -Parent $parent1
            if (-not [string]::IsNullOrWhiteSpace($parent2)) {
                [void]$candidates.Add($parent2)
            }
        }
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($candidate) -or -not (Test-Path $candidate)) {
            continue
        }
        $root = ((& git -C $candidate rev-parse --show-toplevel 2>$null) -join "`n").Trim()
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($root)) {
            return $root
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
        Write-WarnMsg "No se pudo usar -RepoPath '$PreferredPath'."
    } else {
        Write-WarnMsg "No se detecto repositorio Git en el directorio actual."
    }

    $initTarget = if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) { $PreferredPath } else { (Get-Location).Path }
    $shouldInit = Ask-YesNo -Prompt "Quieres ejecutar git init en '$initTarget'?" -DefaultYes $true
    if ($shouldInit) {
        if (-not (Test-Path $initTarget)) {
            $createDir = Ask-YesNo -Prompt "La ruta no existe. Crear carpeta '$initTarget'?" -DefaultYes $true
            if (-not $createDir) {
                Fail "No se puede continuar sin una ruta valida."
            }
            New-Item -ItemType Directory -Path $initTarget -Force | Out-Null
        }
        & git -C $initTarget init
        if ($LASTEXITCODE -eq 0) {
            $root = ((& git -C $initTarget rev-parse --show-toplevel 2>$null) -join "`n").Trim()
            if (-not [string]::IsNullOrWhiteSpace($root)) {
                Write-OkMsg "Repositorio inicializado en $root"
                return $root
            }
        }
        Write-WarnMsg "No se pudo inicializar repositorio en '$initTarget'."
    }

    for ($i = 0; $i -lt 3; $i++) {
        $manualPath = (Read-Host "Ingresa ruta del repositorio Git (o q para cancelar)").Trim()
        if ([string]::IsNullOrWhiteSpace($manualPath)) {
            continue
        }
        if ($manualPath.ToLowerInvariant() -eq "q") {
            break
        }
        if (-not (Test-Path $manualPath)) {
            Write-WarnMsg "La ruta no existe: $manualPath"
            continue
        }
        $root = ((& git -C $manualPath rev-parse --show-toplevel 2>$null) -join "`n").Trim()
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($root)) {
            return $root
        }
        Write-WarnMsg "La ruta no es un repositorio Git: $manualPath"
    }

    return $null
}

function Ensure-FirstCommit {
    param(
        [ref]$BranchRef,
        [ref]$RemoteRef
    )

    if (Test-HasCommits) {
        return
    }

    Write-Section "REPOSITORY BOOTSTRAP"
    Write-WarnMsg "Este repositorio no tiene commits aun (HEAD inexistente)."

    $bootstrap = Ask-YesNo -Prompt "Quieres crear bootstrap inicial (README + first commit + branch main)?" -DefaultYes $true
    if (-not $bootstrap) {
        Fail "No se puede continuar sin un commit inicial."
    }

    if (-not (Test-Path "README.md")) {
        $defaultTitle = Split-Path -Leaf (Get-Location).Path
        if ([string]::IsNullOrWhiteSpace($defaultTitle)) {
            $defaultTitle = "New-Repository"
        }
        $projectTitle = Read-NonEmptyOrDefault -Prompt "Titulo para README" -DefaultValue $defaultTitle
        Set-Content -Path "README.md" -Value "# $projectTitle`n" -Encoding utf8
        Write-OkMsg "README.md creado"
    }

    $stagingOk = Show-BootstrapStageMenu
    if (-not $stagingOk) {
        Fail "Bootstrap cancelado por usuario."
    }

    & git diff --cached --quiet
    if ($LASTEXITCODE -eq 0) {
        Fail "No hay cambios staged para crear el primer commit."
    }

    $firstCommitMsg = Read-NonEmptyOrDefault -Prompt "Mensaje de primer commit" -DefaultValue "first commit"
    Run-Git @("commit", "-m", $firstCommitMsg) | Out-Null
    Write-OkMsg "Primer commit creado"

    $defaultBranch = if ([string]::IsNullOrWhiteSpace($BranchRef.Value)) { "main" } else { $BranchRef.Value }
    $targetBranch = Read-NonEmptyOrDefault -Prompt "Nombre de rama principal" -DefaultValue $defaultBranch
    Run-Git @("branch", "-M", $targetBranch) | Out-Null
    $BranchRef.Value = $targetBranch
    Write-OkMsg "Rama actual: $targetBranch"

    & git remote get-url $RemoteRef.Value *> $null
    if ($LASTEXITCODE -ne 0) {
        $configureRemote = Ask-YesNo -Prompt "Quieres configurar remote '$($RemoteRef.Value)' ahora?" -DefaultYes $true
        if ($configureRemote) {
            $remoteUrl = Read-NonEmptyOrDefault -Prompt "URL remota (https://github.com/usuario/repo.git)"
            & git remote get-url $RemoteRef.Value *> $null
            if ($LASTEXITCODE -eq 0) {
                Run-Git @("remote", "set-url", $RemoteRef.Value, $remoteUrl) | Out-Null
            } else {
                Run-Git @("remote", "add", $RemoteRef.Value, $remoteUrl) | Out-Null
            }
            Write-OkMsg "Remote '$($RemoteRef.Value)' configurado"

            $pushNow = Ask-YesNo -Prompt "Quieres hacer push inicial ahora?" -DefaultYes $true
            if ($pushNow) {
                Run-Git @("push", "-u", $RemoteRef.Value, $BranchRef.Value) | Out-Null
                Write-OkMsg "Push inicial completado"
            }
        } else {
            Write-WarnMsg "Sin remote configurado por ahora. Se omitiran pull/push remotos."
            $RemoteRef.Value = ""
        }
    }
}

function Normalize-Scope([string]$RawScope) {
    $scope = $RawScope.ToLowerInvariant()
    $scope = [regex]::Replace($scope, '[^a-z0-9._-]+', '-')
    $scope = $scope.Trim('-')
    if ([string]::IsNullOrWhiteSpace($scope) -or $scope -eq "root") {
        return ""
    }
    return $scope
}

function Format-CommitMessage([string]$Type, [string]$Scope, [string]$Subject) {
    if ([string]::IsNullOrWhiteSpace($Scope)) {
        return "${Type}: $Subject"
    }
    return "${Type}(${Scope}): $Subject"
}

function Get-SubjectForType([string]$Type, [string]$Base) {
    switch ($Type) {
        "feat" { return "add $Base improvements" }
        "fix" { return "fix issues in $Base" }
        "chore" { return "update $Base" }
        "refactor" { return "refactor $Base" }
        "docs" { return "update $Base" }
        "test" { return "improve $Base coverage" }
        default { return "update $Base" }
    }
}

function Get-CommitSuggestions {
    $entries = @(& git diff --cached --name-status)
    $dirCount = @{}
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $suggestions = New-Object System.Collections.Generic.List[string]

    $hasDocs = $false
    $hasTests = $false
    $hasScripts = $false
    $hasPython = $false
    $hasConfig = $false
    $hasData = $false
    $hasCi = $false

    $added = 0
    $modified = 0
    $deleted = 0
    $renamed = 0

    foreach ($line in $entries) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = $line -split "`t"
        if ($parts.Count -lt 2) {
            continue
        }

        $status = $parts[0]
        $code = $status.Substring(0, 1)
        switch ($code) {
            "A" { $added++ }
            "M" { $modified++ }
            "D" { $deleted++ }
            "R" { $renamed++ }
            default { $modified++ }
        }

        $file = if (($code -eq "R" -or $code -eq "C") -and $parts.Count -ge 3) { $parts[2] } else { $parts[1] }
        if ([string]::IsNullOrWhiteSpace($file)) {
            continue
        }

        $top = if ($file.Contains("/")) { $file.Split("/")[0] } else { "root" }
        if (-not $dirCount.ContainsKey($top)) {
            $dirCount[$top] = 0
        }
        $dirCount[$top]++

        $lower = $file.ToLowerInvariant()
        if ($lower -like "readme*" -or $lower -like "*.md" -or $lower -like "docs/*" -or $lower -like "md/*" -or $lower -like "*.rst" -or $lower -like "*.adoc") {
            $hasDocs = $true
        }
        if ($lower -like "scripts/*" -or $lower -like "*.sh" -or $lower -like "*.ps1" -or $lower -like "*.bat") {
            $hasScripts = $true
        }
        if ($lower -like "tests/*" -or $lower -like "test/*" -or $lower -like "*test*.py" -or $lower -like "*_test.py" -or $lower -like "test_*.py") {
            $hasTests = $true
        }
        if ($lower -like "*.py") {
            $hasPython = $true
        }
        if ($lower -like "config/*" -or $lower -like "*.json" -or $lower -like "*.yml" -or $lower -like "*.yaml" -or $lower -like "*.toml" -or $lower -like "*.ini" -or $lower -like "*.cfg" -or $lower -eq "pyproject.toml" -or $lower -eq "requirements.txt") {
            $hasConfig = $true
        }
        if ($lower -like "data/*") {
            $hasData = $true
        }
        if ($lower -like ".github/*") {
            $hasCi = $true
        }
    }

    $scopeRaw = "repo"
    $max = -1
    foreach ($key in $dirCount.Keys) {
        if ($dirCount[$key] -gt $max) {
            $max = $dirCount[$key]
            $scopeRaw = $key
        }
    }
    $scope = Normalize-Scope -RawScope $scopeRaw

    $docsOnly = $hasDocs -and -not ($hasTests -or $hasScripts -or $hasPython -or $hasConfig -or $hasData -or $hasCi)
    $testsOnly = $hasTests -and -not ($hasDocs -or $hasScripts -or $hasPython -or $hasConfig -or $hasData -or $hasCi)
    $scriptsOnly = $hasScripts -and -not ($hasDocs -or $hasTests -or $hasPython -or $hasConfig -or $hasData -or $hasCi)
    $configOnly = $hasConfig -and -not ($hasDocs -or $hasTests -or $hasScripts -or $hasPython -or $hasData -or $hasCi)

    $base = "project files"
    $typeOrder = @("chore", "feat", "fix")
    if ($docsOnly) {
        $base = "project documentation"
        $typeOrder = @("docs", "chore", "fix")
    } elseif ($testsOnly) {
        $base = "test suite"
        $typeOrder = @("test", "chore", "fix")
    } elseif ($scriptsOnly) {
        $base = "release automation scripts"
        $typeOrder = @("chore", "fix", "feat")
    } elseif ($hasPython -and $hasTests) {
        $base = "scanner workflows and tests"
        $typeOrder = @("feat", "fix", "refactor")
    } elseif ($hasPython) {
        $base = "scanner workflows"
        $typeOrder = @("feat", "fix", "refactor")
    } elseif ($configOnly) {
        $base = "project configuration"
        $typeOrder = @("chore", "fix", "docs")
    } elseif ($hasScripts -and $hasDocs) {
        $base = "release automation and documentation"
        $typeOrder = @("chore", "docs", "fix")
    } elseif ($hasData) {
        $base = "intel datasets"
        $typeOrder = @("chore", "feat", "fix")
    } elseif ($hasCi) {
        $base = "ci pipeline"
        $typeOrder = @("chore", "fix", "refactor")
    }

    if ($deleted -gt 0 -and $added -eq 0 -and $modified -eq 0 -and $renamed -eq 0) {
        $typeOrder = @("chore", "refactor", "fix")
    }

    foreach ($type in $typeOrder) {
        $subject = Get-SubjectForType -Type $type -Base $base
        $message = Format-CommitMessage -Type $type -Scope $scope -Subject $subject
        if ($seen.Add($message)) {
            [void]$suggestions.Add($message)
        }
    }

    foreach ($type in @("chore", "fix", "feat", "refactor", "docs", "test")) {
        if ($suggestions.Count -ge 3) {
            break
        }
        $subject = Get-SubjectForType -Type $type -Base $base
        $message = Format-CommitMessage -Type $type -Scope $scope -Subject $subject
        if ($seen.Add($message)) {
            [void]$suggestions.Add($message)
        }
    }

    return @($suggestions)
}

if ($YesPull -and $NoPull) {
    Fail "No puedes usar -YesPull y -NoPull al mismo tiempo."
}
if ($YesPush -and $NoPush) {
    Fail "No puedes usar -YesPush y -NoPush al mismo tiempo."
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail "git no esta instalado o no esta en PATH."
}

$repoRoot = Resolve-RepoRoot -PreferredPath $RepoPath
if ([string]::IsNullOrWhiteSpace($repoRoot)) {
    Fail "No se encontro un repositorio Git valido."
}
Set-Location $repoRoot

Ensure-GitIdentity
Ensure-FirstCommit -BranchRef ([ref]$Branch) -RemoteRef ([ref]$Remote)

if ([string]::IsNullOrWhiteSpace($Branch)) {
    $Branch = Get-CurrentBranchName
}
if ([string]::IsNullOrWhiteSpace($Branch) -or $Branch -eq "HEAD") {
    Fail "HEAD detached. Usa -Branch <nombre>."
}

$hasRemote = $false
if (-not [string]::IsNullOrWhiteSpace($Remote)) {
    & git remote get-url $Remote *> $null
    if ($LASTEXITCODE -eq 0) {
        $hasRemote = $true
    } else {
        $fallbackRemote = ((& git remote | Select-Object -First 1) -join "`n").Trim()
        if (-not [string]::IsNullOrWhiteSpace($fallbackRemote)) {
            Write-WarnMsg "remote '$Remote' no encontrado. Usando '$fallbackRemote'"
            $Remote = $fallbackRemote
            $hasRemote = $true
        }
    }
}

if (-not $hasRemote) {
    $configureRemoteNow = Ask-YesNo -Prompt "No hay remote activo. Configurar remote origin ahora?" -DefaultYes $true
    if ($configureRemoteNow) {
        $Remote = if ([string]::IsNullOrWhiteSpace($Remote)) { "origin" } else { $Remote }
        $remoteUrl = Read-NonEmptyOrDefault -Prompt "URL remota (https://github.com/usuario/repo.git)"
        & git remote get-url $Remote *> $null
        if ($LASTEXITCODE -eq 0) {
            Run-Git @("remote", "set-url", $Remote, $remoteUrl) | Out-Null
        } else {
            Run-Git @("remote", "add", $Remote, $remoteUrl) | Out-Null
        }
        $hasRemote = $true
        Write-OkMsg "Remote '$Remote' configurado"
    } else {
        Write-WarnMsg "Continuaremos sin remote. Se omitiran operaciones remotas."
        $Remote = ""
    }
}

Update-RepoState

Write-Section "REPO STATUS"
Write-Host "Repo: $repoRoot"
Write-Host "Branch: $Branch"
Write-Host ("Remote: " + $(if ([string]::IsNullOrWhiteSpace($Remote)) { "(none)" } else { $Remote }))
if (-not [string]::IsNullOrWhiteSpace($upstream)) {
    Write-Host "Upstream: $upstream (ahead=$ahead, behind=$behind)"
} else {
    Write-Host "Upstream: not configured"
}

Write-Section "PRE-PULL CHECK"
Write-Host "Staged files: $($stagedFiles.Count)"
Write-Host "Unstaged files: $($unstagedFiles.Count)"
Write-Host "Untracked files: $($untrackedFiles.Count)"
if ($ahead -gt 0) {
    Write-WarnMsg "Local commits not pushed: $ahead"
    & git --no-pager log --oneline "$upstream..HEAD"
}

$preflightDone = $false
while (-not $preflightDone) {
    Show-PreflightMenu
    $preflightChoice = (Read-Host "Choose option [1/2/3/4/5/6]").Trim()
    switch ($preflightChoice) {
        "1" {
            $preflightDone = $true
            continue
        }
        "2" {
            Show-DetailedStatus
            Write-InfoMsg "status report completed. Returning to pre-flight menu."
            continue
        }
        "3" {
            & git restore --staged . *> $null
            if ($LASTEXITCODE -ne 0) {
                Run-Git @("reset", "HEAD", ".") | Out-Null
            }
            Update-RepoState
            Write-OkMsg "index reset (files remain in working tree)."
            Write-InfoMsg "review the menu again and choose next action."
            continue
        }
        "4" {
            & git rev-parse --verify HEAD~1 *> $null
            if ($LASTEXITCODE -ne 0) {
                Write-WarnMsg "cannot reset: repository has no parent commit from HEAD"
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace($upstream) -and $ahead -eq 0) {
                Write-WarnMsg "no local commits pending push. Reset blocked to avoid rewriting published history."
                continue
            }
            if ([string]::IsNullOrWhiteSpace($upstream)) {
                $unknownReset = Ask-YesNo -Prompt "No upstream configured. Cannot verify if commit is published. Continue anyway?" -DefaultYes $false
                if (-not $unknownReset) {
                    Write-InfoMsg "reset skipped"
                    continue
                }
            }
            Write-Host ("Last commit: " + ((& git --no-pager log --oneline -1) -join "`n"))
            $confirmSoft = Ask-YesNo -Prompt "Apply SOFT reset HEAD~1?" -DefaultYes $false
            if ($confirmSoft) {
                Run-Git @("reset", "--soft", "HEAD~1") | Out-Null
                Update-RepoState
                Write-OkMsg "soft reset applied"
                Write-InfoMsg "review the menu again and choose next action."
            } else {
                Write-InfoMsg "soft reset skipped"
            }
            continue
        }
        "5" {
            & git rev-parse --verify HEAD~1 *> $null
            if ($LASTEXITCODE -ne 0) {
                Write-WarnMsg "cannot reset: repository has no parent commit from HEAD"
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace($upstream) -and $ahead -eq 0) {
                Write-WarnMsg "no local commits pending push. Reset blocked to avoid rewriting published history."
                continue
            }
            if ([string]::IsNullOrWhiteSpace($upstream)) {
                $unknownReset = Ask-YesNo -Prompt "No upstream configured. Cannot verify if commit is published. Continue anyway?" -DefaultYes $false
                if (-not $unknownReset) {
                    Write-InfoMsg "reset skipped"
                    continue
                }
            }
            Write-Host ("Last commit: " + ((& git --no-pager log --oneline -1) -join "`n"))
            $confirmMixed = Ask-YesNo -Prompt "Apply MIXED reset HEAD~1?" -DefaultYes $false
            if ($confirmMixed) {
                Run-Git @("reset", "--mixed", "HEAD~1") | Out-Null
                Update-RepoState
                Write-OkMsg "mixed reset applied"
                Write-InfoMsg "review the menu again and choose next action."
            } else {
                Write-InfoMsg "mixed reset skipped"
            }
            continue
        }
        "6" {
            Fail "Proceso cancelado por usuario."
        }
        default {
            Write-WarnMsg "opcion invalida"
            continue
        }
    }
}

$performPull = $false
if ([string]::IsNullOrWhiteSpace($Remote)) {
    Write-InfoMsg "Pull remoto omitido (no hay remote configurado)."
} else {
    $performPull = if ($YesPull) {
        $true
    } elseif ($NoPull) {
        $false
    } else {
        Ask-YesNo -Prompt "Quieres hacer pull --rebase desde $Remote/$Branch antes del release?" -DefaultYes $true
    }
}

if ($performPull) {
    $stashUsed = $false
    $dirtyBeforePull = @(& git status --porcelain)
    if ($dirtyBeforePull.Count -gt 0) {
        Write-WarnMsg "Hay cambios locales antes del pull."
        $stashAnswer = Ask-YesNo -Prompt "Aplicar auto-stash (solo tracked), sync y luego pop?" -DefaultYes $false
        if ($stashAnswer) {
            Run-Git @("stash", "push", "-m", ("release-tag auto-stash " + (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))) | Out-Null
            $stashUsed = $true
            Write-OkMsg "cambios stasheados temporalmente"
        } else {
            Write-InfoMsg "Pull omitido por decision del usuario."
            $performPull = $false
        }
    }

    if ($performPull) {
        Write-InfoMsg "Sincronizando con fetch + rebase..."
        Run-Git @("fetch", $Remote, ("refs/heads/${Branch}:refs/remotes/$Remote/$Branch")) | Out-Null
        Run-Git @("rebase", ("refs/remotes/$Remote/$Branch")) | Out-Null
        Write-OkMsg "sync completado"

        if ($stashUsed) {
            Write-InfoMsg "Restaurando stash..."
            Run-Git @("stash", "pop") | Out-Null
            Write-OkMsg "stash restaurado"
        }
    }
}

Write-Section "LOCAL MODIFIED FILES"
$statusShort = @(& git status --short)
if ($statusShort.Count -gt 0) {
    $statusShort | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "Working tree clean."
}

$changedFiles = @(Get-ChangedFiles)
if ($changedFiles.Count -gt 0) {
    Write-Section "STAGE FILES"
    Write-Choice "1) Add all changes"
    Write-Choice "2) Select files by number"
    Write-Choice "3) Skip staging"

    $stageDone = $false
    while (-not $stageDone) {
        $stageChoice = (Read-Host "Choose option [1/2/3]").Trim()
        switch ($stageChoice) {
            "1" {
                Run-Git @("add", "-A") | Out-Null
                Write-OkMsg "all files staged"
                $stageDone = $true
                continue
            }
            "2" {
                Write-Host ""
                for ($i = 0; $i -lt $changedFiles.Count; $i++) {
                    "{0,3}) {1}" -f ($i + 1), $changedFiles[$i] | Write-Host
                }
                Write-Host ""
                $selectionText = Read-Host "Enter indexes (example: 1,3-5)"
                $selectedIndexes = @(Parse-Selection -InputText $selectionText -MaxIndex $changedFiles.Count)
                if ($selectedIndexes.Count -eq 0) {
                    Write-WarnMsg "no valid indexes selected"
                    continue
                }
                foreach ($idx in $selectedIndexes) {
                    $path = $changedFiles[$idx - 1]
                    Run-Git @("add", "-A", "--", $path) | Out-Null
                }
                Write-OkMsg "selected files staged"
                $stageDone = $true
                continue
            }
            "3" {
                Write-InfoMsg "staging skipped"
                $stageDone = $true
                continue
            }
            default {
                Write-WarnMsg "opcion invalida"
            }
        }
    }
}

& git diff --cached --quiet
$hasStaged = ($LASTEXITCODE -ne 0)
if ($hasStaged) {
    Write-Section "STAGED CHANGES"
    & git diff --cached --name-status

    $commitMessage = ""
    while ([string]::IsNullOrWhiteSpace($commitMessage)) {
        $suggestions = @(Get-CommitSuggestions)
        if ($suggestions.Count -lt 3) {
            $suggestions = @("chore: update project files", "fix: resolve pending issues", "feat: add project improvements")
        }

        Write-Section "COMMIT MESSAGE"
        Write-Host "Auto-suggestions (heuristic, no AI):" -ForegroundColor $script:ColorDim
        Write-Choice ("1) " + $suggestions[0])
        Write-Choice ("2) " + $suggestions[1])
        Write-Choice ("3) " + $suggestions[2])
        Write-Choice "4) Write custom message"
        Write-Choice "5) Refresh suggestions"

        $commitChoice = (Read-Host "Choose option [1/2/3/4/5]").Trim()
        switch ($commitChoice) {
            "1" {
                $commitMessage = $suggestions[0]
                Write-InfoMsg "selected: $commitMessage"
            }
            "2" {
                $commitMessage = $suggestions[1]
                Write-InfoMsg "selected: $commitMessage"
            }
            "3" {
                $commitMessage = $suggestions[2]
                Write-InfoMsg "selected: $commitMessage"
            }
            "4" {
                $commitMessage = Read-Host "Write commit message"
            }
            "5" {
                Write-InfoMsg "refreshing suggestions..."
            }
            default {
                Write-WarnMsg "opcion invalida"
            }
        }
    }

    Run-Git @("commit", "-m", $commitMessage) | Out-Null
    Write-OkMsg "commit created"
} else {
    Write-InfoMsg "no staged changes to commit"
}

$upstream = ((& git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>$null) -join "`n").Trim()
Write-Section "COMMITS NOT PUSHED"
if (-not [string]::IsNullOrWhiteSpace($upstream)) {
    $ahead = [int](((Run-Git @("rev-list", "--count", "$upstream..HEAD")) -join "`n").Trim())
    if ($ahead -gt 0) {
        Write-InfoMsg "You have $ahead commit(s) pending push:"
        & git --no-pager log --oneline "$upstream..HEAD"
    } else {
        Write-InfoMsg "No local commits pending push."
    }
} else {
    Write-WarnMsg "No upstream tracking branch configured."
}

if (-not [string]::IsNullOrWhiteSpace($Remote)) {
    & git fetch --tags $Remote *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-InfoMsg "tags updated from $Remote"
    } else {
        Write-WarnMsg "could not fetch tags from $Remote. Using local tags only."
    }
} else {
    Write-InfoMsg "fetch de tags remoto omitido (sin remote)."
}

$latestTag = ((& git tag --list "v*" --sort=-version:refname | Select-Object -First 1) -join "`n").Trim()
if ([string]::IsNullOrWhiteSpace($latestTag)) {
    $latestTag = ((& git tag --sort=-creatordate | Select-Object -First 1) -join "`n").Trim()
}

if ([string]::IsNullOrWhiteSpace($latestTag)) {
    $range = "HEAD"
    Write-InfoMsg "no previous tags found"
} else {
    $range = "$latestTag..HEAD"
    Write-InfoMsg "latest tag detected: $latestTag"
    $newCommitCount = [int](((Run-Git @("rev-list", "--count", $range)) -join "`n").Trim())
    if ($newCommitCount -eq 0) {
        Fail "No hay commits nuevos desde $latestTag"
    }
}

$releaseCommits = @(& git log --pretty=format:"- %h %s (%an)" $range)
if ($LASTEXITCODE -ne 0 -or $releaseCommits.Count -eq 0) {
    Fail "No se pudieron obtener commits para el release."
}

$defaultTag = Get-NextPatchTag -BaseTag $(if ([string]::IsNullOrWhiteSpace($latestTag)) { "v0.0.0" } else { $latestTag })
if ([string]::IsNullOrWhiteSpace($Version)) {
    $inputVersion = Read-Host "Release version [$defaultTag]"
    if ([string]::IsNullOrWhiteSpace($inputVersion)) {
        $inputVersion = $defaultTag
    }
} else {
    $inputVersion = $Version
}

$tag = Normalize-Tag -InputVersion $inputVersion
if ([string]::IsNullOrWhiteSpace($tag)) {
    Fail "Version invalida. Usa SemVer: 1.2.3 o v1.2.3"
}

& git rev-parse $tag *> $null
if ($LASTEXITCODE -eq 0) {
    Fail "El tag ya existe localmente: $tag"
}

if (-not [string]::IsNullOrWhiteSpace($Remote)) {
    $remoteTag = ((& git ls-remote --tags $Remote "refs/tags/$tag" "refs/tags/$tag^{}" 2>$null) -join "`n").Trim()
    if (-not [string]::IsNullOrWhiteSpace($remoteTag)) {
        Fail "El tag ya existe en remoto ${Remote}: $tag"
    }
}

Write-Section "RELEASE PREVIEW"
Write-Host "Tag: $tag"
Write-Host "Commits:"
$releaseCommits | ForEach-Object { Write-Host $_ }

Write-Host ""
Write-Host "Files:"
if ([string]::IsNullOrWhiteSpace($latestTag)) {
    & git show --name-status --format="" HEAD
} else {
    & git diff --name-status "$latestTag..HEAD"
}

$changelogFile = "CHANGELOG.md"
if (-not (Test-Path $changelogFile)) {
    @"
# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and Semantic Versioning.

## [Unreleased]
"@ | Set-Content -Path $changelogFile -Encoding utf8
}

$releaseDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
$commitText = ($releaseCommits -join "`n")

if ([string]::IsNullOrWhiteSpace($latestTag)) {
    $fileList = @(& git show --name-only --format="" HEAD | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
} else {
    $fileList = @(& git diff --name-only "$latestTag..HEAD" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
$filesText = ($fileList | ForEach-Object { "- $_" }) -join "`n"

$releaseSection = @"
## [$tag] - $releaseDate

### Summary

- Release $tag

### Commits

$commitText

### Files

$filesText

"@

$changelogContent = Get-Content -Path $changelogFile -Raw
if ($changelogContent -match '(?m)^## \[Unreleased\]\s*$') {
    $changelogContent = [regex]::Replace(
        $changelogContent,
        '(?m)^## \[Unreleased\]\s*$',
        "## [Unreleased]`n`n$releaseSection",
        1
    )
} else {
    $changelogContent = $releaseSection + $changelogContent
}

Set-Content -Path $changelogFile -Value $changelogContent -Encoding utf8

Run-Git @("add", $changelogFile) | Out-Null
Run-Git @("commit", "-m", "chore(release): $tag") | Out-Null
Run-Git @("tag", "-a", $tag, "-m", "Release $tag") | Out-Null

Write-Section "RELEASE CREATED"
$releaseCommit = ((Run-Git @("rev-parse", "--short", "HEAD")) -join "`n").Trim()
Write-Host "Commit: $releaseCommit"
Write-Host "Tag: $tag"
& git --no-pager show --stat --oneline -1 HEAD

$performPush = $false
if ([string]::IsNullOrWhiteSpace($Remote)) {
    Write-InfoMsg "Push omitido (no hay remote configurado)."
} else {
    $performPush = if ($YesPush) {
        $true
    } elseif ($NoPush) {
        $false
    } else {
        Ask-YesNo -Prompt "Push branch y tag a $Remote ahora?" -DefaultYes $true
    }
}

if ($performPush) {
    if ([string]::IsNullOrWhiteSpace($upstream)) {
        Run-Git @("push", "-u", $Remote, $Branch) | Out-Null
    } else {
        Run-Git @("push", $Remote, $Branch) | Out-Null
    }
    Run-Git @("push", $Remote, $tag) | Out-Null
    Write-OkMsg "push completado a $Remote"
} else {
    if ([string]::IsNullOrWhiteSpace($Remote)) {
        Write-InfoMsg "Push omitido. Configura remote y luego ejecuta push manual."
    } else {
        Write-InfoMsg "Push omitido. Ejecuta: git push $Remote $Branch ; git push $Remote $tag"
    }
}
