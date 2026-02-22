#!/usr/bin/env pwsh
param(
    [string]$Version = "",
    [string]$Remote = "origin",
    [string]$Branch = "",
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

if ($YesPull -and $NoPull) {
    Fail "No puedes usar -YesPull y -NoPull al mismo tiempo."
}
if ($YesPush -and $NoPush) {
    Fail "No puedes usar -YesPush y -NoPush al mismo tiempo."
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail "git no esta instalado o no esta en PATH."
}

& git rev-parse --git-dir *> $null
if ($LASTEXITCODE -ne 0) {
    Fail "Este directorio no es un repositorio Git."
}

$repoRoot = ((Run-Git @("rev-parse", "--show-toplevel")) -join "`n").Trim()
Set-Location $repoRoot

if ([string]::IsNullOrWhiteSpace($Branch)) {
    $Branch = ((Run-Git @("rev-parse", "--abbrev-ref", "HEAD")) -join "`n").Trim()
}
if ($Branch -eq "HEAD") {
    Fail "HEAD detached. Usa -Branch <nombre>."
}

& git remote get-url $Remote *> $null
if ($LASTEXITCODE -ne 0) {
    $fallbackRemote = ((& git remote | Select-Object -First 1) -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($fallbackRemote)) {
        Fail "No hay remotos configurados en Git."
    }
    Write-WarnMsg "remote '$Remote' no encontrado. Usando '$fallbackRemote'"
    $Remote = $fallbackRemote
}

Update-RepoState

Write-Section "REPO STATUS"
Write-Host "Repo: $repoRoot"
Write-Host "Branch: $Branch"
Write-Host "Remote: $Remote"
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

$performPull = if ($YesPull) {
    $true
} elseif ($NoPull) {
    $false
} else {
    Ask-YesNo -Prompt "Quieres hacer pull --rebase desde $Remote/$Branch antes del release?" -DefaultYes $true
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
        Run-Git @("fetch", $Remote, ("refs/heads/$Branch:refs/remotes/$Remote/$Branch")) | Out-Null
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
        $commitMessage = Read-Host "Write commit message"
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

& git fetch --tags $Remote *> $null
if ($LASTEXITCODE -eq 0) {
    Write-InfoMsg "tags updated from $Remote"
} else {
    Write-WarnMsg "could not fetch tags from $Remote. Using local tags only."
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

$remoteTag = ((& git ls-remote --tags $Remote "refs/tags/$tag" "refs/tags/$tag^{}" 2>$null) -join "`n").Trim()
if (-not [string]::IsNullOrWhiteSpace($remoteTag)) {
    Fail "El tag ya existe en remoto ${Remote}: $tag"
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

$performPush = if ($YesPush) {
    $true
} elseif ($NoPush) {
    $false
} else {
    Ask-YesNo -Prompt "Push branch y tag a $Remote ahora?" -DefaultYes $true
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
    Write-InfoMsg "Push omitido. Ejecuta: git push $Remote $Branch ; git push $Remote $tag"
}
