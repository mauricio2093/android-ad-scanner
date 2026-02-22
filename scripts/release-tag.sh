#!/usr/bin/env bash
set -euo pipefail

USE_COLOR=false
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  if command -v tput >/dev/null 2>&1; then
    colors="$(tput colors 2>/dev/null || echo 0)"
    if [[ "$colors" -ge 8 ]]; then
      USE_COLOR=true
    fi
  fi
fi

if [[ "$USE_COLOR" == true ]]; then
  C_RESET="$(printf '\033[0m')"
  C_BOLD="$(printf '\033[1m')"
  C_DIM="$(printf '\033[2m')"
  C_SECTION="$(printf '\033[38;5;45m')"
  C_INFO="$(printf '\033[38;5;39m')"
  C_WARN="$(printf '\033[38;5;214m')"
  C_ERROR="$(printf '\033[38;5;196m')"
  C_OK="$(printf '\033[38;5;82m')"
  C_CHOICE="$(printf '\033[38;5;141m')"
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_SECTION=""
  C_INFO=""
  C_WARN=""
  C_ERROR=""
  C_OK=""
  C_CHOICE=""
fi

print_section() {
  printf '\n%s%s[%s]%s\n' "$C_SECTION" "$C_BOLD" "$1" "$C_RESET"
}

log_info() {
  printf '%s%s[INFO]%s %s\n' "$C_INFO" "$C_BOLD" "$C_RESET" "$1"
}

log_warn() {
  printf '%s%s[WARN]%s %s\n' "$C_WARN" "$C_BOLD" "$C_RESET" "$1"
}

log_ok() {
  printf '%s%s[OK]%s %s\n' "$C_OK" "$C_BOLD" "$C_RESET" "$1"
}

log_error() {
  printf '%s%s[ERROR]%s %s\n' "$C_ERROR" "$C_BOLD" "$C_RESET" "$1" >&2
}

print_choice() {
  printf '%s%s%s%s\n' "$C_CHOICE" "$1" "$C_RESET" ""
}

on_error() {
  local exit_code=$1
  local line_no=$2
  local cmd=$3
  log_error "command failed (exit=$exit_code) at line $line_no"
  log_error "command: $cmd"
  exit "$exit_code"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release-tag.sh [version] [--remote <name>] [--branch <name>] [--yes-pull|--no-pull] [--yes-push|--no-push]

Examples:
  ./scripts/release-tag.sh
  ./scripts/release-tag.sh 1.2.3
  ./scripts/release-tag.sh v1.2.3 --remote origin --branch main --yes-pull --yes-push
USAGE
}

ask_yes_no() {
  local prompt=$1
  local default_choice=$2
  local hint="[y/N]"
  local answer=""

  if [[ "$default_choice" == "Y" ]]; then
    hint="[Y/n]"
  fi

  while true; do
    read -r -p "$prompt $hint " answer
    answer="${answer:-$default_choice}"
    case "${answer,,}" in
      y|yes) return 0 ;;
      n|no) return 1 ;;
      *) log_warn "answer y/n" ;;
    esac
  done
}

next_patch_tag() {
  local base_tag=$1
  if [[ "$base_tag" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    local major="${BASH_REMATCH[1]}"
    local minor="${BASH_REMATCH[2]}"
    local patch="${BASH_REMATCH[3]}"
    printf 'v%d.%d.%d\n' "$major" "$minor" "$((patch + 1))"
    return
  fi
  printf 'v0.0.1\n'
}

normalize_tag() {
  local version=$1
  if [[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if [[ "$version" == v* ]]; then
      printf '%s\n' "$version"
    else
      printf 'v%s\n' "$version"
    fi
    return
  fi
  return 1
}

collect_changed_files() {
  mapfile -t changed_files < <(git status --porcelain | sed -E 's/^.. //; s/.* -> //' | awk 'NF && !seen[$0]++')
}

stage_selected_files() {
  local selection=$1
  local token=""
  local start=""
  local end=""
  local i=0
  local -A seen=()
  local -a selected=()

  IFS=',' read -ra tokens <<< "$selection"
  for token in "${tokens[@]}"; do
    token="${token//[[:space:]]/}"
    if [[ -z "$token" ]]; then
      continue
    fi

    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start="${BASH_REMATCH[1]}"
      end="${BASH_REMATCH[2]}"
      if (( start > end )); then
        local tmp=$start
        start=$end
        end=$tmp
      fi
      for ((i = start; i <= end; i++)); do
        if (( i >= 1 && i <= ${#changed_files[@]} )) && [[ -z "${seen[$i]:-}" ]]; then
          seen[$i]=1
          selected+=("$i")
        fi
      done
    elif [[ "$token" =~ ^[0-9]+$ ]]; then
      i=$token
      if (( i >= 1 && i <= ${#changed_files[@]} )) && [[ -z "${seen[$i]:-}" ]]; then
        seen[$i]=1
        selected+=("$i")
      fi
    else
      log_warn "invalid index token: $token"
    fi
  done

  if (( ${#selected[@]} == 0 )); then
    log_warn "no valid file index selected"
    return 1
  fi

  for i in "${selected[@]}"; do
    git add -A -- "${changed_files[$((i - 1))]}"
  done

  return 0
}

refresh_repo_state() {
  upstream_ref="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
  if [[ -n "$upstream_ref" ]]; then
    ahead_count="$(git rev-list --count "${upstream_ref}..HEAD")"
    behind_count="$(git rev-list --count "HEAD..${upstream_ref}")"
  else
    ahead_count=0
    behind_count=0
  fi

  staged_count="$(git diff --cached --name-only | awk 'NF{c++} END{print c+0}')"
  unstaged_count="$(git diff --name-only | awk 'NF{c++} END{print c+0}')"
  untracked_count="$(git ls-files --others --exclude-standard | awk 'NF{c++} END{print c+0}')"
}

show_detailed_status() {
  print_section "DETAILED STATUS"
  printf '%sShort status:%s\n' "$C_DIM" "$C_RESET"
  if [[ -n "$(git status --porcelain)" ]]; then
    git status --short
  else
    printf '  clean\n'
  fi

  if [[ "$staged_count" -gt 0 ]]; then
    printf '\n%sStaged diff:%s\n' "$C_DIM" "$C_RESET"
    git diff --cached --name-status
  fi

  if [[ "$unstaged_count" -gt 0 ]]; then
    printf '\n%sUnstaged diff:%s\n' "$C_DIM" "$C_RESET"
    git diff --name-status
  fi

  if [[ "$untracked_count" -gt 0 ]]; then
    printf '\n%sUntracked files:%s\n' "$C_DIM" "$C_RESET"
    git ls-files --others --exclude-standard | sed 's/^/?? /'
  fi

  if [[ -n "$upstream_ref" && "$ahead_count" -gt 0 ]]; then
    printf '\n%sLocal commits not pushed:%s\n' "$C_DIM" "$C_RESET"
    git --no-pager log --oneline "${upstream_ref}..HEAD"
  fi
}

show_preflight_menu() {
  print_section "PRE-FLIGHT CONTROL CENTER"
  print_choice "1) Continue workflow"
  print_choice "2) Show detailed status report"
  print_choice "3) Reset staged index (unstage all)"
  print_choice "4) Soft reset last local commit (HEAD~1, keep staged)"
  print_choice "5) Mixed reset last local commit (HEAD~1, keep unstaged)"
  print_choice "6) Cancel flow"
  printf '%sChoose an option. Tip: use 2 to inspect, then 1 to continue.%s\n' "$C_DIM" "$C_RESET"
}

version_arg=""
remote_name="origin"
branch_name=""
pull_pref="ask"
push_pref="ask"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --remote)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log_error "--remote requires a value"
        exit 1
      fi
      remote_name="$2"
      shift 2
      ;;
    --branch)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log_error "--branch requires a value"
        exit 1
      fi
      branch_name="$2"
      shift 2
      ;;
    --yes-pull)
      pull_pref="yes"
      shift
      ;;
    --no-pull)
      pull_pref="no"
      shift
      ;;
    --yes-push)
      push_pref="yes"
      shift
      ;;
    --no-push)
      push_pref="no"
      shift
      ;;
    *)
      if [[ -z "$version_arg" && "$1" != --* ]]; then
        version_arg="$1"
        shift
      else
        log_error "unknown argument: $1"
        usage
        exit 1
      fi
      ;;
  esac
done

if ! command -v git >/dev/null 2>&1; then
  log_error "git not found in PATH"
  exit 1
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  log_error "this is not a git repository"
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if [[ -z "$branch_name" ]]; then
  branch_name="$(git rev-parse --abbrev-ref HEAD)"
fi

if [[ "$branch_name" == "HEAD" ]]; then
  log_error "detached HEAD. Use --branch <name>."
  exit 1
fi

if ! git remote get-url "$remote_name" >/dev/null 2>&1; then
  fallback_remote="$(git remote | head -n1 || true)"
  if [[ -z "$fallback_remote" ]]; then
    log_error "no git remote configured"
    exit 1
  fi
  log_warn "remote $remote_name not found. Using $fallback_remote"
  remote_name="$fallback_remote"
fi

refresh_repo_state

print_section "REPO STATUS"
printf 'Repo: %s\n' "$repo_root"
printf 'Branch: %s\n' "$branch_name"
printf 'Remote: %s\n' "$remote_name"
if [[ -n "$upstream_ref" ]]; then
  printf 'Upstream: %s (ahead=%s, behind=%s)\n' "$upstream_ref" "$ahead_count" "$behind_count"
else
  printf 'Upstream: not configured\n'
fi

print_section "PRE-PULL CHECK"
printf 'Staged files: %s\n' "$staged_count"
printf 'Unstaged files: %s\n' "$unstaged_count"
printf 'Untracked files: %s\n' "$untracked_count"
if [[ -n "$upstream_ref" && "$ahead_count" -gt 0 ]]; then
  printf 'Local commits not pushed: %s\n' "$ahead_count"
  git --no-pager log --oneline "${upstream_ref}..HEAD"
fi

preflight_done=false
while [[ "$preflight_done" == false ]]; do
  show_preflight_menu
  read -r -p 'Choose option [1/2/3/4/5/6]: ' preflight_choice
  case "$preflight_choice" in
    1)
      preflight_done=true
      ;;
    2)
      show_detailed_status
      log_info "status report completed. Returning to pre-flight menu."
      ;;
    3)
      if ! git restore --staged . >/dev/null 2>&1; then
        git reset HEAD . >/dev/null
      fi
      refresh_repo_state
      log_ok "index reset (files remain in working tree)"
      log_info "review the menu again and choose next action."
      ;;
    4|5)
      if ! git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
        log_warn "cannot reset: repository has no parent commit from HEAD"
        continue
      fi

      if [[ -n "$upstream_ref" && "$ahead_count" -eq 0 ]]; then
        log_warn "no local commits pending push. Reset blocked to avoid rewriting published history."
        continue
      fi

      if [[ -z "$upstream_ref" ]]; then
        if ! ask_yes_no 'No upstream configured. Cannot verify if commit is published. Continue anyway?' 'N'; then
          log_info "reset skipped"
          continue
        fi
      fi

      printf 'Last commit: %s\n' "$(git --no-pager log --oneline -1)"
      if [[ "$preflight_choice" == "4" ]]; then
        if ask_yes_no 'Apply SOFT reset HEAD~1?' 'N'; then
          git reset --soft HEAD~1
          refresh_repo_state
          log_ok "soft reset applied"
          log_info "review the menu again and choose next action."
        else
          log_info "soft reset skipped"
        fi
      else
        if ask_yes_no 'Apply MIXED reset HEAD~1?' 'N'; then
          git reset --mixed HEAD~1
          refresh_repo_state
          log_ok "mixed reset applied"
          log_info "review the menu again and choose next action."
        else
          log_info "mixed reset skipped"
        fi
      fi
      ;;
    6)
      log_error "flow cancelled by user"
      exit 1
      ;;
    *)
      log_warn "invalid option"
      ;;
  esac
done

perform_pull=false
if [[ "$pull_pref" == "yes" ]]; then
  perform_pull=true
elif [[ "$pull_pref" == "no" ]]; then
  perform_pull=false
else
  if ask_yes_no "Do pull --rebase from $remote_name/$branch_name before release?" "Y"; then
    perform_pull=true
  fi
fi

if [[ "$perform_pull" == true ]]; then
  stash_used=false
  if [[ -n "$(git status --porcelain)" ]]; then
    log_warn "local changes detected before pull"
    if ask_yes_no "Create auto-stash (tracked only), sync, then pop stash?" "N"; then
      git stash push -m "release-tag auto-stash $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
      stash_used=true
      log_info "local changes stashed"
    else
      log_info "pull skipped by user"
      perform_pull=false
    fi
  fi

  if [[ "$perform_pull" == true ]]; then
    log_info "syncing with fetch + rebase..."
    git fetch "$remote_name" "refs/heads/$branch_name:refs/remotes/$remote_name/$branch_name"
    git rebase "refs/remotes/$remote_name/$branch_name"
    log_ok "sync completed"

    if [[ "$stash_used" == true ]]; then
      log_info "restoring stash..."
      git stash pop
      log_ok "stash restored"
    fi
  fi
fi

print_section "LOCAL MODIFIED FILES"
if [[ -n "$(git status --porcelain)" ]]; then
  git status --short
else
  printf 'Working tree clean.\n'
fi

collect_changed_files
if (( ${#changed_files[@]} > 0 )); then
  print_section "STAGE FILES"
  print_choice "1) Add all changes"
  print_choice "2) Select files by number"
  print_choice "3) Skip staging"

  while true; do
    read -r -p 'Choose option [1/2/3]: ' stage_choice
    case "$stage_choice" in
      1)
        git add -A
        log_ok "all files staged"
        break
        ;;
      2)
        printf '\n'
        for i in "${!changed_files[@]}"; do
          printf '%3d) %s\n' "$((i + 1))" "${changed_files[$i]}"
        done
        printf '\n'
        read -r -p 'Enter indexes (example: 1,3-5): ' selection
        if stage_selected_files "$selection"; then
          log_ok "selected files staged"
          break
        fi
        ;;
      3)
        log_info "staging skipped"
        break
        ;;
      *)
        log_warn "invalid option"
        ;;
    esac
  done
fi

if ! git diff --cached --quiet; then
  print_section "STAGED CHANGES"
  git diff --cached --name-status
  printf '\n'

  commit_message=""
  while [[ -z "$commit_message" ]]; do
    read -r -p 'Write commit message: ' commit_message
    commit_message="${commit_message## }"
    commit_message="${commit_message%% }"
  done

  git commit -m "$commit_message"
  log_ok "commit created"
else
  log_info "no staged changes to commit"
fi

upstream_ref="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
print_section "COMMITS NOT PUSHED"
if [[ -n "$upstream_ref" ]]; then
  ahead_count="$(git rev-list --count "${upstream_ref}..HEAD")"
  if (( ahead_count > 0 )); then
    printf 'You have %s commit(s) pending push:\n' "$ahead_count"
    git --no-pager log --oneline "${upstream_ref}..HEAD"
  else
    printf 'No local commits pending push.\n'
  fi
else
  printf 'No upstream tracking branch configured.\n'
fi

if git fetch --tags "$remote_name" >/dev/null 2>&1; then
  log_info "tags updated from $remote_name"
else
  log_warn "could not fetch tags from $remote_name. Using local tags only."
fi

latest_tag="$(git tag --list 'v*' --sort=-version:refname | head -n1)"
if [[ -z "$latest_tag" ]]; then
  latest_tag="$(git tag --sort=-creatordate | head -n1 || true)"
fi

if [[ -n "$latest_tag" ]]; then
  range="$latest_tag..HEAD"
  log_info "latest tag detected: $latest_tag"
else
  range="HEAD"
  log_info "no previous tags found"
fi

if [[ -n "$latest_tag" ]] && [[ "$(git rev-list --count "$range")" == "0" ]]; then
  log_error "no new commits since $latest_tag"
  exit 1
fi

mapfile -t release_commits < <(git log --pretty=format:'- %h %s (%an)' "$range")
if (( ${#release_commits[@]} == 0 )); then
  log_error "no commits available for release"
  exit 1
fi

default_next_tag="$(next_patch_tag "${latest_tag:-v0.0.0}")"
if [[ -n "$version_arg" ]]; then
  tag="$(normalize_tag "$version_arg" || true)"
  if [[ -z "$tag" ]]; then
    log_error "invalid version: $version_arg"
    exit 1
  fi
else
  read -r -p "Release version [$default_next_tag]: " input_version
  input_version="${input_version:-$default_next_tag}"
  tag="$(normalize_tag "$input_version" || true)"
  if [[ -z "$tag" ]]; then
    log_error "invalid semver format. Example: 1.2.3 or v1.2.3"
    exit 1
  fi
fi

if git rev-parse "$tag" >/dev/null 2>&1; then
  log_error "tag already exists locally: $tag"
  exit 1
fi

remote_tag_exists="$(git ls-remote --tags "$remote_name" "refs/tags/$tag" "refs/tags/$tag^{}" 2>/dev/null || true)"
if [[ -n "$remote_tag_exists" ]]; then
  log_error "tag already exists in remote $remote_name: $tag"
  exit 1
fi

print_section "RELEASE PREVIEW"
printf 'Tag: %s\n' "$tag"
printf 'Commits:\n'
printf '%s\n' "${release_commits[@]}"
printf '\nFiles:\n'
if [[ -n "$latest_tag" ]]; then
  git diff --name-status "$latest_tag"..HEAD
else
  git show --name-status --format='' HEAD
fi

changelog_file="CHANGELOG.md"
if [[ ! -f "$changelog_file" ]]; then
  cat > "$changelog_file" <<'LOG'
# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and Semantic Versioning.

## [Unreleased]
LOG
fi

release_date="$(date -u +%Y-%m-%d)"
release_section_file="$(mktemp)"

{
  printf '## [%s] - %s\n\n' "$tag" "$release_date"
  printf '### Summary\n\n'
  printf -- '- Release %s\n\n' "$tag"
  printf '### Commits\n\n'
  printf '%s\n' "${release_commits[@]}"
  printf '\n### Files\n\n'
  if [[ -n "$latest_tag" ]]; then
    git diff --name-only "$latest_tag"..HEAD | sed 's/^/- /'
  else
    git show --name-only --format='' HEAD | sed '/^$/d; s/^/- /'
  fi
  printf '\n'
} > "$release_section_file"

if grep -q '^## \[Unreleased\]$' "$changelog_file"; then
  tmp_file="$(mktemp)"
  awk -v section_file="$release_section_file" '
    {
      print
      if (!done && $0 ~ /^## \[Unreleased\]$/) {
        print ""
        while ((getline line < section_file) > 0) print line
        close(section_file)
        done=1
      }
    }
  ' "$changelog_file" > "$tmp_file"
  mv "$tmp_file" "$changelog_file"
else
  tmp_file="$(mktemp)"
  {
    cat "$release_section_file"
    cat "$changelog_file"
  } > "$tmp_file"
  mv "$tmp_file" "$changelog_file"
fi

rm -f "$release_section_file"

git add "$changelog_file"
git commit -m "chore(release): $tag"
git tag -a "$tag" -m "Release $tag"

print_section "RELEASE CREATED"
printf 'Commit: %s\n' "$(git rev-parse --short HEAD)"
printf 'Tag: %s\n' "$tag"

git --no-pager show --stat --oneline -1 HEAD

perform_push=false
if [[ "$push_pref" == "yes" ]]; then
  perform_push=true
elif [[ "$push_pref" == "no" ]]; then
  perform_push=false
else
  if ask_yes_no "Push branch and tag to $remote_name now?" "Y"; then
    perform_push=true
  fi
fi

if [[ "$perform_push" == true ]]; then
  if [[ -z "$upstream_ref" ]]; then
    git push -u "$remote_name" "$branch_name"
  else
    git push "$remote_name" "$branch_name"
  fi
  git push "$remote_name" "$tag"
  log_ok "push completed to $remote_name"
else
  log_info "push skipped. Run: git push $remote_name $branch_name && git push $remote_name $tag"
fi
