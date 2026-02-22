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
  ./scripts/release-tag.sh [version] [--repo <path>] [--remote <name>] [--branch <name>] [--yes-pull|--no-pull] [--yes-push|--no-push]

Examples:
  ./scripts/release-tag.sh
  ./scripts/release-tag.sh --repo /path/to/repo
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

read_nonempty_or_default() {
  local prompt="$1"
  local default_value="${2:-}"
  local value=""
  while true; do
    if [[ -n "$default_value" ]]; then
      read -r -p "$prompt [$default_value]: " value
      value="${value:-$default_value}"
    else
      read -r -p "$prompt: " value
    fi
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
}

has_commits() {
  git rev-parse --verify HEAD >/dev/null 2>&1
}

get_current_branch() {
  local branch=""
  branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
  if [[ -n "$branch" ]]; then
    printf '%s\n' "$branch"
    return 0
  fi
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [[ -n "$branch" && "$branch" != "HEAD" ]]; then
    printf '%s\n' "$branch"
    return 0
  fi
  printf '\n'
}

ensure_git_identity() {
  local git_name=""
  local git_email=""

  git_name="$(git config --get user.name 2>/dev/null || true)"
  git_email="$(git config --get user.email 2>/dev/null || true)"

  if [[ -n "$git_name" && -n "$git_email" ]]; then
    return 0
  fi

  print_section "GIT IDENTITY SETUP"
  log_warn "git user.name / user.email is not configured for this repo"

  if [[ -z "$git_name" ]]; then
    git_name="$(read_nonempty_or_default 'Git user.name (local repo)')"
    git config user.name "$git_name"
    log_ok "configured user.name=$git_name"
  fi

  if [[ -z "$git_email" ]]; then
    git_email="$(read_nonempty_or_default 'Git user.email (local repo)')"
    git config user.email "$git_email"
    log_ok "configured user.email=$git_email"
  fi
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

stage_bootstrap_selection() {
  local selection="$1"
  local token=""
  local start=""
  local end=""
  local i=0
  local selected_count=0
  local -A seen=()
  local -a tokens=()

  IFS=',' read -ra tokens <<< "$selection"
  for token in "${tokens[@]}"; do
    token="${token#"${token%%[![:space:]]*}"}"
    token="${token%"${token##*[![:space:]]}"}"
    [[ -z "$token" ]] && continue

    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      start="${BASH_REMATCH[1]}"
      end="${BASH_REMATCH[2]}"
      if (( start > end )); then
        local tmp="$start"
        start="$end"
        end="$tmp"
      fi
      for ((i = start; i <= end; i++)); do
        if (( i >= 1 && i <= ${#changed_files[@]} )) && [[ -z "${seen[$i]:-}" ]]; then
          seen[$i]=1
          git add -A -- "${changed_files[$((i - 1))]}"
          selected_count=$((selected_count + 1))
        fi
      done
      continue
    fi

    if [[ "$token" =~ ^[0-9]+$ ]]; then
      i="$token"
      if (( i >= 1 && i <= ${#changed_files[@]} )) && [[ -z "${seen[$i]:-}" ]]; then
        seen[$i]=1
        git add -A -- "${changed_files[$((i - 1))]}"
        selected_count=$((selected_count + 1))
      else
        log_warn "invalid file index: $token"
      fi
      continue
    fi

    if [[ -e "$token" ]]; then
      git add -A -- "$token"
      selected_count=$((selected_count + 1))
    else
      log_warn "path not found: $token"
    fi
  done

  if (( selected_count == 0 )); then
    log_warn "no valid files/folders selected"
    return 1
  fi
  return 0
}

bootstrap_stage_menu() {
  local stage_choice=""
  local selection=""

  while true; do
    print_section "FIRST COMMIT STAGING"
    print_choice "1) Stage all project files"
    if [[ -f "README.md" ]]; then
      print_choice "2) Stage only README.md"
    else
      print_choice "2) Stage only README.md (not found)"
    fi
    print_choice "3) Select specific files/folders"
    print_choice "4) Cancel bootstrap"

    read -r -p 'Choose option [1/2/3/4]: ' stage_choice
    case "$stage_choice" in
      1)
        git add -A
        ;;
      2)
        if [[ -f "README.md" ]]; then
          git add README.md
        else
          log_warn "README.md does not exist"
          continue
        fi
        ;;
      3)
        collect_changed_files
        if (( ${#changed_files[@]} == 0 )); then
          log_warn "no pending files to select"
          continue
        fi
        printf '%sDetected changed files:%s\n' "$C_DIM" "$C_RESET"
        for i in "${!changed_files[@]}"; do
          printf '%3d) %s\n' "$((i + 1))" "${changed_files[$i]}"
        done
        read -r -p 'Select indexes/ranges and/or paths (example: 1,3-5,src,README.md): ' selection
        if ! stage_bootstrap_selection "$selection"; then
          continue
        fi
        ;;
      4)
        log_error "bootstrap cancelled by user"
        return 1
        ;;
      *)
        log_warn "invalid option"
        continue
        ;;
    esac

    if git diff --cached --quiet; then
      log_warn "no staged changes selected yet"
      continue
    fi

    print_section "FIRST COMMIT PREVIEW"
    git diff --cached --name-status
    return 0
  done
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

resolve_repo_root() {
  local preferred_path="${1:-}"
  local script_dir=""
  local candidate=""
  local manual_path=""
  local tries=0
  local -a candidates=()

  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [[ -n "$preferred_path" ]]; then
    candidates+=("$preferred_path")
  fi
  candidates+=("$(pwd)")
  candidates+=("$script_dir" "$script_dir/.." "$script_dir/../..")

  for candidate in "${candidates[@]}"; do
    [[ -z "$candidate" ]] && continue
    if [[ ! -d "$candidate" ]]; then
      continue
    fi
    if git -C "$candidate" rev-parse --git-dir >/dev/null 2>&1; then
      git -C "$candidate" rev-parse --show-toplevel
      return 0
    fi
  done

  if [[ -n "$preferred_path" ]]; then
    log_warn "could not use --repo $preferred_path" >&2
  else
    log_warn "no git repository detected from current folder" >&2
  fi

  local init_target="${preferred_path:-$(pwd)}"
  if ask_yes_no "Initialize git repository in $init_target?" "Y"; then
    if [[ ! -d "$init_target" ]]; then
      if ask_yes_no "Path does not exist. Create $init_target?" "Y"; then
        mkdir -p "$init_target"
      else
        log_error "cannot continue without valid path" >&2
        return 1
      fi
    fi
    if git -C "$init_target" init >/dev/null 2>&1; then
      log_ok "repository initialized in $init_target" >&2
      git -C "$init_target" rev-parse --show-toplevel
      return 0
    fi
    log_warn "failed to initialize repository in $init_target" >&2
  fi

  while (( tries < 3 )); do
    read -r -p 'Enter Git repository path (or q to cancel): ' manual_path
    manual_path="${manual_path:-}"
    if [[ "${manual_path,,}" == "q" ]]; then
      break
    fi
    if [[ -z "$manual_path" ]]; then
      tries=$((tries + 1))
      continue
    fi
    if [[ ! -d "$manual_path" ]]; then
      log_warn "path does not exist: $manual_path" >&2
      tries=$((tries + 1))
      continue
    fi
    if git -C "$manual_path" rev-parse --git-dir >/dev/null 2>&1; then
      git -C "$manual_path" rev-parse --show-toplevel
      return 0
    fi
    log_warn "path is not a git repository: $manual_path" >&2
    tries=$((tries + 1))
  done

  return 1
}

ensure_first_commit() {
  local default_title=""
  local project_title=""
  local first_commit_msg=""
  local target_branch=""
  local remote_url=""

  if has_commits; then
    return 0
  fi

  print_section "REPOSITORY BOOTSTRAP"
  log_warn "repository has no commits yet (HEAD missing)"
  if ! ask_yes_no "Create bootstrap now (README + first commit + main branch)?" "Y"; then
    log_error "cannot continue without initial commit"
    return 1
  fi

  if [[ ! -f "README.md" ]]; then
    default_title="$(basename "$(pwd)")"
    [[ -z "$default_title" ]] && default_title="New-Repository"
    project_title="$(read_nonempty_or_default "README title" "$default_title")"
    printf '# %s\n' "$project_title" > README.md
    log_ok "README.md created"
  fi

  if ! bootstrap_stage_menu; then
    return 1
  fi

  if git diff --cached --quiet; then
    log_error "no staged changes for first commit"
    return 1
  fi

  first_commit_msg="$(read_nonempty_or_default "First commit message" "first commit")"
  git commit -m "$first_commit_msg"
  log_ok "first commit created"

  target_branch="${branch_name:-main}"
  target_branch="$(read_nonempty_or_default "Primary branch name" "$target_branch")"
  git branch -M "$target_branch"
  branch_name="$target_branch"
  log_ok "branch set to $branch_name"

  if ! git remote get-url "$remote_name" >/dev/null 2>&1; then
    if ask_yes_no "Configure remote '$remote_name' now?" "Y"; then
      remote_url="$(read_nonempty_or_default "Remote URL (https://github.com/user/repo.git)")"
      if git remote get-url "$remote_name" >/dev/null 2>&1; then
        git remote set-url "$remote_name" "$remote_url"
      else
        git remote add "$remote_name" "$remote_url"
      fi
      log_ok "remote $remote_name configured"
      if ask_yes_no "Push initial commit now?" "Y"; then
        git push -u "$remote_name" "$branch_name"
        log_ok "initial push completed"
      fi
    else
      log_warn "continuing without remote; pull/push steps will be skipped"
      remote_name=""
    fi
  fi
}

normalize_scope() {
  local raw="$1"
  raw="${raw,,}"
  raw="$(printf '%s' "$raw" | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//')"
  if [[ -z "$raw" || "$raw" == "root" ]]; then
    printf '\n'
  else
    printf '%s\n' "$raw"
  fi
}

format_commit_message() {
  local type="$1"
  local scope="$2"
  local subject="$3"
  if [[ -n "$scope" ]]; then
    printf '%s(%s): %s\n' "$type" "$scope" "$subject"
  else
    printf '%s: %s\n' "$type" "$subject"
  fi
}

subject_for_type() {
  local type="$1"
  local base="$2"
  case "$type" in
    feat) printf 'add %s improvements\n' "$base" ;;
    fix) printf 'fix issues in %s\n' "$base" ;;
    chore) printf 'update %s\n' "$base" ;;
    refactor) printf 'refactor %s\n' "$base" ;;
    docs) printf 'update %s\n' "$base" ;;
    test) printf 'improve %s coverage\n' "$base" ;;
    *) printf 'update %s\n' "$base" ;;
  esac
}

generate_commit_suggestions() {
  local status=""
  local p1=""
  local p2=""
  local file=""
  local first=""
  local lower=""
  local top=""
  local base="project files"
  local scope="repo"
  local docs_only=false
  local tests_only=false
  local scripts_only=false
  local config_only=false
  local has_docs=false
  local has_tests=false
  local has_scripts=false
  local has_python=false
  local has_config=false
  local has_data=false
  local has_ci=false
  local added=0
  local modified=0
  local deleted=0
  local renamed=0
  local max_dir=0
  local dir=""
  local -a types=()
  local type=""
  local subject=""
  local message=""
  local -A dir_counts=()
  local -A seen=()

  while IFS=$'\t' read -r status p1 p2; do
    [[ -z "$status" ]] && continue
    first="${status:0:1}"
    case "$first" in
      A) added=$((added + 1)) ;;
      M) modified=$((modified + 1)) ;;
      D) deleted=$((deleted + 1)) ;;
      R) renamed=$((renamed + 1)) ;;
      C) modified=$((modified + 1)) ;;
      *) modified=$((modified + 1)) ;;
    esac

    if [[ "$first" == "R" || "$first" == "C" ]]; then
      file="$p2"
    else
      file="$p1"
    fi
    [[ -z "$file" ]] && continue

    if [[ "$file" == */* ]]; then
      top="${file%%/*}"
    else
      top="root"
    fi
    if [[ -z "${dir_counts["$top"]+x}" ]]; then
      dir_counts["$top"]=0
    fi
    dir_counts["$top"]=$(( dir_counts["$top"] + 1 ))

    lower="${file,,}"
    case "$lower" in
      readme*|*.md|docs/*|md/*|*.rst|*.adoc) has_docs=true ;;
    esac
    case "$lower" in
      scripts/*|*.sh|*.ps1|*.bat) has_scripts=true ;;
    esac
    case "$lower" in
      tests/*|test/*|*test*.py|*_test.py|test_*.py) has_tests=true ;;
    esac
    case "$lower" in
      *.py) has_python=true ;;
    esac
    case "$lower" in
      config/*|*.json|*.yml|*.yaml|*.toml|*.ini|*.cfg|pyproject.toml|requirements.txt) has_config=true ;;
    esac
    case "$lower" in
      data/*) has_data=true ;;
    esac
    case "$lower" in
      .github/*) has_ci=true ;;
    esac
  done < <(git diff --cached --name-status)

  for dir in "${!dir_counts[@]}"; do
    if (( dir_counts["$dir"] > max_dir )); then
      max_dir="${dir_counts["$dir"]}"
      scope="$dir"
    fi
  done
  scope="$(normalize_scope "$scope")"

  docs_only=false
  tests_only=false
  scripts_only=false
  config_only=false

  if [[ "$has_docs" == true && "$has_scripts" == false && "$has_tests" == false && "$has_python" == false && "$has_config" == false && "$has_data" == false && "$has_ci" == false ]]; then
    docs_only=true
  fi
  if [[ "$has_tests" == true && "$has_docs" == false && "$has_scripts" == false && "$has_python" == false && "$has_config" == false && "$has_data" == false && "$has_ci" == false ]]; then
    tests_only=true
  fi
  if [[ "$has_scripts" == true && "$has_docs" == false && "$has_tests" == false && "$has_python" == false && "$has_config" == false && "$has_data" == false && "$has_ci" == false ]]; then
    scripts_only=true
  fi
  if [[ "$has_config" == true && "$has_docs" == false && "$has_tests" == false && "$has_scripts" == false && "$has_python" == false && "$has_data" == false && "$has_ci" == false ]]; then
    config_only=true
  fi

  if [[ "$docs_only" == true ]]; then
    base="project documentation"
    types=("docs" "chore" "fix")
  elif [[ "$tests_only" == true ]]; then
    base="test suite"
    types=("test" "chore" "fix")
  elif [[ "$scripts_only" == true ]]; then
    base="release automation scripts"
    types=("chore" "fix" "feat")
  elif [[ "$has_python" == true && "$has_tests" == true ]]; then
    base="scanner workflows and tests"
    types=("feat" "fix" "refactor")
  elif [[ "$has_python" == true ]]; then
    base="scanner workflows"
    types=("feat" "fix" "refactor")
  elif [[ "$config_only" == true ]]; then
    base="project configuration"
    types=("chore" "fix" "docs")
  elif [[ "$has_scripts" == true && "$has_docs" == true ]]; then
    base="release automation and documentation"
    types=("chore" "docs" "fix")
  elif [[ "$has_data" == true ]]; then
    base="intel datasets"
    types=("chore" "feat" "fix")
  elif [[ "$has_ci" == true ]]; then
    base="ci pipeline"
    types=("chore" "fix" "refactor")
  else
    base="project files"
    types=("chore" "feat" "fix")
  fi

  if (( deleted > 0 && added == 0 && modified == 0 && renamed == 0 )); then
    types=("chore" "refactor" "fix")
  fi

  commit_suggestions=()
  for type in "${types[@]}"; do
    subject="$(subject_for_type "$type" "$base")"
    message="$(format_commit_message "$type" "$scope" "$subject")"
    if [[ -z "${seen["$message"]:-}" ]]; then
      seen["$message"]=1
      commit_suggestions+=("$message")
    fi
  done

  if (( ${#commit_suggestions[@]} < 3 )); then
    for type in chore fix feat refactor docs test; do
      subject="$(subject_for_type "$type" "$base")"
      message="$(format_commit_message "$type" "$scope" "$subject")"
      if [[ -z "${seen["$message"]:-}" ]]; then
        seen["$message"]=1
        commit_suggestions+=("$message")
      fi
      if (( ${#commit_suggestions[@]} >= 3 )); then
        break
      fi
    done
  fi
}

version_arg=""
repo_path=""
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
    --repo)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log_error "--repo requires a value"
        exit 1
      fi
      repo_path="$2"
      shift 2
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

repo_root="$(resolve_repo_root "$repo_path" || true)"
if [[ -z "$repo_root" ]]; then
  log_error "no valid git repository found"
  exit 1
fi

cd "$repo_root"

ensure_git_identity
ensure_first_commit

if [[ -z "$branch_name" ]]; then
  branch_name="$(get_current_branch)"
fi

if [[ -z "$branch_name" || "$branch_name" == "HEAD" ]]; then
  log_error "detached HEAD. Use --branch <name>."
  exit 1
fi

has_remote=false
if [[ -n "$remote_name" ]] && git remote get-url "$remote_name" >/dev/null 2>&1; then
  has_remote=true
else
  fallback_remote="$(git remote | head -n1 || true)"
  if [[ -n "$fallback_remote" ]]; then
    log_warn "remote $remote_name not found. Using $fallback_remote"
    remote_name="$fallback_remote"
    has_remote=true
  fi
fi

if [[ "$has_remote" == false ]]; then
  if ask_yes_no "No active remote found. Configure origin now?" "Y"; then
    remote_name="${remote_name:-origin}"
    remote_url="$(read_nonempty_or_default 'Remote URL (https://github.com/user/repo.git)')"
    if git remote get-url "$remote_name" >/dev/null 2>&1; then
      git remote set-url "$remote_name" "$remote_url"
    else
      git remote add "$remote_name" "$remote_url"
    fi
    has_remote=true
    log_ok "remote $remote_name configured"
  else
    log_warn "continuing without remote; pull/push steps will be skipped"
    remote_name=""
  fi
fi

refresh_repo_state

print_section "REPO STATUS"
printf 'Repo: %s\n' "$repo_root"
printf 'Branch: %s\n' "$branch_name"
if [[ -n "$remote_name" ]]; then
  printf 'Remote: %s\n' "$remote_name"
else
  printf 'Remote: (none)\n'
fi
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
if [[ -z "$remote_name" ]]; then
  log_info "remote pull skipped (no remote configured)"
else
  if [[ "$pull_pref" == "yes" ]]; then
    perform_pull=true
  elif [[ "$pull_pref" == "no" ]]; then
    perform_pull=false
  else
    if ask_yes_no "Do pull --rebase from $remote_name/$branch_name before release?" "Y"; then
      perform_pull=true
    fi
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
    generate_commit_suggestions
    print_section "COMMIT MESSAGE"
    printf '%sAuto-suggestions (heuristic, no AI):%s\n' "$C_DIM" "$C_RESET"
    print_choice "1) ${commit_suggestions[0]}"
    print_choice "2) ${commit_suggestions[1]}"
    print_choice "3) ${commit_suggestions[2]}"
    print_choice "4) Write custom message"
    print_choice "5) Refresh suggestions"
    read -r -p 'Choose option [1/2/3/4/5]: ' commit_choice
    case "$commit_choice" in
      1|2|3)
        commit_message="${commit_suggestions[$((commit_choice - 1))]}"
        log_info "selected: $commit_message"
        ;;
      4)
        read -r -p 'Write commit message: ' commit_message
        commit_message="${commit_message## }"
        commit_message="${commit_message%% }"
        ;;
      5)
        log_info "refreshing suggestions..."
        ;;
      *)
        log_warn "invalid option"
        ;;
    esac
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

if [[ -n "$remote_name" ]]; then
  if git fetch --tags "$remote_name" >/dev/null 2>&1; then
    log_info "tags updated from $remote_name"
  else
    log_warn "could not fetch tags from $remote_name. Using local tags only."
  fi
else
  log_info "remote tag fetch skipped (no remote configured)"
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

if [[ -n "$remote_name" ]]; then
  remote_tag_exists="$(git ls-remote --tags "$remote_name" "refs/tags/$tag" "refs/tags/$tag^{}" 2>/dev/null || true)"
  if [[ -n "$remote_tag_exists" ]]; then
    log_error "tag already exists in remote $remote_name: $tag"
    exit 1
  fi
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
if [[ -z "$remote_name" ]]; then
  log_info "push skipped (no remote configured)"
else
  if [[ "$push_pref" == "yes" ]]; then
    perform_push=true
  elif [[ "$push_pref" == "no" ]]; then
    perform_push=false
  else
    if ask_yes_no "Push branch and tag to $remote_name now?" "Y"; then
      perform_push=true
    fi
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
  if [[ -n "$remote_name" ]]; then
    log_info "push skipped. Run: git push $remote_name $branch_name && git push $remote_name $tag"
  else
    log_info "push skipped. Configure remote and push when ready."
  fi
fi
