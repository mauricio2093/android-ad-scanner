#!/usr/bin/env bash
set -euo pipefail

on_error() {
  local exit_code=$1
  local line_no=$2
  local cmd=$3
  printf '\n[ERROR] command failed (exit=%s) at line %s\n' "$exit_code" "$line_no" >&2
  printf '[ERROR] command: %s\n' "$cmd" >&2
  exit "$exit_code"
}
trap 'on_error $? $LINENO "$BASH_COMMAND"' ERR

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run-app.sh [--intel] [--venv <path>] [--python <cmd>] [--] [app_args...]

Examples:
  ./scripts/run-app.sh
  ./scripts/run-app.sh --intel -- --list-scans 20
  ./scripts/run-app.sh --venv .venv --python python3
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

main_script_rel="adb_automation_tool.py"
venv_path=".venv"
python_cmd=""
app_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --intel)
      main_script_rel="smart_intel_scan.py"
      shift
      ;;
    --venv)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        printf '[ERROR] --venv requires a path\n' >&2
        exit 1
      fi
      venv_path="$2"
      shift 2
      ;;
    --python)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        printf '[ERROR] --python requires a command\n' >&2
        exit 1
      fi
      python_cmd="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      app_args+=("$@")
      break
      ;;
    *)
      app_args+=("$1")
      shift
      ;;
  esac
done

main_script="$repo_root/$main_script_rel"

if [[ ! -f "$main_script" ]]; then
  printf '[ERROR] script not found: %s\n' "$main_script" >&2
  exit 1
fi

python_bin=""
if [[ -n "$python_cmd" ]]; then
  if ! command -v "$python_cmd" >/dev/null 2>&1; then
    printf '[ERROR] python command not found: %s\n' "$python_cmd" >&2
    exit 1
  fi
  python_bin="$python_cmd"
elif [[ -x "$repo_root/$venv_path/bin/python" ]]; then
  python_bin="$repo_root/$venv_path/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="python3"
elif command -v python >/dev/null 2>&1; then
  python_bin="python"
else
  printf '[ERROR] no Python interpreter found (python3/python)\n' >&2
  exit 1
fi

if ! command -v adb >/dev/null 2>&1; then
  printf '[WARN] adb was not found in PATH. Some features may fail.\n' >&2
fi

printf '[INFO] Repo root: %s\n' "$repo_root"
printf '[INFO] Running: %s %s' "$python_bin" "$main_script"
if [[ ${#app_args[@]} -gt 0 ]]; then
  printf ' %q' "${app_args[@]}"
fi
printf '\n'

cd "$repo_root"
"$python_bin" "$main_script" "${app_args[@]}"
