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

if [[ -t 1 ]]; then
  c_info='\033[1;36m'
  c_warn='\033[1;33m'
  c_err='\033[1;31m'
  c_ok='\033[1;32m'
  c_dim='\033[0;37m'
  c_reset='\033[0m'
else
  c_info=''
  c_warn=''
  c_err=''
  c_ok=''
  c_dim=''
  c_reset=''
fi

log() { printf "${c_info}[INFO]${c_reset} %s\n" "$*"; }
warn() { printf "${c_warn}[WARN]${c_reset} %s\n" "$*"; }
ok() { printf "${c_ok}[OK]${c_reset} %s\n" "$*"; }
fail() { printf "${c_err}[ERROR]${c_reset} %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build-exe.sh [options]

Options:
  --repo <path>          Repo path (default: auto from script location)
  --venv <path>          Virtual env path relative to repo (default: .venv)
  --python <cmd>         Python command (example: python3)
  --mode <spec|direct>   Build mode (default: spec)
  --entry <file>         Entry script for direct mode (default: adb_automation_tool.py)
  --spec <file>          Spec file for spec mode (default: adb_automation_tool.spec)
  --name <name>          Output app name for direct mode (default: adb_automation_tool)
  --icon <path>          Icon path for direct mode
  --onedir               Use onedir in direct mode (default is onefile)
  --console              Build with console in direct mode (default is windowed)
  --clean                Remove repo build/ and dist/ before building
  --install-pyinstaller  Install/upgrade pyinstaller if missing
  --yes                  Non-interactive mode
  -h, --help             Show this help

Examples:
  ./scripts/build-exe.sh --clean --install-pyinstaller
  ./scripts/build-exe.sh --mode direct --name android-ad-scanner --console
EOF
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
venv_path=".venv"
python_cmd=""
mode="spec"
entry_script="adb_automation_tool.py"
spec_file="adb_automation_tool.spec"
app_name="adb_automation_tool"
icon_path=""
use_onedir=0
use_console=0
clean_build=0
install_pyinstaller=0
assume_yes=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a path"
      repo_root="$2"
      shift 2
      ;;
    --venv)
      [[ $# -ge 2 ]] || fail "--venv requires a path"
      venv_path="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || fail "--python requires a command"
      python_cmd="$2"
      shift 2
      ;;
    --mode)
      [[ $# -ge 2 ]] || fail "--mode requires spec or direct"
      mode="$2"
      [[ "$mode" == "spec" || "$mode" == "direct" ]] || fail "Invalid --mode: $mode"
      shift 2
      ;;
    --entry)
      [[ $# -ge 2 ]] || fail "--entry requires a file"
      entry_script="$2"
      shift 2
      ;;
    --spec)
      [[ $# -ge 2 ]] || fail "--spec requires a file"
      spec_file="$2"
      shift 2
      ;;
    --name)
      [[ $# -ge 2 ]] || fail "--name requires a value"
      app_name="$2"
      shift 2
      ;;
    --icon)
      [[ $# -ge 2 ]] || fail "--icon requires a path"
      icon_path="$2"
      shift 2
      ;;
    --onedir)
      use_onedir=1
      shift
      ;;
    --console)
      use_console=1
      shift
      ;;
    --clean)
      clean_build=1
      shift
      ;;
    --install-pyinstaller)
      install_pyinstaller=1
      shift
      ;;
    --yes)
      assume_yes=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

repo_root="$(cd "$repo_root" && pwd)"
cd "$repo_root"

python_bin=""
if [[ -n "$python_cmd" ]]; then
  command -v "$python_cmd" >/dev/null 2>&1 || fail "Python command not found: $python_cmd"
  python_bin="$python_cmd"
elif [[ -x "$repo_root/$venv_path/bin/python" ]]; then
  python_bin="$repo_root/$venv_path/bin/python"
elif [[ -x "$repo_root/$venv_path/Scripts/python.exe" ]]; then
  python_bin="$repo_root/$venv_path/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then
  python_bin="python3"
elif command -v python >/dev/null 2>&1; then
  python_bin="python"
else
  fail "No Python interpreter found."
fi

entry_abs="$repo_root/$entry_script"
spec_abs="$repo_root/$spec_file"

if [[ "$mode" == "spec" ]]; then
  [[ -f "$spec_abs" ]] || fail "Spec file not found: $spec_abs"
else
  [[ -f "$entry_abs" ]] || fail "Entry script not found: $entry_abs"
  if [[ -n "$icon_path" ]]; then
    [[ -f "$repo_root/$icon_path" || -f "$icon_path" ]] || fail "Icon file not found: $icon_path"
  fi
fi

has_pyinstaller=1
if ! "$python_bin" -c "import PyInstaller; print(PyInstaller.__version__)" >/dev/null 2>&1; then
  has_pyinstaller=0
fi

if [[ "$has_pyinstaller" -eq 0 ]]; then
  if [[ "$install_pyinstaller" -eq 1 ]]; then
    log "Installing PyInstaller..."
    "$python_bin" -m pip install --upgrade pyinstaller
  else
    fail "PyInstaller is not installed. Run with --install-pyinstaller."
  fi
fi

py_version="$("$python_bin" -c 'import sys; print(sys.version.split()[0])')"
pyinstaller_version="$("$python_bin" -c 'import PyInstaller; print(PyInstaller.__version__)')"

printf "\n${c_dim}[PRE-FLIGHT BUILD]${c_reset}\n"
printf "Repo: %s\n" "$repo_root"
printf "Python: %s (v%s)\n" "$python_bin" "$py_version"
printf "PyInstaller: %s\n" "$pyinstaller_version"
printf "Mode: %s\n" "$mode"
if [[ "$mode" == "spec" ]]; then
  printf "Spec: %s\n" "$spec_file"
else
  printf "Entry: %s\n" "$entry_script"
  printf "Name: %s\n" "$app_name"
  printf "Layout: %s\n" "$([[ "$use_onedir" -eq 1 ]] && echo "onedir" || echo "onefile")"
  printf "Console: %s\n" "$([[ "$use_console" -eq 1 ]] && echo "enabled" || echo "disabled")"
fi
printf "Clean build dirs: %s\n" "$([[ "$clean_build" -eq 1 ]] && echo "yes" || echo "no")"

if [[ "$assume_yes" -ne 1 ]]; then
  read -r -p "Continue build? [Y/n]: " confirm
  if [[ "${confirm:-Y}" =~ ^[Nn]$ ]]; then
    warn "Build cancelled."
    exit 0
  fi
fi

if [[ "$clean_build" -eq 1 ]]; then
  log "Cleaning build/ and dist/..."
  rm -rf "$repo_root/build" "$repo_root/dist"
fi

cmd=("$python_bin" "-m" "PyInstaller" "--noconfirm")
if [[ "$clean_build" -eq 1 ]]; then
  cmd+=("--clean")
fi

if [[ "$mode" == "spec" ]]; then
  cmd+=("$spec_file")
else
  if [[ "$use_onedir" -eq 1 ]]; then
    cmd+=("--onedir")
  else
    cmd+=("--onefile")
  fi

  if [[ "$use_console" -eq 1 ]]; then
    cmd+=("--console")
  else
    cmd+=("--windowed")
  fi

  cmd+=("--name" "$app_name")
  if [[ -n "$icon_path" ]]; then
    cmd+=("--icon" "$icon_path")
  fi
  cmd+=("$entry_script")
fi

log "Executing build command..."
"${cmd[@]}"

artifact_candidates=(
  "$repo_root/dist/$app_name.exe"
  "$repo_root/dist/$app_name"
  "$repo_root/dist/$app_name/$app_name.exe"
  "$repo_root/dist/adb_automation_tool.exe"
)

artifact_path=""
for candidate in "${artifact_candidates[@]}"; do
  if [[ -e "$candidate" ]]; then
    artifact_path="$candidate"
    break
  fi
done

if [[ -n "$artifact_path" ]]; then
  ok "Build completed."
  printf "${c_ok}Artifact:${c_reset} %s\n" "$artifact_path"
else
  warn "Build finished but artifact was not found in expected paths."
  warn "Inspect dist/ manually."
fi
