#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_SCRIPT="$ROOT_DIR/scripts/release-tag.sh"

if [[ ! -x "$RELEASE_SCRIPT" ]]; then
  echo "[ERROR] release script not found or not executable: $RELEASE_SCRIPT" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  if [[ "${KEEP_QA_TMP:-0}" != "1" ]]; then
    rm -rf "$TMP_DIR"
  else
    echo "[INFO] keeping temp dir: $TMP_DIR"
  fi
}
trap cleanup EXIT

echo "[INFO] QA temp workspace: $TMP_DIR"

mkdir -p "$TMP_DIR/remote.git"
git -C "$TMP_DIR/remote.git" init --bare >/dev/null
git -C "$TMP_DIR" clone "$TMP_DIR/remote.git" work >/dev/null

cd "$TMP_DIR/work"
git checkout -b main >/dev/null
git config user.name "QA Bot"
git config user.email "qa@example.com"

mkdir -p scripts
cp "$RELEASE_SCRIPT" scripts/release-tag.sh
chmod +x scripts/release-tag.sh

echo "hello" > app.txt
git add app.txt scripts/release-tag.sh
git commit -m "feat: initial" >/dev/null
git push -u origin main >/dev/null

echo "[TEST1] clean flow: preflight menu + sync + release + push"
set +e
printf '2\n1\ny\nv0.0.1\ny\n' | ./scripts/release-tag.sh --branch main --remote origin > "$TMP_DIR/test1.log" 2>&1
TEST1_EXIT=$?
set -e
if [[ $TEST1_EXIT -ne 0 ]]; then
  echo "[FAIL] test1 failed with exit=$TEST1_EXIT"
  sed -n '1,260p' "$TMP_DIR/test1.log"
  exit 1
fi

git tag --list | grep -q '^v0.0.1$'
git -C "$TMP_DIR/remote.git" tag | grep -q '^v0.0.1$'
grep -q 'sync completed' "$TMP_DIR/test1.log"
if grep -q 'Cannot rebase onto multiple branches' "$TMP_DIR/test1.log"; then
  echo "[FAIL] test1 detected rebase ambiguity regression"
  exit 1
fi
echo "[PASS] test1"

echo "[TEST2] dirty flow: stash tracked + stage + commit + release + push"
echo "dirty-change" >> app.txt
echo "new file" > note.tmp

set +e
printf '1\ny\ny\n1\nchore: add dirty changes\nv0.0.2\ny\n' | ./scripts/release-tag.sh --branch main --remote origin > "$TMP_DIR/test2.log" 2>&1
TEST2_EXIT=$?
set -e
if [[ $TEST2_EXIT -ne 0 ]]; then
  echo "[FAIL] test2 failed with exit=$TEST2_EXIT"
  sed -n '1,320p' "$TMP_DIR/test2.log"
  exit 1
fi

git tag --list | grep -q '^v0.0.2$'
git -C "$TMP_DIR/remote.git" tag | grep -q '^v0.0.2$'
grep -q 'local changes stashed' "$TMP_DIR/test2.log"
grep -q 'sync completed' "$TMP_DIR/test2.log"
if grep -q 'Cannot rebase onto multiple branches' "$TMP_DIR/test2.log"; then
  echo "[FAIL] test2 detected rebase ambiguity regression"
  exit 1
fi
echo "[PASS] test2"

echo "[TEST3] post-conditions"
if [[ -n "$(git stash list)" ]]; then
  echo "[FAIL] stash not empty after successful run"
  git stash list
  exit 1
fi
echo "[PASS] stash empty"

echo "[SUMMARY] all QA checks passed"
echo "[INFO] test logs: $TMP_DIR/test1.log and $TMP_DIR/test2.log"
