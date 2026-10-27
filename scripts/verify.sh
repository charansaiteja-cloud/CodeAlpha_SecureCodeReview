#!/usr/bin/env bash
set -u
cd "$(dirname "$0")/.."
mkdir -p reports/evidence
run() {
  name="$1"; shift
  "$@" > "reports/evidence/$name.txt" 2>&1
  rc=$?
  cat "reports/evidence/$name.txt"
  echo "$rc" > "reports/evidence/$name.exitcode"
  echo "$name exit code: $rc"
}
run pytest python -m pytest -q
run compile python -m compileall -q app vulnerable_samples tests
if command -v bandit >/dev/null 2>&1; then
  run bandit-vulnerable bandit -r vulnerable_samples -f txt
  run bandit-corrected bandit -r app -f txt
else
  echo "Bandit not installed"
fi
if command -v semgrep >/dev/null 2>&1; then
  run semgrep-vulnerable semgrep --config .semgrep/rules.yml vulnerable_samples
  run semgrep-corrected semgrep --config .semgrep/rules.yml app
else
  echo "Semgrep not installed; not run"
fi
