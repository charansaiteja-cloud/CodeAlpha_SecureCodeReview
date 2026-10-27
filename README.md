# CodeAlpha Secure Code Review — Task 3

Local Python/FastAPI security demonstration. Intentionally insecure examples
are isolated in vulnerable_samples; corrected code is in app.

## Install
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run locally
```bash
export LAB_API_KEY='local-demo-key-change-me'
export LAB_DB_PATH=/tmp/codealpha_review.sqlite3
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Test and scan
```bash
python -m pytest -q
python -m compileall -q app vulnerable_samples tests
bandit -r app vulnerable_samples -f txt
semgrep --config .semgrep/rules.yml app vulnerable_samples
```

Do not deploy or import vulnerable_samples. Review actual analyzer output and
report false positives and residual risks. A clean scan is not proof of safety.

## Task mapping
Scope, findings and remediation: reports/
Corrected application: app/
Vulnerable samples: vulnerable_samples/
Regression tests: tests/
Static-analysis rules: .semgrep/rules.yml
