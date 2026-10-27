# CodeAlpha Secure Coding Review

**Audit date:** 2026-10-27
**Scope:** corrected FastAPI application, scanner integration, tests, CI workflow, dependency declarations, container configuration, and the intentionally vulnerable educational fixtures.
**Method:** manual source review, threat modeling, regression tests, Bandit, local Semgrep rules, the `p/python` Semgrep registry ruleset, `pip check`, `pip-audit`, and CI configuration review.

No production systems, production data, or real credentials were in scope.

## 1. Threat Model

### Assets

- Items stored in the SQLite database.
- The `LAB_API_KEY` shared secret and protected API routes.
- Files readable by the application user through the scan endpoint.
- Integrity of scanner results used for security decisions.
- The CI workflow and its repository token permissions.

### Entry points

- Unauthenticated `/health`.
- API-key-protected item, demo, and scan routes.
- Request bodies and query parameters, especially `name`, `q`, `target_path`, and `item_id`.
- Scanner subprocess invocation and JSON parsing.
- GitHub Actions triggers and third-party action references.

### Adversaries considered

- An unauthenticated remote caller.
- An authenticated caller sending malformed or hostile values.
- A caller attempting path traversal or symlink escape.
- A malicious or compromised dependency or action.
- A developer accidentally treating a failed or skipped scanner as a pass.

### Security objectives

- Reject unauthenticated access and fail closed when unconfigured.
- Treat SQL input as data, not syntax.
- Keep scan targets inside an allowed root and bound their size.
- Never hide scanner failures or findings.
- Keep CI permissions minimal and third-party actions pinned.
- Document residual risk honestly.

## 2. Application Findings

The intentionally vulnerable functions are isolated in `vulnerable_samples/insecure_examples.py`. They are detection fixtures, not code paths of the corrected application. Each was reviewed and matched against a maintained rule and a safe alternative.

| ID | Weakness | Fixture evidence | Severity in fixture | Corrected application | Detection / regression |
| --- | --- | --- | --- | --- | --- |
| F-01 | SQL injection | `unsafe_lookup` concatenates `name` into SQL | High if reachable | Bound parameters in `get_item`, `create_item`, and `search_items`; LIKE wildcards escaped | `B608`, `codealpha.python.sql-string-construction`, `test_sql_metacharacters_are_data`, `test_like_wildcards_are_treated_as_literal_text` |
| F-02 | OS command injection | `unsafe_preview` uses command concatenation and `shell=True` | High if reachable | No shell-executed feature; scanner subprocesses use argument lists and `shell=False` | `B602`, `codealpha.python.subprocess-shell-true`, safe benchmark assertion |
| F-03 | Unsafe deserialization | `pickle.loads(data)` | High for attacker-controlled bytes | The application does not deserialize pickle; API input is JSON/Pydantic-validated | `B301`, `codealpha.python.pickle-deserialization` |
| F-04 | Dynamic code execution | `eval(expression)` | High if reachable | No `eval`/`exec` in application code | `B307`, `codealpha.python.dynamic-code-execution`, benchmark test |
| F-05 | Unsafe YAML loading | `yaml.load(..., Loader=yaml.Loader)` | High for untrusted YAML | No YAML input in the application; safe benchmark uses `yaml.safe_load` | `B506`, `codealpha.python.unsafe-yaml-load` |
| F-06 | Disabled TLS verification | `requests.get(url, verify=False)` | High for sensitive traffic | The application makes no outbound HTTP requests | `B501`, `codealpha.python.disabled-tls-verification` |
| F-07 | Insecure temporary file | `tempfile.mktemp()` | Medium (race condition) | No temporary-file generation in the application | `B306`, `codealpha.python.insecure-tempfile` |
| F-08 | Hard-coded credential | Fictional `DEMO_PASSWORD` string literal | Informational for the placeholder; High if a real credential | Runtime secret read from `LAB_API_KEY`; `.env` ignored; Compose requires an environment value | `B105`, `codealpha.python.hardcoded-secret`, `test_missing_config_fails_closed` |
| F-09 | Verbose exception disclosure | `unsafe_divide` returns `str(exc)` and `repr(exc)` | Low to Medium | API errors are generic; unexpected scan errors are logged server-side and return 500 | Scanner/API tests; source review |

### Application controls verified

- **Authentication:** protected routes require `X-API-Key`; missing, wrong, oversized, or unconfigured keys return 401. Comparison uses `hmac.compare_digest` over UTF-8 bytes and handles encoding failures as invalid.
- **Input constraints:** item names are 1–64 characters, must contain non-whitespace, and reject control characters. Search terms are capped at 64 characters. Scan target paths are capped at 256 characters and reject control characters.
- **SQL handling:** all item SQL uses bound parameters. The search pattern escapes `!`, `%`, and `_` and uses `ESCAPE '!'`, preventing wildcard injection.
- **Path containment:** scan targets are resolved and checked with `Path.is_relative_to`, not string prefixes. A sibling-prefix bypass is covered by a regression test. Excluded directories and symlink escapes are rejected.
- **Resource bounds:** scan files are capped (default 2000) and one scan runs per process; a concurrent request receives 429. Both scanner failures produce 503.
- **Headers:** strict API CSP (`default-src 'none'`), HSTS, frame denial, `nosniff`, `no-store`, no-referrer, permissions policy, COOP/CORP, and `X-XSS-Protection: 0`. The relaxed documentation CSP is scoped to documentation paths only.
- **Documentation:** Swagger/OpenAPI is disabled unless `LAB_ENABLE_DOCS` is explicitly enabled.
- **Database:** SQLite connections use a timeout and are closed per request; a missing parent directory is created.

### Findings in the corrected application

No medium/high Bandit findings and no local Semgrep findings were identified in `app/` at this revision. The `p/python` registry scan also reported zero findings. These results reduce known risk; they do not prove the absence of vulnerabilities.

## 3. Build and CI Findings

| ID | Finding | Impact | Resolution |
| --- | --- | --- | --- |
| C-01 | Two workflows shared the name `Secure Code Review CI` and the same triggers (`ci.yml` and `security.yml`) | Duplicate/conflicting results; one could pass while the other failed | Removed `security.yml`; one consolidated `ci.yml` remains |
| C-02 | `--config auto` was combined with `SEMGREP_SEND_METRICS=off` | Semgrep failed with “Cannot create auto config when metrics are off” | All scans use explicit configs (`.semgrep/rules.yml` or `p/python`) with metrics off |
| C-03 | Semgrep findings did not fail the build without `--error`; the old CI also used `continue-on-error` | False green result | Added `--error`; removed `continue-on-error`; scanner failures remain visible |
| C-04 | Different Bandit thresholds and scan targets between workflows (`-lll` vs `-ll`) | Inconsistent policy and missed medium findings | One policy: `bandit -r app -ll`; fixtures are covered by tests |
| C-05 | CI used field-level action tags and broad default permissions | Supply-chain and token-exposure risk | Pinned checkout/setup-python to full SHAs, `permissions: contents: read`, `persist-credentials: false`, and concurrency cancellation |
| C-06 | Dependency audit was not a blocking, strict step | Known vulnerable dependencies could pass | `pip-audit --strict -r requirements-dev.txt` is blocking; runtime/dev requirements are split |
| C-07 | The local ruleset covered only two classes | Weak custom detection coverage | Expanded to eight maintained rules with fixture coverage and validation |
| C-08 | Generated scans could include virtual environments, caches, or the database; the API lacked a scan cap and concurrency guard | Unbounded work and noisy results | Explicit file collection, exclusions, file cap, scan-root containment, and one in-process scan slot |
| C-09 | Docker ran as root and copied unnecessary files | Larger attack surface | Non-root user, runtime-only copy, read-only Compose filesystem, dropped capabilities, required API key |

### Token-length review

The application does not make assumptions about GitHub token lengths or `ghs_...` token formats. Authentication is limited to the runtime `X-API-Key` and rejects values longer than 4096 characters before comparison. No code change was warranted for GitHub token handling.

## 4. Verification Results

Local run on 2026-10-27:

| Check | Command | Result |
| --- | --- | --- |
| Tests | `python -m pytest -q` | `64 passed` |
| Compilation | `python -m compileall -q app tests benchmarks vulnerable_samples` | Exit 0 |
| Dependency consistency | `python -m pip check` | No broken requirements |
| Bandit application | `python -m bandit -r app -ll` | Exit 0; 0 medium/high; 2 low below threshold |
| Local Semgrep | `semgrep scan --config .semgrep/rules.yml --metrics=off --error --strict --disable-version-check --no-rewrite-rule-ids app` | 8 rules, 0 findings, exit 0 |
| Registry Semgrep | `semgrep scan --config p/python --metrics=off --error --strict --disable-version-check app` | 151 rules, 0 findings, exit 0 |
| Fixture Semgrep | Same local command against `vulnerable_samples` | All eight classes detected; expected exit 1 |
| Fixture Bandit | `python -m bandit -r vulnerable_samples` | Expected findings; expected exit 1 |
| Dependency audit | `python -m pip_audit --strict -r requirements-dev.txt` | No known vulnerabilities |
| Local gate | `bash scripts/verify.sh` | All verification checks passed |

Tool versions: Python 3.14.8, Bandit 1.9.4, Semgrep 1.79.0, pip-audit installed in the local virtual environment. CI uses Python 3.11/3.12; its remote result must be confirmed after the commit is pushed. No remote CI success is claimed here.

## 5. Residual Risk and Limitations

- Static analysis is pattern-based and can miss vulnerable data flows or report false positives.
- The local rules cover eight classes, not the full Python attack surface. `p/python` coverage varies by ruleset revision.
- The scan endpoint runs trusted tools against files readable by the application user. The scan root, file cap, exclusions, timeouts, and API key reduce exposure but are not a sandbox.
- The single semaphore bounds concurrency in one process only; there is no distributed rate limiting.
- The API key is a shared secret, not per-user identity, authorization, or tenant isolation.
- TLS termination, secrets management, audit logging, monitoring, and incident response are not implemented.
- SQLite is appropriate for the lab, not concurrent multi-instance production use.
- Dependency audit results reflect advisories known at scan time.
- Container hardening is a baseline; no image signing, SBOM attestation, or runtime policy is included.
- A clean scan is evidence for a specific revision, rule set, and configuration, not a guarantee.

## 6. Conclusion

The corrected application and the consolidated CI workflow are materially safer than the starting state. The original Semgrep failure is fixed by removing auto-configuration while keeping metrics off, and the false-green conditions are fixed by `--error`, removal of `continue-on-error`, explicit scanner status handling, and a single blocking policy. The vulnerable fixtures remain intentionally vulnerable and are isolated from the application gate.
