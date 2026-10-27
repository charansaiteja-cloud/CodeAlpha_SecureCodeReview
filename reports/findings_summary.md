# Findings Summary

The intentionally insecure fixture `vulnerable_samples/insecure_examples.py` contains the weaknesses below. They are source-level review and scanner-calibration targets, not production code. The corrected application either implements the safe pattern or does not contain the feature at all.

| Weakness | Fixture function | Local Semgrep rule | Bandit rule | Corrected application |
| --- | --- | --- | --- | --- |
| SQL injection | `unsafe_lookup` | `codealpha.python.sql-string-construction` | `B608` | Parameterized SQL; literal LIKE escaping |
| Shell command injection | `unsafe_preview` | `codealpha.python.subprocess-shell-true` | `B602` (also `B404`) | No shell-executed feature; scanner subprocesses use argv lists |
| Unsafe pickle deserialization | `unsafe_load` | `codealpha.python.pickle-deserialization` | `B301` (also `B403`) | No pickle input; JSON/Pydantic validation |
| Dynamic code execution | `unsafe_eval` | `codealpha.python.dynamic-code-execution` | `B307` | No `eval`/`exec` in application code |
| Unsafe YAML loading | `unsafe_yaml` | `codealpha.python.unsafe-yaml-load` | `B506` | No YAML input; safe benchmark uses `safe_load` |
| Disabled TLS verification | `unsafe_request` | `codealpha.python.disabled-tls-verification` | `B501` | No outbound HTTP requests |
| Insecure temporary file | `unsafe_tempfile` | `codealpha.python.insecure-tempfile` | `B306` | No temporary-file generation |
| Hard-coded credential | `DEMO_PASSWORD` | `codealpha.python.hardcoded-secret` | `B105` | Runtime `LAB_API_KEY`; fail closed when unset |
| Verbose exception disclosure | `unsafe_divide` | Manual review only | Not directly detected | Generic API errors; server-side logging |

The fixtures also trigger Bandit import notices `B403` (pickle) and `B404` (subprocess). Those are supporting signals, not separate vulnerability classes.

## Current detection evidence

- Local Semgrep rules on `vulnerable_samples/`: 8 findings, one for each maintained rule class; expected exit code 1 with `--error`.
- Bandit on `vulnerable_samples/`: 10 findings across the rule IDs above; expected exit code 1.
- Local Semgrep rules on `app/`: 0 findings.
- Bandit on `app/ -ll`: no medium/high findings (2 low-severity results are below the configured threshold).
- `benchmarks/safe_sample.py`: no findings from either scanner; `benchmarks/vulnerable_sample.py` is detected.

These counts demonstrate that the rules work against the fixtures and are quiet on the corrected scope. They are **not** a claim that the application is vulnerability-free. Exact commands, tool versions, and limitations are recorded in [`security_audit.md`](security_audit.md) and [`../docs/security-policy.md`](../docs/security-policy.md).
