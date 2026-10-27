# CodeAlpha Secure Coding Review

## Scope and threat model
This audit covers the local Python sample, isolated insecure examples,
corrected FastAPI code, tests, and static analysis. No external systems,
production data, or real credentials are in scope. Assets include database
records, API responses, and authentication configuration. An attacker may
submit malformed HTTP parameters or attempt unauthenticated access.

## F-01: SQL injection risk
Severity: High if attacker-controlled input reaches unsafe_lookup.
Evidence: SQL is constructed by concatenating name into the query.
Impact: SQL syntax could be altered, subject to database privileges.
Safe reproduction: inspect source only; do not execute hostile input.
Remediation: parameterized queries, implemented in app/main.py.
Test: test_sql_metacharacters_are_data and test_create_and_search.
Residual risk: authorization and data ownership require separate review.

## F-02: Shell command injection risk
Severity: High if unsafe_preview receives untrusted input.
Evidence: command string concatenation and shell=True.
Impact: shell metacharacters may execute unintended commands.
Safe reproduction: static inspection only; do not invoke the function.
Remediation: avoid the shell and use a fixed executable with argument list.
Implementation: this feature is absent from the corrected app.
Residual risk: review any future subprocess feature separately.

## F-03: Unsafe pickle deserialization
Severity: High for attacker-controlled bytes.
Evidence: pickle.loads(data).
Impact: deserialization may execute attacker-controlled Python behavior.
Safe reproduction: static inspection only; no malicious payload required.
Remediation: use a constrained format such as JSON and validate its schema.
Implementation: the corrected app does not deserialize pickle.
Residual risk: JSON still needs size and schema limits.

## F-04: Password-like value in source
Severity: Informational for the explicitly fictional placeholder; potentially
High if a real reusable credential were committed.
Evidence: DEMO_PASSWORD in the insecure sample.
Impact: real committed secrets can be copied and reused.
Remediation: remove real secrets, use managed configuration, rotate exposures.
Test: test_missing_config_fails_closed.
Residual risk: environment variables are not a full secrets manager.

## F-05: Verbose exception disclosure
Severity: Low to Medium depending on reachability and exception content.
Evidence: unsafe_divide returns str(exc) and repr(exc).
Impact: callers may learn internal implementation details.
Remediation: generic client errors and sanitized restricted logs.
Implementation: corrected endpoints return generic HTTP errors.
Residual risk: production logging and exception handling need review.

## Corrected controls
The corrected application uses SQL parameters, constrained input, an API-key
dependency that fails closed, debug=False, and baseline security headers.

## Limitations
Static analysis and tests cannot prove the absence of vulnerabilities.
This demonstration does not implement production identity management,
rate limiting, TLS termination, full role-based authorization, or deployment
hardening. Record actual scanner output, tool versions, and test counts after
running verification.
