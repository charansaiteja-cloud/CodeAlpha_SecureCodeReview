# Secure Code Review Tool — Architecture

```mermaid
flowchart TD
    A[Developer] --> B[GitHub Repository]
    B --> C[GitHub Actions CI]
    C --> D[Pytest]
    C --> E[Bandit]
    C --> F[Semgrep OSS]
    D --> G[Pass or Fail]
    E --> G
    F --> G
    G --> H[Review Results and Fix Findings]
    H --> B
```

## Workflow

1. A developer pushes code or opens a pull request.
2. GitHub Actions starts the configured CI workflow.
3. Pytest checks application behavior.
4. Bandit performs Python security analysis.
5. Semgrep runs custom and OSS security rules.
6. The developer reviews failures or findings and fixes issues.
