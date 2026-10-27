from pathlib import Path
from app.scanner.orchestrator import ScanOrchestrator

def test_benchmark_detection_rate():
    """
    Benchmarks the ScanOrchestrator against controlled vulnerable and safe samples.
    Verifies that true positives are detected in vulnerable code.
    """
    benchmarks_dir = Path("benchmarks").resolve()
    assert benchmarks_dir.is_dir(), "Benchmarks directory must exist."

    orchestrator = ScanOrchestrator()
    results = orchestrator.run_scan(benchmarks_dir)

    findings = results.get("findings", [])

    # Verify that true-positive findings were detected in the benchmark suite
    assert isinstance(findings, list)
    assert len(findings) > 0, "Benchmark failed: Expected findings in vulnerable sample but found none."

    rule_ids = {f.get("rule_id") for f in findings}
    print(f"Benchmark successfully detected rule IDs: {rule_ids}")
