from pathlib import Path
from typing import List, Dict, Any
from app.models.findings import Finding
from app.scanner.bandit_runner import BanditRunner
from app.scanner.semgrep_runner import SemgrepRunner

class ScanOrchestrator:
    def __init__(self):
        self.scanners = [
            BanditRunner(),
            SemgrepRunner()
        ]

    def run_scan(self, target_dir: Path) -> Dict[str, Any]:
        """
        Runs all registered scanners against the target directory,
        deduplicates overlapping findings, and returns an aggregated result summary.
        """
        if not target_dir.exists() or not target_dir.is_dir():
            raise ValueError(f"Invalid target directory for scanning: {target_dir}")

        raw_findings: List[Finding] = []
        scanner_errors: Dict[str, str] = {}

        for scanner in self.scanners:
            try:
                results = scanner.scan(target_dir)
                raw_findings.extend(results)
            except Exception as e:
                scanner_errors[scanner.name] = str(e)

        # Deduplicate findings based on stable identity (rule_id + file_path + start_line)
        unique_findings_map: Dict[str, Finding] = {}
        for finding in raw_findings:
            key = f"{finding.rule_id}:{finding.file_path}:{finding.start_line}"
            if key not in unique_findings_map:
                unique_findings_map[key] = finding
            else:
                # Keep highest severity or merge scanners if needed
                existing = unique_findings_map[key]
                if finding.severity.value > existing.severity.value:
                    unique_findings_map[key] = finding

        deduplicated_findings = list(unique_findings_map.values())

        # Count by severity
        severity_counts = {
            "CRITICAL": sum(1 for f in deduplicated_findings if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in deduplicated_findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in deduplicated_findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in deduplicated_findings if f.severity == "LOW"),
            "INFORMATIONAL": sum(1 for f in deduplicated_findings if f.severity == "INFORMATIONAL"),
        }

        return {
            "status": "completed" if not scanner_errors else "partial",
            "target_scanned": str(target_dir),
            "total_findings": len(deduplicated_findings),
            "severity_breakdown": severity_counts,
            "findings": [f.model_dump() for f in deduplicated_findings],
            "scanner_errors": scanner_errors
        }
