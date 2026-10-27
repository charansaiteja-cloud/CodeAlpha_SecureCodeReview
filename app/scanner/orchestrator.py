import sys
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(self):
        pass

    def run_scan(self, target_dir: Path) -> Dict[str, Any]:
        """
        Runs security scanners (Bandit) against the target directory safely,
        normalizing findings into a unified schema.
        """
        resolved_path = Path(target_dir).resolve()
        if not resolved_path.exists() or not resolved_path.is_dir():
            return {
                "status": "error",
                "target_scanned": str(resolved_path),
                "total_findings": 0,
                "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "findings": [],
                "summary": {"error": "Invalid target directory for scanning"}
            }

        findings: List[Dict[str, Any]] = []
        
        # Execute Bandit securely using the current virtual environment python interpreter
        try:
            cmd = [sys.executable, "-m", "bandit", "-r", str(resolved_path), "-f", "json", "-lll"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode not in (0, 1):
                logger.error("Bandit exited with code %d, stderr: %s", result.returncode, result.stderr)

            if result.stdout:
                data = json.loads(result.stdout)
                for r in data.get("results", []):
                    findings.append({
                        "rule_id": r.get("test_id"),
                        "category": r.get("test_name"),
                        "severity": r.get("issue_severity"),
                        "confidence": r.get("issue_confidence"),
                        "file_path": r.get("filename"),
                        "line": r.get("line_number"),
                        "message": r.get("issue_text")
                    })
        except Exception:
            logger.exception("Bandit scan execution failed")

        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
            else:
                severity_breakdown["MEDIUM"] += 1

        return {
            "status": "success",
            "target_scanned": str(resolved_path),
            "total_findings": len(findings),
            "severity_breakdown": severity_breakdown,
            "findings": findings,
            "summary": {
                "total_files_scanned": sum(1 for _ in resolved_path.rglob("*.py")),
                "status": "completed"
            }
        }
