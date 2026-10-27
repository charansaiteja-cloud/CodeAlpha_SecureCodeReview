import sys
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

class ScanOrchestrator:
    def __init__(self):
        pass

    def run_scan(self, target_dir: Path) -> Dict[str, Any]:
        """
        Runs security scanners (Bandit and Semgrep) against the target directory safely,
        explicitly verifying tool health, handling timeouts, and enforcing numeric severity ranking.
        """
        resolved_path = Path(target_dir).resolve()
        if not resolved_path.exists() or not resolved_path.is_dir():
            return {
                "status": "error",
                "target_scanned": str(resolved_path),
                "total_findings": 0,
                "severity_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "findings": [],
                "summary": {"error": "Invalid target directory for scanning", "scanners_healthy": False}
            }

        findings: List[Dict[str, Any]] = []
        scanner_statuses = {"bandit": "failed", "semgrep": "failed"}

        # 1. Run Bandit SAST
        try:
            bandit_cmd = [sys.executable, "-m", "bandit", "-r", str(resolved_path), "-f", "json", "-lll"]
            bandit_res = subprocess.run(bandit_cmd, capture_output=True, text=True, timeout=30)
            
            if bandit_res.returncode in (0, 1) and bandit_res.stdout:
                scanner_statuses["bandit"] = "success"
                data = json.loads(bandit_res.stdout)
                for r in data.get("results", []):
                    findings.append({
                        "tool": "bandit",
                        "rule_id": r.get("test_id"),
                        "category": r.get("test_name"),
                        "severity": r.get("issue_severity", "MEDIUM").upper(),
                        "confidence": r.get("issue_confidence"),
                        "file_path": r.get("filename"),
                        "line": r.get("line_number"),
                        "message": r.get("issue_text")
                    })
            else:
                logger.error("Bandit execution failed with code %d", bandit_res.returncode)
        except Exception:
            logger.exception("Bandit scan execution encountered an exception")

        # 2. Run Semgrep SAST with explicit custom rules if present
        try:
            rules_path = Path(".semgrep/rules.yml")
            semgrep_config = str(rules_path) if rules_path.exists() else "auto"
            
            semgrep_cmd = ["semgrep", "scan", "--config", semgrep_config, "--json", str(resolved_path)]
            semgrep_res = subprocess.run(semgrep_cmd, capture_output=True, text=True, timeout=45)

            if semgrep_res.returncode in (0, 1) and semgrep_res.stdout:
                scanner_statuses["semgrep"] = "success"
                s_data = json.loads(semgrep_res.stdout)
                for r in s_data.get("results", []):
                    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                    raw_sev = r.get("extra", {}).get("severity", "WARNING").upper()
                    severity = sev_map.get(raw_sev, "MEDIUM")
                    
                    findings.append({
                        "tool": "semgrep",
                        "rule_id": r.get("check_id"),
                        "category": "Custom Semgrep Rule",
                        "severity": severity,
                        "confidence": "HIGH",
                        "file_path": r.get("path"),
                        "line": r.get("start", {}).get("line"),
                        "message": r.get("extra", {}).get("message")
                    })
            else:
                logger.warning("Semgrep execution skipped or failed (return code %d)", semgrep_res.returncode)
        except Exception:
            logger.exception("Semgrep scan execution encountered an exception")

        # Deduplicate findings using explicit numeric severity ranking (highest weight retained)
        deduped_map: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            key = f"{f.get('file_path')}:{f.get('line')}:{f.get('rule_id')}"
            existing = deduped_map.get(key)
            if not existing:
                deduped_map[key] = f
            else:
                curr_weight = SEVERITY_WEIGHTS.get(f.get("severity", "MEDIUM"), 2)
                exist_weight = SEVERITY_WEIGHTS.get(existing.get("severity", "MEDIUM"), 2)
                if curr_weight > exist_weight:
                    deduped_map[key] = f

        final_findings = list(deduped_map.values())

        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in final_findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in severity_breakdown:
                severity_breakdown[sev] += 1
            else:
                severity_breakdown["MEDIUM"] += 1

        overall_status = "success" if all(s == "success" for s in scanner_statuses.values()) else "partial"

        return {
            "status": overall_status,
            "target_scanned": str(resolved_path),
            "total_findings": len(final_findings),
            "severity_breakdown": severity_breakdown,
            "findings": final_findings,
            "summary": {
                "total_files_scanned": sum(1 for _ in resolved_path.rglob("*.py")),
                "scanner_statuses": scanner_statuses,
                "status": "completed" if overall_status == "success" else "completed_with_warnings"
            }
        }
