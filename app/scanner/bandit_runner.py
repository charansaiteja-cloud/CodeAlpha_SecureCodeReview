import json
import subprocess
import hashlib
from pathlib import Path
from typing import List
from app.scanner.base import BaseScanner
from app.models.findings import Finding, Severity

class BanditRunner(BaseScanner):
    name = "Bandit"
    version = "1.7.5"

    def scan(self, target_dir: Path) -> List[Finding]:
        findings: List[Finding] = []
        cmd = [
            "bandit",
            "-r",
            str(target_dir),
            "-f",
            "json",
            "-q"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            # Bandit returns exit code 1 if issues are found, 0 if clean. Other codes indicate errors.
            if result.returncode not in (0, 1):
                return findings

            if not result.stdout.strip():
                return findings

            data = json.loads(result.stdout)
            for item in data.get("results", []):
                file_path = item.get("filename", "")
                line_number = item.get("line_number", 0)
                rule_id = item.get("test_id", "B000")
                title = item.get("test_name", "Security Issue")
                description = item.get("issue_text", "")
                raw_severity = item.get("issue_severity", "MEDIUM").upper()
                
                # Map Bandit severity to our model
                severity_map = {
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW
                }
                severity = severity_map.get(raw_severity, Severity.MEDIUM)

                # Generate stable unique ID for deduplication
                unique_str = f"{rule_id}:{file_path}:{line_number}"
                finding_id = hashlib.sha256(unique_str.encode("utf-8")).hexdigest()[:16]

                findings.append(
                    Finding(
                        finding_id=finding_id,
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        file_path=file_path,
                        start_line=line_number,
                        end_line=item.get("line_range", [line_number])[-1],
                        code_snippet=item.get("code", "").strip(),
                        remediation="Review secure coding guidelines for Python and remediate vulnerable pattern.",
                        scanner_name=self.name,
                        scanner_version=self.version
                    )
                )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

        return findings
