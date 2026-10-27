import json
import subprocess
import hashlib
from pathlib import Path
from typing import List
from app.scanner.base import BaseScanner
from app.models.findings import Finding, Severity

class SemgrepRunner(BaseScanner):
    name = "Semgrep"
    version = "1.50.0"

    def scan(self, target_dir: Path) -> List[Finding]:
        findings: List[Finding] = []
        
        # Check if local virtualenv semgrep exists or use system semgrep
        semgrep_path = ".semgrep-venv/bin/semgrep"
        cmd = [
            semgrep_path if Path(semgrep_path).is_file() else "semgrep",
            "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            str(target_dir)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
                check=False
            )
            
            if not result.stdout.strip():
                return findings

            data = json.loads(result.stdout)
            for item in data.get("results", []):
                file_path = item.get("path", "")
                start_line = item.get("start", {}).get("line", 0)
                end_line = item.get("end", {}).get("line", start_line)
                
                extra = item.get("extra", {})
                rule_id = item.get("check_id", "semgrep.rule")
                title = extra.get("message", "Security Vulnerability Detected").split("\n")[0]
                description = extra.get("message", "")
                
                raw_sev = extra.get("severity", "WARNING").upper()
                severity_map = {
                    "ERROR": Severity.HIGH,
                    "WARNING": Severity.MEDIUM,
                    "INFO": Severity.LOW
                }
                severity = severity_map.get(raw_sev, Severity.MEDIUM)
                
                # Metadata CWE/OWASP mapping if present
                metadata = extra.get("metadata", {})
                cwe_list = metadata.get("cwe", [])
                cwe_id = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else cwe_list

                unique_str = f"{rule_id}:{file_path}:{start_line}"
                finding_id = hashlib.sha256(unique_str.encode("utf-8")).hexdigest()[:16]

                findings.append(
                    Finding(
                        finding_id=finding_id,
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        severity=severity,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=extra.get("lines", "").strip(),
                        remediation=metadata.get("fix", "Review code logic and apply secure coding practices."),
                        cwe_id=str(cwe_id) if cwe_id else None,
                        owasp_mapping=metadata.get("owasp"),
                        scanner_name=self.name,
                        scanner_version=self.version
                    )
                )
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

        return findings
