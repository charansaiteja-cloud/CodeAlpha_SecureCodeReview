import json
from pathlib import Path
from typing import Dict, Any, List
from app.models.findings import Finding

class ReportService:
    @staticmethod
    def generate_json_report(scan_results: Dict[str, Any]) -> str:
        return json.dumps(scan_results, indent=2)

    @staticmethod
    def generate_sarif_report(scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Converts normalized scan findings into SARIF v2.1.0 format
        compatible with GitHub Code Scanning.
        """
        findings = scan_results.get("findings", [])
        rules_dict = {}
        results = []

        for f in findings:
            rule_id = f.get("rule_id", "UNKNOWN")
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": f.get("title", rule_id),
                    "shortDescription": {"text": f.get("title", "")},
                    "fullDescription": {"text": f.get("description", "")},
                    "help": {"text": f.get("remediation", "")},
                    "properties": {
                        "security-severity": "8.0" if f.get("severity") in ["HIGH", "CRITICAL"] else "4.0"
                    }
                }

            results.append({
                "ruleId": rule_id,
                "message": {"text": f.get("description", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("file_path", "")},
                            "region": {
                                "startLine": f.get("start_line", 1),
                                "endLine": f.get("end_line", f.get("start_line", 1))
                            }
                        }
                    }
                ]
            })

        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeAlpha SecureCodeReview",
                            "version": "2.0.0",
                            "rules": list(rules_dict.values())
                        }
                    },
                    "results": results
                }
            ]
        }
        return sarif_report
