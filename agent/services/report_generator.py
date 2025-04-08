"""
Report generator for Solidity audit results.
"""
import json
import os
from typing import Dict, List, Any, Optional
import datetime
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

from agent.models.solidity_file import SolidityFile
from agent.models.audit_result import AuditResult, Vulnerability


class ReportGenerator:
    """Generator for different formats of audit reports."""
    
    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the report generator.
        
        Args:
            template_dir: Directory containing report templates
        """
        if template_dir is None:
            # Use default templates directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(os.path.dirname(os.path.dirname(current_dir)), "templates")
        
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))
    
    def generate_text_report(self, audit_result: AuditResult) -> str:
        """
        Generate a plain text report.
        
        Args:
            audit_result: Audit result to generate report for
            
        Returns:
            Text report
        """
        template = self.env.get_template("text_report.txt")
        return template.render(
            audit_result=audit_result,
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    
    def generate_json_report(self, audit_result: AuditResult) -> str:
        """
        Generate a JSON report.
        
        Args:
            audit_result: Audit result to generate report for
            
        Returns:
            JSON report
        """
        report_data = {
            "audit_id": audit_result.audit_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "files_analyzed": [file.path for file in audit_result.files],
            "vulnerabilities": []
        }
        
        for vuln in audit_result.vulnerabilities:
            vuln_data = {
                "id": vuln.id,
                "name": vuln.name,
                "description": vuln.description,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "locations": [
                    {
                        "file": loc.file,
                        "line_start": loc.line_start,
                        "line_end": loc.line_end,
                        "code_snippet": loc.code_snippet
                    } for loc in vuln.locations
                ],
                "impact": vuln.impact,
                "remediation": vuln.remediation,
                "references": vuln.references
            }
            report_data["vulnerabilities"].append(vuln_data)
        
        return json.dumps(report_data, indent=2)
    
    def generate_sarif_report(self, audit_result: AuditResult) -> str:
        """
        Generate a SARIF report.
        
        Args:
            audit_result: Audit result to generate report for
            
        Returns:
            SARIF report
        """
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Solidity Audit Agent",
                            "informationUri": "https://github.com/agent4rena/agent-template",
                            "version": "1.0.0",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Add rules
        rule_index = {}
        for i, vuln in enumerate(audit_result.vulnerabilities):
            rule_id = f"SOLIDITY-{vuln.id}"
            rule_index[vuln.id] = rule_id
            
            rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": vuln.name
                },
                "fullDescription": {
                    "text": vuln.description
                },
                "help": {
                    "text": f"Impact: {vuln.impact}\n\nRemediation: {vuln.remediation}"
                },
                "properties": {
                    "security-severity": str(vuln.cvss_score),
                    "tags": ["security", "solidity", "smart-contract"]
                }
            }
            
            sarif_data["runs"][0]["tool"]["driver"]["rules"].append(rule)
        
        # Add results
        for vuln in audit_result.vulnerabilities:
            for loc in vuln.locations:
                result = {
                    "ruleId": rule_index[vuln.id],
                    "level": "error" if vuln.severity in ["HIGH", "CRITICAL"] else "warning",
                    "message": {
                        "text": f"{vuln.name}: {vuln.description}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": loc.file
                                },
                                "region": {
                                    "startLine": loc.line_start,
                                    "endLine": loc.line_end,
                                    "snippet": {
                                        "text": loc.code_snippet
                                    }
                                }
                            }
                        }
                    ]
                }
                
                sarif_data["runs"][0]["results"].append(result)
        
        return json.dumps(sarif_data, indent=2)
    
    def generate_html_report(self, audit_result: AuditResult, output_path: str) -> str:
        """
        Generate an HTML report.
        
        Args:
            audit_result: Audit result to generate report for
            output_path: Path to save the HTML report
            
        Returns:
            Path to the generated HTML report
        """
        template = self.env.get_template("html_report.html")
        
        html_content = template.render(
            audit_result=audit_result,
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return output_path