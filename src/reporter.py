"""
Report generation utilities for IAM policy analysis results.
"""

import json
from typing import List, Dict, Any
from tabulate import tabulate
from src.analyzer import Finding


class ReportGenerator:
    """Generates reports from IAM policy analysis findings."""
    
    @staticmethod
    def generate_table_report(findings: List[Finding]) -> str:
        """Generate a table format report."""
        if not findings:
            return "✅ No security issues found in the IAM policy."
        
        # Group findings by severity
        severity_order = ['critical', 'high', 'medium', 'low']
        grouped = {severity: [] for severity in severity_order}
        
        for finding in findings:
            grouped[finding.severity].append(finding)
        
        report = []
        
        for severity in severity_order:
            severity_findings = grouped[severity]
            if not severity_findings:
                continue
            
            report.append(f"\n🚨 {severity.upper()} SEVERITY ISSUES ({len(severity_findings)})")
            report.append("=" * 50)
            
            table_data = []
            for finding in severity_findings:
                table_data.append([
                    finding.title,
                    finding.description[:60] + "..." if len(finding.description) > 60 else finding.description,
                    finding.recommendation[:60] + "..." if len(finding.recommendation) > 60 else finding.recommendation
                ])
            
            table = tabulate(
                table_data,
                headers=['Issue', 'Description', 'Recommendation'],
                tablefmt='grid',
                maxcolwidths=[30, 40, 40]
            )
            report.append(table)
        
        # Summary
        total_issues = len(findings)
        critical_count = len(grouped['critical'])
        high_count = len(grouped['high'])
        
        report.insert(0, f"📊 IAM Policy Analysis Summary")
        report.insert(1, f"Total Issues Found: {total_issues}")
        report.insert(2, f"Critical: {critical_count}, High: {high_count}, Medium: {len(grouped['medium'])}, Low: {len(grouped['low'])}")
        report.insert(3, "")
        
        return "\n".join(report)
    
    @staticmethod
    def generate_json_report(findings: List[Finding]) -> str:
        """Generate a JSON format report."""
        report_data = {
            "summary": {
                "total_issues": len(findings),
                "critical": len([f for f in findings if f.severity == 'critical']),
                "high": len([f for f in findings if f.severity == 'high']),
                "medium": len([f for f in findings if f.severity == 'medium']),
                "low": len([f for f in findings if f.severity == 'low'])
            },
            "findings": [
                {
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "policy_statement": finding.policy_statement
                }
                for finding in findings
            ]
        }
        
        return json.dumps(report_data, indent=2)
    
    @staticmethod
    def generate_csv_report(findings: List[Finding]) -> str:
        """Generate a CSV format report."""
        if not findings:
            return "severity,title,description,recommendation\n"
        
        lines = ["severity,title,description,recommendation"]
        
        for finding in findings:
            # Escape quotes and commas for CSV
            title = finding.title.replace('"', '""')
            description = finding.description.replace('"', '""')
            recommendation = finding.recommendation.replace('"', '""')
            
            lines.append(f'"{finding.severity}","{title}","{description}","{recommendation}"')
        
        return "\n".join(lines)


def format_findings(findings: List[Finding], format_type: str = 'table') -> str:
    """Format findings based on the specified format type."""
    generator = ReportGenerator()
    
    if format_type == 'json':
        return generator.generate_json_report(findings)
    elif format_type == 'csv':
        return generator.generate_csv_report(findings)
    else:  # default to table
        return generator.generate_table_report(findings)
