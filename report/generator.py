"""Report Generator - Generate reports in various formats."""

import json
from datetime import datetime
from typing import Dict, Any, List


class ReportGenerator:
    """Generate security scan reports."""
    
    def __init__(self, results: Dict[str, Any]):
        """Initialize with scan results."""
        self.results = results
    
    def to_json(self, indent: int = 2) -> str:
        """Generate JSON report."""
        return json.dumps(self.results, indent=indent, default=str)
    
    def to_markdown(self) -> str:
        """Generate Markdown report."""
        lines = []
        
        # Header
        lines.append(f"# Security Scan Report: {self.results.get('target', 'Unknown')}")
        lines.append("")
        lines.append(f"**Scan Time:** {self.results.get('scan_time', 'Unknown')}")
        lines.append(f"**Scanner Version:** {self.results.get('scanner_version', 'Unknown')}")
        lines.append("")
        
        # Risk Score
        risk_score = self.results.get("risk_score", 0)
        risk_level = self._get_risk_level(risk_score)
        lines.append(f"## Risk Score: {risk_score}/100 ({risk_level})")
        lines.append("")
        
        # Summary
        summary = self.results.get("severity_summary", {})
        lines.append("### Findings Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {summary.get('critical', 0)} |")
        lines.append(f"| High | {summary.get('high', 0)} |")
        lines.append(f"| Medium | {summary.get('medium', 0)} |")
        lines.append(f"| Low | {summary.get('low', 0)} |")
        lines.append(f"| Info | {summary.get('info', 0)} |")
        lines.append("")
        
        # Findings by severity
        findings = self.results.get("findings", [])
        if findings:
            lines.append("## Findings")
            lines.append("")
            
            for severity in ["critical", "high", "medium", "low", "info"]:
                severity_findings = [f for f in findings if f.get("severity", "").lower() == severity]
                if severity_findings:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "")
                    lines.append(f"### {emoji} {severity.upper()}")
                    lines.append("")
                    
                    for finding in severity_findings:
                        lines.append(f"#### {finding.get('title', 'Unknown')}")
                        lines.append("")
                        lines.append(f"**Module:** {finding.get('module', 'Unknown')}")
                        lines.append("")
                        lines.append(finding.get("description", ""))
                        lines.append("")
                        
                        if finding.get("remediation"):
                            lines.append(f"**Remediation:** {finding['remediation']}")
                            lines.append("")
                        
                        if finding.get("references"):
                            lines.append("**References:**")
                            for ref in finding["references"]:
                                lines.append(f"- {ref}")
                            lines.append("")
        
        # Module Results
        lines.append("## Module Details")
        lines.append("")
        
        module_results = self.results.get("module_results", {})
        for module_name, module_data in module_results.items():
            lines.append(f"### {module_name.upper()}")
            lines.append("")
            
            if module_data.get("error"):
                lines.append(f"⚠️ Error: {module_data['error']}")
            else:
                # Module-specific summaries
                if module_name == "dns":
                    if module_data.get("dnssec", {}).get("enabled"):
                        lines.append("✅ DNSSEC: Enabled")
                    else:
                        lines.append("❌ DNSSEC: Not enabled")
                    
                    email_sec = module_data.get("email_security", {})
                    lines.append(f"- SPF: {'✅' if email_sec.get('spf', {}).get('present') else '❌'}")
                    lines.append(f"- DMARC: {'✅' if email_sec.get('dmarc', {}).get('present') else '❌'}")
                
                elif module_name == "ssl":
                    cert = module_data.get("certificate", {})
                    if cert.get("expired"):
                        lines.append("❌ Certificate: EXPIRED")
                    elif cert.get("expires_in_days", 0) <= 30:
                        lines.append(f"⚠️ Certificate: Expires in {cert.get('expires_in_days')} days")
                    else:
                        lines.append(f"✅ Certificate: Valid ({cert.get('expires_in_days')} days)")
                
                elif module_name == "ports":
                    open_ports = module_data.get("open_ports", [])
                    lines.append(f"Open ports: {', '.join(map(str, open_ports)) or 'None detected'}")
                
                elif module_name == "subdomains":
                    subs = module_data.get("subdomains", [])
                    lines.append(f"Found {len(subs)} subdomains")
                    if subs:
                        for sub in subs[:10]:
                            lines.append(f"  - {sub}")
                        if len(subs) > 10:
                            lines.append(f"  - ... and {len(subs) - 10} more")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def to_html(self) -> str:
        """Generate HTML report."""
        risk_score = self.results.get("risk_score", 0)
        risk_level = self._get_risk_level(risk_score)
        risk_color = self._get_risk_color(risk_score)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {self.results.get('target', 'Unknown')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #1a1a1a; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        h3 {{ color: #555; }}
        .risk-score {{
            font-size: 48px;
            font-weight: bold;
            color: {risk_color};
            text-align: center;
            padding: 20px;
        }}
        .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .summary-table th, .summary-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .summary-table th {{ background: #f8f9fa; }}
        .finding {{
            border-left: 4px solid #ccc;
            padding: 15px;
            margin: 10px 0;
            background: #fafafa;
            border-radius: 0 4px 4px 0;
        }}
        .finding.critical {{ border-color: #dc3545; background: #fff5f5; }}
        .finding.high {{ border-color: #fd7e14; background: #fff8f0; }}
        .finding.medium {{ border-color: #ffc107; background: #fffdf0; }}
        .finding.low {{ border-color: #17a2b8; background: #f0f9ff; }}
        .finding.info {{ border-color: #6c757d; background: #f8f9fa; }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: #dc3545; color: white; }}
        .severity-badge.high {{ background: #fd7e14; color: white; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #17a2b8; color: white; }}
        .severity-badge.info {{ background: #6c757d; color: white; }}
        .meta {{ color: #666; font-size: 14px; }}
        .remediation {{ background: #e8f5e9; padding: 10px; border-radius: 4px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Security Scan Report</h1>
        <p class="meta">
            <strong>Target:</strong> {self.results.get('target', 'Unknown')} |
            <strong>Scan Time:</strong> {self.results.get('scan_time', 'Unknown')} |
            <strong>Version:</strong> {self.results.get('scanner_version', 'Unknown')}
        </p>
        
        <div class="risk-score">
            Risk Score: {risk_score}/100<br>
            <span style="font-size: 24px;">{risk_level}</span>
        </div>
        
        <h2>📊 Summary</h2>
        <table class="summary-table">
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>🔴 Critical</td><td>{self.results.get('severity_summary', {}).get('critical', 0)}</td></tr>
            <tr><td>🟠 High</td><td>{self.results.get('severity_summary', {}).get('high', 0)}</td></tr>
            <tr><td>🟡 Medium</td><td>{self.results.get('severity_summary', {}).get('medium', 0)}</td></tr>
            <tr><td>🔵 Low</td><td>{self.results.get('severity_summary', {}).get('low', 0)}</td></tr>
            <tr><td>⚪ Info</td><td>{self.results.get('severity_summary', {}).get('info', 0)}</td></tr>
        </table>
        
        <h2>🔍 Findings</h2>
"""
        
        findings = self.results.get("findings", [])
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_findings = [f for f in findings if f.get("severity", "").lower() == severity]
            for finding in severity_findings:
                html += f"""
        <div class="finding {severity}">
            <span class="severity-badge {severity}">{severity}</span>
            <h3>{finding.get('title', 'Unknown')}</h3>
            <p class="meta">Module: {finding.get('module', 'Unknown')}</p>
            <p>{finding.get('description', '')}</p>
"""
                if finding.get("remediation"):
                    html += f"""
            <div class="remediation">
                <strong>Remediation:</strong> {finding['remediation']}
            </div>
"""
                html += "        </div>\n"
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score."""
        if score >= 70:
            return "HIGH RISK"
        elif score >= 40:
            return "MEDIUM RISK"
        elif score >= 10:
            return "LOW RISK"
        else:
            return "MINIMAL RISK"
    
    def _get_risk_color(self, score: int) -> str:
        """Get color for risk score."""
        if score >= 70:
            return "#dc3545"
        elif score >= 40:
            return "#fd7e14"
        elif score >= 10:
            return "#ffc107"
        else:
            return "#28a745"
