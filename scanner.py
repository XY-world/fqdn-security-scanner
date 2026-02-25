#!/usr/bin/env python3
"""
FQDN Security Scanner - Main Entry Point

A comprehensive security scanning tool for Fully Qualified Domain Names.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from modules.dns_scanner import DNSScanner
from modules.ssl_scanner import SSLScanner
from modules.header_scanner import HeaderScanner
from modules.port_scanner import PortScanner
from modules.subdomain_scanner import SubdomainScanner
from modules.vuln_scanner import VulnScanner
from report.generator import ReportGenerator

__version__ = "1.0.0"

AVAILABLE_MODULES = {
    "dns": DNSScanner,
    "ssl": SSLScanner,
    "headers": HeaderScanner,
    "ports": PortScanner,
    "subdomains": SubdomainScanner,
    "vulns": VulnScanner,
}


def calculate_risk_score(findings: List[Dict]) -> int:
    """Calculate overall risk score from findings."""
    severity_scores = {
        "critical": 40,
        "high": 25,
        "medium": 10,
        "low": 5,
        "info": 1,
    }
    
    total = 0
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        total += severity_scores.get(severity, 0)
    
    # Cap at 100
    return min(total, 100)


def run_scan(
    target: str,
    modules: Optional[List[str]] = None,
    timeout: int = 30,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Run security scan on target FQDN.
    
    Args:
        target: The FQDN to scan
        modules: List of modules to run (None = all)
        timeout: Timeout per module in seconds
        verbose: Print verbose output
    
    Returns:
        Scan results dictionary
    """
    if modules is None:
        modules = list(AVAILABLE_MODULES.keys())
    
    results = {
        "target": target,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "scanner_version": __version__,
        "modules_run": modules,
        "findings": [],
        "module_results": {},
    }
    
    for module_name in modules:
        if module_name not in AVAILABLE_MODULES:
            if verbose:
                print(f"[!] Unknown module: {module_name}", file=sys.stderr)
            continue
        
        if verbose:
            print(f"[*] Running {module_name} scanner...")
        
        try:
            scanner_class = AVAILABLE_MODULES[module_name]
            scanner = scanner_class(target, timeout=timeout)
            module_results = scanner.scan()
            
            results["module_results"][module_name] = module_results
            
            # Collect findings
            if "findings" in module_results:
                for finding in module_results["findings"]:
                    finding["module"] = module_name
                    results["findings"].append(finding)
            
            if verbose:
                finding_count = len(module_results.get("findings", []))
                print(f"    Found {finding_count} issues")
                
        except Exception as e:
            if verbose:
                print(f"[!] Error in {module_name}: {e}", file=sys.stderr)
            results["module_results"][module_name] = {
                "error": str(e),
                "status": "failed"
            }
    
    # Calculate risk score
    results["risk_score"] = calculate_risk_score(results["findings"])
    
    # Summary counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in results["findings"]:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    results["severity_summary"] = severity_counts
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="FQDN Security Scanner - Comprehensive domain security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Basic scan with all modules
  %(prog)s example.com --modules dns,ssl  # Specific modules only
  %(prog)s example.com -o report.json     # Save to file
  %(prog)s example.com --format md        # Markdown output
        """
    )
    
    parser.add_argument("target", help="Target FQDN to scan")
    parser.add_argument(
        "-m", "--modules",
        help=f"Comma-separated list of modules ({','.join(AVAILABLE_MODULES.keys())})",
        default=None
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path",
        default=None
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "md", "html"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Timeout per module in seconds (default: 30)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run all modules (same as omitting --modules)"
    )
    
    args = parser.parse_args()
    
    # Parse modules
    modules = None
    if args.modules and not args.full:
        modules = [m.strip() for m in args.modules.split(",")]
    
    # Validate target
    target = args.target.strip().lower()
    if target.startswith("http://") or target.startswith("https://"):
        # Extract domain from URL
        from urllib.parse import urlparse
        target = urlparse(target).netloc
    
    if not target:
        print("Error: Invalid target", file=sys.stderr)
        sys.exit(1)
    
    # Run scan
    if args.verbose:
        print(f"[*] Starting scan of {target}")
        print(f"[*] Modules: {modules or 'all'}")
    
    results = run_scan(
        target=target,
        modules=modules,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # Generate output
    generator = ReportGenerator(results)
    
    if args.format == "json":
        output = generator.to_json()
    elif args.format == "md":
        output = generator.to_markdown()
    elif args.format == "html":
        output = generator.to_html()
    else:
        output = generator.to_json()
    
    # Output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"[*] Report saved to {args.output}")
    else:
        print(output)
    
    # Exit code based on risk
    if results["risk_score"] >= 70:
        sys.exit(2)  # High risk
    elif results["risk_score"] >= 30:
        sys.exit(1)  # Medium risk
    else:
        sys.exit(0)  # Low risk


if __name__ == "__main__":
    main()
