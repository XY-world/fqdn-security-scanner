#!/usr/bin/env python3
"""
Discovery Agent Runner - Real implementation using web search.

This script is called by OpenClaw cron to search for new security vulnerabilities.
"""

import sys
import os
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.manager import agent_manager

DATA_DIR = Path(__file__).parent.parent / "data"
SEEN_FILE = DATA_DIR / "seen_discoveries.json"


def load_seen():
    """Load previously seen discovery URLs to avoid duplicates."""
    if SEEN_FILE.exists():
        try:
            return set(json.loads(SEEN_FILE.read_text()))
        except:
            pass
    return set()


def save_seen(seen):
    """Save seen discovery URLs."""
    SEEN_FILE.write_text(json.dumps(list(seen)[-500:]))  # Keep last 500


def search_web(query: str) -> list:
    """Search web using multiple sources."""
    import requests
    
    results = []
    
    # 1. Search CVE database (CIRCL)
    try:
        # Extract key terms
        terms = query.lower().replace("2026", "").replace("latest", "").replace("new", "").strip()
        cve_response = requests.get(
            f"https://cve.circl.lu/api/search/{terms}",
            timeout=15
        )
        if cve_response.status_code == 200:
            cves = cve_response.json()
            for cve in cves[:3]:
                if cve.get("id") and cve.get("summary"):
                    results.append({
                        "title": f"{cve.get('id')}: {cve.get('summary', '')[:100]}",
                        "description": cve.get("summary", "")[:500],
                        "url": f"https://cve.circl.lu/cve/{cve.get('id')}"
                    })
    except Exception as e:
        print(f"    CVE search error: {e}")
    
    # 2. Search NVD (National Vulnerability Database)
    try:
        nvd_keywords = query.split()[:2]
        nvd_response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": " ".join(nvd_keywords), "resultsPerPage": 3},
            timeout=15,
            headers={"User-Agent": "FQDN-Security-Scanner/1.0"}
        )
        if nvd_response.status_code == 200:
            data = nvd_response.json()
            for vuln in data.get("vulnerabilities", [])[:3]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
                if cve_id and desc:
                    results.append({
                        "title": f"{cve_id}: {desc[:100]}",
                        "description": desc[:500],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
    except Exception as e:
        print(f"    NVD search error: {e}")
    
    # 3. Search GitHub Security Advisories
    try:
        gh_response = requests.get(
            "https://api.github.com/advisories",
            params={"type": "reviewed", "per_page": 3},
            timeout=10,
            headers={"Accept": "application/vnd.github+json"}
        )
        if gh_response.status_code == 200:
            for advisory in gh_response.json()[:3]:
                if advisory.get("summary"):
                    results.append({
                        "title": advisory.get("summary", "")[:150],
                        "description": advisory.get("description", "")[:500] if advisory.get("description") else advisory.get("summary", ""),
                        "url": advisory.get("html_url", "")
                    })
    except Exception as e:
        print(f"    GitHub advisories error: {e}")
    
    return results
    
    return results


def categorize_result(title: str, description: str) -> str:
    """Categorize a search result."""
    text = (title + " " + description).lower()
    
    if "cve-" in text or "vulnerability" in text or "exploit" in text:
        return "cve"
    elif "technique" in text or "method" in text or "bypass" in text:
        return "technique"
    elif "tool" in text or "scanner" in text or "framework" in text:
        return "tool"
    elif "research" in text or "paper" in text or "study" in text:
        return "research"
    else:
        return "news"


def run_discovery():
    """Run the discovery search."""
    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting Discovery Agent...")
    
    agent_manager.update_agent_status("discovery", "active")
    agent_manager.add_activity("discovery", "Starting security discovery search...")
    
    # Search topics
    topics = [
        "FQDN security vulnerability 2026",
        "DNS security CVE latest",
        "SSL TLS vulnerability new",
        "HTTP security headers bypass",
        "subdomain takeover technique",
        "DNSSEC vulnerability",
        "SPF DKIM DMARC bypass",
        "certificate transparency security",
    ]
    
    seen = load_seen()
    new_findings = []
    
    for topic in topics:
        print(f"  Searching: {topic}")
        agent_manager.add_activity("discovery", f"Searching: {topic}")
        
        results = search_web(topic)
        
        for result in results[:3]:  # Top 3 per topic
            url = result.get("url", "")
            title = result.get("title", "")
            description = result.get("description", "")
            
            if url in seen:
                continue
            
            # Check relevance
            text = (title + " " + description).lower()
            keywords = ["vulnerability", "cve", "security", "exploit", "bypass", 
                       "attack", "flaw", "risk", "threat", "dns", "ssl", "tls",
                       "certificate", "header", "subdomain", "dnssec"]
            
            if not any(kw in text for kw in keywords):
                continue
            
            # Add discovery
            category = categorize_result(title, description)
            discovery = agent_manager.add_discovery(
                title=title[:200],
                description=description[:500],
                source=url,
                category=category
            )
            
            new_findings.append(discovery)
            seen.add(url)
            print(f"    Found: {title[:60]}...")
    
    save_seen(seen)
    
    # Analyze coverage
    agent_manager.add_activity("discovery", "Analyzing coverage against Scanner modules...")
    analysis = analyze_coverage(new_findings)
    agent_manager.set_coverage_analysis(analysis)
    
    # Complete
    agent_manager.update_agent_status(
        "discovery", 
        "idle", 
        f"Found {len(new_findings)} new items, {analysis['uncovered_count']} not covered"
    )
    agent_manager.add_activity(
        "discovery",
        f"Completed. Found {len(new_findings)} discoveries, {analysis['uncovered_count']} need new modules."
    )
    
    print(f"[{datetime.now(timezone.utc).isoformat()}] Discovery complete. Found {len(new_findings)} new items.")
    
    return new_findings


def analyze_coverage(findings: list) -> dict:
    """Analyze which discoveries are covered by existing Scanner modules."""
    
    # Current Scanner modules and what they cover
    SCANNER_MODULES = {
        "dns": {
            "name": "DNS Security",
            "covers": ["dns", "dnssec", "spf", "dkim", "dmarc", "mx", "cname", "ns", "soa", "txt"]
        },
        "ssl": {
            "name": "SSL/TLS",
            "covers": ["ssl", "tls", "certificate", "cipher", "https", "x509", "pem", "key", "encryption"]
        },
        "headers": {
            "name": "HTTP Headers",
            "covers": ["header", "hsts", "csp", "x-frame", "x-content", "cors", "cookie", "referrer"]
        },
        "ports": {
            "name": "Port Scan",
            "covers": ["port", "tcp", "udp", "service", "open port", "firewall", "network"]
        },
        "subdomains": {
            "name": "Subdomains",
            "covers": ["subdomain", "takeover", "dangling", "cname", "domain enumeration"]
        },
        "vulns": {
            "name": "Vulnerabilities",
            "covers": ["vulnerability", "cve", "exploit", "injection", "xss", "csrf", "sqli", "rce"]
        }
    }
    
    # Categorize all discoveries
    categories = {}
    uncovered = []
    covered = []
    
    all_discoveries = agent_manager.get_discoveries(limit=100)
    
    for discovery in all_discoveries:
        title = discovery.get("title", "").lower()
        description = discovery.get("description", "").lower()
        text = title + " " + description
        
        # Find which module covers this
        covered_by = None
        for module_id, module_info in SCANNER_MODULES.items():
            for keyword in module_info["covers"]:
                if keyword in text:
                    covered_by = module_id
                    break
            if covered_by:
                break
        
        # Categorize by vulnerability type
        vuln_type = categorize_vuln_type(text)
        if vuln_type not in categories:
            categories[vuln_type] = {"count": 0, "covered": 0, "uncovered": 0, "discoveries": []}
        
        categories[vuln_type]["count"] += 1
        categories[vuln_type]["discoveries"].append(discovery["id"])
        
        if covered_by:
            categories[vuln_type]["covered"] += 1
            covered.append({
                "id": discovery["id"],
                "title": discovery.get("title", "")[:80],
                "covered_by": covered_by,
                "module_name": SCANNER_MODULES[covered_by]["name"]
            })
        else:
            categories[vuln_type]["uncovered"] += 1
            uncovered.append({
                "id": discovery["id"],
                "title": discovery.get("title", "")[:80],
                "suggested_module": suggest_module(text),
                "category": discovery.get("category", ""),
                "status": discovery.get("status", "new")
            })
    
    analysis = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_discoveries": len(all_discoveries),
        "covered_count": len(covered),
        "uncovered_count": len(uncovered),
        "coverage_percentage": round(len(covered) / max(len(all_discoveries), 1) * 100, 1),
        "categories": categories,
        "covered": covered[:20],  # Top 20
        "uncovered": uncovered[:20],  # Top 20 uncovered
        "modules": list(SCANNER_MODULES.keys()),
        "module_details": SCANNER_MODULES
    }
    
    return analysis


def categorize_vuln_type(text: str) -> str:
    """Categorize the vulnerability type."""
    if any(kw in text for kw in ["dns", "dnssec", "domain name"]):
        return "DNS Security"
    elif any(kw in text for kw in ["ssl", "tls", "certificate", "cipher", "encryption"]):
        return "SSL/TLS"
    elif any(kw in text for kw in ["header", "hsts", "csp", "cors", "cookie"]):
        return "HTTP Headers"
    elif any(kw in text for kw in ["subdomain", "takeover", "dangling"]):
        return "Subdomain Security"
    elif any(kw in text for kw in ["spf", "dkim", "dmarc", "email", "smtp", "mail"]):
        return "Email Security"
    elif any(kw in text for kw in ["injection", "xss", "csrf", "sqli", "rce"]):
        return "Web Application"
    elif any(kw in text for kw in ["authentication", "oauth", "jwt", "session"]):
        return "Authentication"
    elif any(kw in text for kw in ["port", "network", "tcp", "udp", "firewall"]):
        return "Network"
    else:
        return "Other"


def suggest_module(text: str) -> str:
    """Suggest a module name for uncovered vulnerability."""
    if any(kw in text for kw in ["spf", "dkim", "dmarc", "email", "smtp"]):
        return "email_security"
    elif any(kw in text for kw in ["oauth", "jwt", "authentication", "session"]):
        return "auth_checker"
    elif any(kw in text for kw in ["api", "graphql", "rest"]):
        return "api_security"
    elif any(kw in text for kw in ["waf", "firewall", "bypass"]):
        return "waf_detector"
    elif any(kw in text for kw in ["container", "docker", "kubernetes"]):
        return "container_security"
    else:
        return "custom_check"


if __name__ == "__main__":
    findings = run_discovery()
    
    # Output summary for cron
    if findings:
        print("\n📢 New Security Discoveries:")
        for f in findings[:5]:
            print(f"  • [{f['category']}] {f['title'][:60]}...")
    else:
        print("\n✓ No new discoveries found.")
    
    # Output coverage analysis
    analysis = agent_manager.get_coverage_analysis()
    if analysis:
        print(f"\n📊 Coverage Analysis:")
        print(f"   Total: {analysis.get('total_discoveries', 0)} discoveries")
        print(f"   Covered: {analysis.get('covered_count', 0)} ({analysis.get('coverage_percentage', 0)}%)")
        print(f"   Uncovered: {analysis.get('uncovered_count', 0)}")
        
        if analysis.get("uncovered"):
            print(f"\n⚠️  Need Implementation:")
            for item in analysis["uncovered"][:5]:
                print(f"   • {item['title'][:50]}... → {item['suggested_module']}")
