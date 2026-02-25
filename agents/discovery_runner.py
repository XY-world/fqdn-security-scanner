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
    
    # Complete
    agent_manager.update_agent_status(
        "discovery", 
        "idle", 
        f"Found {len(new_findings)} new items"
    )
    agent_manager.add_activity(
        "discovery",
        f"Completed search. Found {len(new_findings)} new discoveries."
    )
    
    print(f"[{datetime.now(timezone.utc).isoformat()}] Discovery complete. Found {len(new_findings)} new items.")
    
    return new_findings


if __name__ == "__main__":
    findings = run_discovery()
    
    # Output summary for cron
    if findings:
        print("\n📢 New Security Discoveries:")
        for f in findings[:5]:
            print(f"  • [{f['category']}] {f['title'][:60]}...")
    else:
        print("\n✓ No new discoveries found.")
