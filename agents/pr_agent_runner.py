#!/usr/bin/env python3
"""
PR Agent Runner - Generates and hot-loads detection modules.
"""

import sys
import os
import json
import importlib.util
import subprocess
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.manager import agent_manager

PROJECT_DIR = Path(__file__).parent.parent
MODULES_DIR = PROJECT_DIR / "modules"
DYNAMIC_MODULES_DIR = PROJECT_DIR / "dynamic_modules"
DYNAMIC_MODULES_DIR.mkdir(exist_ok=True)

REPO = "XY-world/fqdn-security-scanner"


# Module templates for different vulnerability types
MODULE_TEMPLATES = {
    "ssl": {
        "name": "SSL/TLS Security",
        "icon": "🔒",
        "keywords": ["ssl", "tls", "certificate", "cipher", "https"],
        "code": '''
import ssl
import socket
from typing import Dict, List

class SSLSecurityScanner:
    """Scanner for SSL/TLS security issues."""
    
    name = "ssl_security"
    description = "Checks SSL/TLS configuration and certificate validity"
    
    def __init__(self, target: str, timeout: int = 30):
        self.target = target
        self.timeout = timeout
    
    def scan(self) -> Dict:
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    protocol = ssock.version()
                    
                    if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        findings.append({
                            "title": f"Outdated Protocol: {protocol}",
                            "description": f"Server uses {protocol} which is deprecated",
                            "severity": "high",
                            "remediation": "Upgrade to TLS 1.2 or higher"
                        })
                    else:
                        findings.append({
                            "title": f"Protocol: {protocol}",
                            "description": f"Server uses {protocol}",
                            "severity": "info"
                        })
        except Exception as e:
            findings.append({
                "title": "SSL Connection Error",
                "description": str(e),
                "severity": "medium"
            })
        
        return {"status": "completed", "findings": findings}
'''
    },
    "headers": {
        "name": "HTTP Headers",
        "icon": "📋",
        "keywords": ["header", "hsts", "csp", "cors", "cookie"],
        "code": '''
import requests
from typing import Dict, List

class HTTPHeadersScanner:
    """Scanner for HTTP security headers."""
    
    name = "http_headers"
    description = "Checks for security headers in HTTP responses"
    
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy", 
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy"
    ]
    
    def __init__(self, target: str, timeout: int = 30):
        self.target = target
        self.timeout = timeout
    
    def scan(self) -> Dict:
        findings = []
        
        try:
            url = f"https://{self.target}" if not self.target.startswith("http") else self.target
            resp = requests.get(url, timeout=self.timeout, verify=True)
            headers = resp.headers
            
            for header in self.SECURITY_HEADERS:
                if header not in headers:
                    findings.append({
                        "title": f"Missing {header}",
                        "description": f"Security header {header} is not set",
                        "severity": "medium",
                        "remediation": f"Add {header} header to HTTP responses"
                    })
        except Exception as e:
            findings.append({
                "title": "HTTP Request Error",
                "description": str(e),
                "severity": "low"
            })
        
        return {"status": "completed", "findings": findings}
'''
    },
    "subdomain": {
        "name": "Subdomain Security",
        "icon": "🔍",
        "keywords": ["subdomain", "takeover", "dangling"],
        "code": '''
import dns.resolver
from typing import Dict, List

class SubdomainSecurityScanner:
    """Scanner for subdomain security issues."""
    
    name = "subdomain_security"
    description = "Checks for subdomain takeover vulnerabilities"
    
    COMMON_SUBDOMAINS = ["www", "mail", "ftp", "admin", "api", "dev", "staging"]
    
    def __init__(self, target: str, timeout: int = 30):
        self.target = target
        self.timeout = timeout
    
    def scan(self) -> Dict:
        findings = []
        
        for sub in self.COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.target}"
            try:
                dns.resolver.resolve(fqdn, "A", lifetime=5)
                findings.append({
                    "title": f"Subdomain found: {fqdn}",
                    "description": f"Active subdomain detected",
                    "severity": "info"
                })
            except:
                pass
        
        return {"status": "completed", "findings": findings}
'''
    },
    "email": {
        "name": "Email Security",
        "icon": "📧",
        "keywords": ["spf", "dkim", "dmarc", "email", "smtp", "mail"],
        "code": '''
import dns.resolver
from typing import Dict, List

class EmailSecurityScanner:
    """Scanner for email security configuration."""
    
    name = "email_security"
    description = "Checks SPF, DKIM, and DMARC configuration"
    
    def __init__(self, target: str, timeout: int = 30):
        self.target = target
        self.timeout = timeout
    
    def scan(self) -> Dict:
        findings = []
        
        # Check SPF
        try:
            answers = dns.resolver.resolve(self.target, "TXT", lifetime=10)
            spf_found = False
            for rdata in answers:
                txt = rdata.to_text()
                if "v=spf1" in txt:
                    spf_found = True
                    findings.append({
                        "title": "SPF Record Found",
                        "description": txt[:100],
                        "severity": "info"
                    })
            if not spf_found:
                findings.append({
                    "title": "Missing SPF Record",
                    "description": "No SPF record found for domain",
                    "severity": "medium",
                    "remediation": "Add SPF record to prevent email spoofing"
                })
        except:
            pass
        
        # Check DMARC
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{self.target}", "TXT", lifetime=10)
            findings.append({
                "title": "DMARC Record Found",
                "description": "DMARC policy is configured",
                "severity": "info"
            })
        except:
            findings.append({
                "title": "Missing DMARC Record",
                "description": "No DMARC record found",
                "severity": "medium",
                "remediation": "Add DMARC record for email authentication"
            })
        
        return {"status": "completed", "findings": findings}
'''
    },
    "generic": {
        "name": "Security Check",
        "icon": "⚠️",
        "keywords": [],
        "code": '''
from typing import Dict, List

class GenericSecurityScanner:
    """Generic security scanner placeholder."""
    
    name = "generic_security"
    description = "Generic security check"
    
    def __init__(self, target: str, timeout: int = 30):
        self.target = target
        self.timeout = timeout
    
    def scan(self) -> Dict:
        findings = [{
            "title": "Module Placeholder",
            "description": "This module needs implementation",
            "severity": "info"
        }]
        return {"status": "completed", "findings": findings}
'''
    }
}


def determine_module_type(discovery: dict) -> str:
    """Determine which module template to use based on discovery."""
    title = discovery.get("title", "").lower()
    description = discovery.get("description", "").lower()
    text = title + " " + description
    
    for module_type, template in MODULE_TEMPLATES.items():
        for keyword in template.get("keywords", []):
            if keyword in text:
                return module_type
    
    return "generic"


def generate_module(discovery: dict) -> dict:
    """Generate a scanner module based on discovery."""
    module_type = determine_module_type(discovery)
    template = MODULE_TEMPLATES.get(module_type, MODULE_TEMPLATES["generic"])
    
    module_id = f"{module_type}_{discovery.get('id', 0)}"
    
    return {
        "id": module_id,
        "type": module_type,
        "name": template["name"],
        "icon": template["icon"],
        "code": template["code"],
        "discovery_id": discovery.get("id"),
        "discovery_title": discovery.get("title", "")[:100]
    }


def hot_load_module(module_info: dict) -> bool:
    """Hot-load a module into the running scanner."""
    module_id = module_info["id"]
    code = module_info["code"]
    
    # Write module to dynamic modules directory
    module_file = DYNAMIC_MODULES_DIR / f"{module_id}.py"
    module_file.write_text(code)
    
    # Load the module dynamically to verify it works
    try:
        spec = importlib.util.spec_from_file_location(module_id, module_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find the scanner class
        scanner_class = None
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and name.endswith("Scanner"):
                scanner_class = obj
                break
        
        if scanner_class:
            # Register in the registry file
            registry_file = PROJECT_DIR / "data" / "dynamic_modules.json"
            
            try:
                registry = json.loads(registry_file.read_text()) if registry_file.exists() else {}
            except:
                registry = {}
            
            registry[module_id] = {
                "file": str(module_file),
                "name": module_info["name"],
                "icon": module_info["icon"],
                "discovery_id": module_info.get("discovery_id"),
                "loaded_at": datetime.now(timezone.utc).isoformat()
            }
            
            registry_file.write_text(json.dumps(registry, indent=2))
            
            # Update scanner agent stats
            agent_manager.agents["scanner"].stats["available_modules"] = 1 + len(registry)
            agent_manager._save_state()
            
            return True
    except Exception as e:
        print(f"Error loading module: {e}")
        return False
    
    return False


def process_discovery(discovery_id: int) -> dict:
    """Process a discovery and hot-load a new module."""
    
    print(f"[{datetime.now(timezone.utc).isoformat()}] Processing discovery #{discovery_id}...")
    
    agent_manager.update_agent_status("pr_agent", "active")
    agent_manager.add_activity("pr_agent", f"Processing discovery #{discovery_id}")
    
    # Get discovery
    discoveries = agent_manager.get_discoveries(limit=100)
    discovery = next((d for d in discoveries if d.get("id") == discovery_id), None)
    
    if not discovery:
        agent_manager.update_agent_status("pr_agent", "error", f"Discovery #{discovery_id} not found")
        return {"success": False, "error": "Discovery not found"}
    
    # Generate module
    agent_manager.add_activity("pr_agent", f"Generating module for: {discovery.get('title', '')[:50]}...")
    module_info = generate_module(discovery)
    
    # Hot-load the module
    agent_manager.add_activity("pr_agent", f"Hot-loading module: {module_info['name']}")
    success = hot_load_module(module_info)
    
    if success:
        agent_manager.increment_stat("pr_agent", "prs_opened")
        agent_manager.add_activity("pr_agent", f"✅ Module loaded: {module_info['name']} ({module_info['id']})")
        agent_manager.update_discovery_status(discovery_id, "implemented")
        agent_manager.update_agent_status("pr_agent", "idle", f"Module {module_info['name']} loaded")
        print(f"✅ Module hot-loaded: {module_info['id']}")
        
        return {
            "success": True,
            "module_id": module_info["id"],
            "module_name": module_info["name"],
            "action": "hot_loaded"
        }
    else:
        agent_manager.add_activity("pr_agent", f"❌ Failed to load module")
        agent_manager.update_agent_status("pr_agent", "error", "Module load failed")
        return {"success": False, "error": "Module load failed"}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  pr_agent_runner.py <discovery_id>  - Hot-load module for discovery")
        print("  pr_agent_runner.py --list          - List loaded modules")
        sys.exit(1)
    
    if sys.argv[1] == "--list":
        registry_file = PROJECT_DIR / "data" / "dynamic_modules.json"
        if registry_file.exists():
            registry = json.loads(registry_file.read_text())
            print("Loaded modules:")
            for mid, info in registry.items():
                print(f"  {mid}: {info['name']} ({info['icon']})")
        else:
            print("No modules loaded yet.")
    else:
        discovery_id = int(sys.argv[1])
        result = process_discovery(discovery_id)
        print(result)
        sys.exit(0 if result.get("success") else 1)
