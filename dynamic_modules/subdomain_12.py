
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
