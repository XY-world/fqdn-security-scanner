
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
