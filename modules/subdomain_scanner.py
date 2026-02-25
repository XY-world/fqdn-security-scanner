"""Subdomain Enumeration Scanner Module."""

from typing import Dict, Any, List
import socket

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from .base import BaseScanner


class SubdomainScanner(BaseScanner):
    """Enumerate subdomains via DNS."""
    
    # Common subdomain prefixes to check
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "blog", "dev", "staging", "test", "api", "app", "admin",
        "portal", "secure", "vpn", "remote", "m", "mobile",
        "shop", "store", "support", "help", "docs", "cdn",
        "static", "assets", "img", "images", "video", "media",
        "beta", "alpha", "demo", "sandbox", "uat", "qa",
        "git", "gitlab", "github", "jenkins", "ci", "build",
        "db", "database", "mysql", "postgres", "redis", "mongo",
        "elk", "kibana", "grafana", "prometheus", "metrics",
        "login", "auth", "sso", "oauth", "id", "accounts",
        "payment", "pay", "billing", "invoice",
        "internal", "intranet", "corp", "office",
        "cloud", "aws", "azure", "gcp",
    ]
    
    def scan(self) -> Dict[str, Any]:
        """Run subdomain enumeration."""
        results = {
            "status": "completed",
            "subdomains": [],
            "resolved": {},
            "wildcard": False,
            "findings": [],
        }
        
        if not HAS_DNS:
            results["status"] = "error"
            results["error"] = "dnspython not installed"
            return results
        
        # Check for wildcard DNS
        results["wildcard"] = self._check_wildcard()
        
        if results["wildcard"]:
            self.add_finding(
                title="Wildcard DNS Detected",
                description="Domain uses wildcard DNS. Subdomain enumeration may be unreliable.",
                severity="info",
                remediation="Consider if wildcard DNS is necessary for your use case."
            )
        
        # Enumerate subdomains
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for prefix in self.COMMON_SUBDOMAINS:
            subdomain = f"{prefix}.{self.target}"
            try:
                answers = resolver.resolve(subdomain, "A")
                ips = [str(rdata) for rdata in answers]
                
                # Skip if wildcard and same IP as wildcard
                if not results["wildcard"] or ips != results.get("wildcard_ips", []):
                    results["subdomains"].append(subdomain)
                    results["resolved"][subdomain] = ips
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.exception.DNSException:
                pass
        
        # Check for interesting/risky subdomains
        self._analyze_subdomains(results["subdomains"])
        
        results["findings"] = self.get_findings()
        return results
    
    def _check_wildcard(self) -> bool:
        """Check if domain has wildcard DNS."""
        import random
        import string
        
        # Generate random subdomain
        random_prefix = ''.join(random.choices(string.ascii_lowercase, k=16))
        random_subdomain = f"{random_prefix}.{self.target}"
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            answers = resolver.resolve(random_subdomain, "A")
            return len(answers) > 0
        except dns.exception.DNSException:
            return False
    
    def _analyze_subdomains(self, subdomains: List[str]):
        """Analyze discovered subdomains for security issues."""
        
        risky_prefixes = {
            "admin": "Administrative interface may be exposed",
            "dev": "Development environment may contain debug info",
            "staging": "Staging environment may have weaker security",
            "test": "Test environment may be vulnerable",
            "internal": "Internal subdomain exposed externally",
            "intranet": "Intranet subdomain exposed externally",
            "jenkins": "CI/CD server may be exposed",
            "gitlab": "Git server may be exposed",
            "grafana": "Monitoring dashboard may be exposed",
            "kibana": "Log dashboard may be exposed",
            "db": "Database service indication",
            "mysql": "MySQL service indication",
            "redis": "Redis service indication",
            "mongo": "MongoDB service indication",
        }
        
        for subdomain in subdomains:
            prefix = subdomain.split(".")[0]
            if prefix in risky_prefixes:
                self.add_finding(
                    title=f"Potentially Sensitive Subdomain: {subdomain}",
                    description=risky_prefixes[prefix],
                    severity="medium" if prefix in ["admin", "internal", "intranet"] else "low",
                    remediation="Ensure this subdomain is properly secured or not publicly accessible."
                )
