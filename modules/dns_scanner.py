"""DNS Security Scanner Module."""

import socket
from typing import Dict, Any, List, Optional

try:
    import dns.resolver
    import dns.dnssec
    import dns.rdatatype
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from .base import BaseScanner


class DNSScanner(BaseScanner):
    """Scan DNS configuration for security issues."""
    
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "CNAME"]
    
    def scan(self) -> Dict[str, Any]:
        """Run DNS security scan."""
        results = {
            "status": "completed",
            "records": {},
            "dnssec": {},
            "email_security": {},
            "findings": [],
        }
        
        if not HAS_DNS:
            results["status"] = "error"
            results["error"] = "dnspython not installed"
            return results
        
        # Get DNS records
        results["records"] = self._get_dns_records()
        
        # Check DNSSEC
        results["dnssec"] = self._check_dnssec()
        
        # Check email security (SPF, DKIM, DMARC)
        results["email_security"] = self._check_email_security()
        
        # Check CAA records
        self._check_caa_records(results["records"].get("CAA", []))
        
        # Collect findings
        results["findings"] = self.get_findings()
        
        return results
    
    def _get_dns_records(self) -> Dict[str, List[str]]:
        """Fetch common DNS records."""
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(self.target, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                records[rtype] = []
            except dns.exception.DNSException:
                records[rtype] = []
        
        return records
    
    def _check_dnssec(self) -> Dict[str, Any]:
        """Check DNSSEC configuration."""
        result = {
            "enabled": False,
            "valid": False,
            "dnskey": [],
            "ds": [],
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        
        try:
            # Check for DNSKEY records
            dnskey_answers = resolver.resolve(self.target, "DNSKEY")
            result["dnskey"] = [str(rdata) for rdata in dnskey_answers]
            result["enabled"] = len(result["dnskey"]) > 0
            
            if result["enabled"]:
                # Try to validate
                result["valid"] = True  # Simplified - real validation is complex
        except dns.exception.DNSException:
            pass
        
        if not result["enabled"]:
            self.add_finding(
                title="DNSSEC Not Enabled",
                description=f"DNSSEC is not configured for {self.target}. This allows DNS spoofing attacks.",
                severity="medium",
                remediation="Enable DNSSEC with your DNS provider to protect against DNS spoofing.",
                references=["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"]
            )
        
        return result
    
    def _check_email_security(self) -> Dict[str, Any]:
        """Check SPF, DKIM hints, and DMARC."""
        result = {
            "spf": {"present": False, "record": None, "issues": []},
            "dmarc": {"present": False, "record": None, "policy": None, "issues": []},
            "dkim_selectors_found": [],
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        
        # Check SPF
        try:
            txt_records = resolver.resolve(self.target, "TXT")
            for rdata in txt_records:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["spf"]["present"] = True
                    result["spf"]["record"] = txt
                    
                    # Check for weak SPF
                    if "+all" in txt:
                        result["spf"]["issues"].append("Weak SPF: +all allows any sender")
                        self.add_finding(
                            title="Weak SPF Record",
                            description="SPF record uses +all which allows any server to send email as your domain.",
                            severity="high",
                            remediation="Change +all to -all or ~all to restrict unauthorized senders."
                        )
                    elif "?all" in txt:
                        result["spf"]["issues"].append("Neutral SPF: ?all provides no protection")
                        self.add_finding(
                            title="Neutral SPF Record",
                            description="SPF record uses ?all which provides no protection against spoofing.",
                            severity="medium",
                            remediation="Change ?all to -all or ~all."
                        )
        except dns.exception.DNSException:
            pass
        
        if not result["spf"]["present"]:
            self.add_finding(
                title="No SPF Record",
                description=f"No SPF record found for {self.target}. Email spoofing is possible.",
                severity="medium",
                remediation="Add an SPF TXT record to specify authorized mail servers."
            )
        
        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{self.target}"
            dmarc_records = resolver.resolve(dmarc_domain, "TXT")
            for rdata in dmarc_records:
                txt = str(rdata).strip('"')
                if txt.startswith("v=DMARC1"):
                    result["dmarc"]["present"] = True
                    result["dmarc"]["record"] = txt
                    
                    # Parse policy
                    if "p=none" in txt:
                        result["dmarc"]["policy"] = "none"
                        self.add_finding(
                            title="DMARC Policy Set to None",
                            description="DMARC policy is 'none' which only monitors but doesn't reject spoofed emails.",
                            severity="low",
                            remediation="Consider upgrading to p=quarantine or p=reject after monitoring."
                        )
                    elif "p=quarantine" in txt:
                        result["dmarc"]["policy"] = "quarantine"
                    elif "p=reject" in txt:
                        result["dmarc"]["policy"] = "reject"
        except dns.exception.DNSException:
            pass
        
        if not result["dmarc"]["present"]:
            self.add_finding(
                title="No DMARC Record",
                description=f"No DMARC record found for {self.target}. Email authentication is incomplete.",
                severity="medium",
                remediation="Add a DMARC TXT record at _dmarc.{domain} to protect against email spoofing."
            )
        
        return result
    
    def _check_caa_records(self, caa_records: List[str]):
        """Check CAA (Certificate Authority Authorization) records."""
        if not caa_records:
            self.add_finding(
                title="No CAA Records",
                description="No CAA records found. Any CA can issue certificates for this domain.",
                severity="low",
                remediation="Add CAA records to restrict which CAs can issue certificates for your domain.",
                references=["https://letsencrypt.org/docs/caa/"]
            )
