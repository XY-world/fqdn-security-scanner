"""HTTP Security Headers Scanner Module."""

import requests
from typing import Dict, Any, List
from urllib.parse import urljoin

from .base import BaseScanner


class HeaderScanner(BaseScanner):
    """Scan HTTP security headers."""
    
    # Security headers to check
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "high",
            "description": "HSTS header missing. Site vulnerable to SSL stripping attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "description": "CSP header missing. Site may be vulnerable to XSS attacks.",
            "remediation": "Implement a Content-Security-Policy header to mitigate XSS."
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description": "X-Content-Type-Options header missing. MIME sniffing possible.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' header."
        },
        "X-Frame-Options": {
            "severity": "medium",
            "description": "X-Frame-Options header missing. Site may be vulnerable to clickjacking.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
        },
        "X-XSS-Protection": {
            "severity": "low",
            "description": "X-XSS-Protection header missing (legacy browser protection).",
            "remediation": "Add 'X-XSS-Protection: 1; mode=block' header."
        },
        "Referrer-Policy": {
            "severity": "low",
            "description": "Referrer-Policy header missing. Referrer information may leak.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
        },
        "Permissions-Policy": {
            "severity": "low",
            "description": "Permissions-Policy header missing. Browser features not restricted.",
            "remediation": "Add Permissions-Policy header to control browser features."
        },
    }
    
    # Headers that leak server information
    INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    
    def scan(self) -> Dict[str, Any]:
        """Run HTTP security headers scan."""
        results = {
            "status": "completed",
            "url": f"https://{self.target}",
            "headers": {},
            "missing_headers": [],
            "info_leak_headers": {},
            "cookies": [],
            "findings": [],
        }
        
        try:
            # Try HTTPS first
            response = requests.get(
                f"https://{self.target}",
                timeout=self.timeout,
                allow_redirects=True,
                verify=True
            )
            results["url"] = response.url
            results["status_code"] = response.status_code
            results["headers"] = dict(response.headers)
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            try:
                response = requests.get(
                    f"http://{self.target}",
                    timeout=self.timeout,
                    allow_redirects=True
                )
                results["url"] = response.url
                results["headers"] = dict(response.headers)
                
                # Flag HTTP-only
                self.add_finding(
                    title="HTTPS Not Available",
                    description=f"Site only responds on HTTP, not HTTPS.",
                    severity="high",
                    remediation="Enable HTTPS with a valid SSL certificate."
                )
            except Exception as e:
                results["status"] = "error"
                results["error"] = str(e)
                return results
                
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            return results
        
        # Check security headers
        headers_lower = {k.lower(): v for k, v in results["headers"].items()}
        
        for header, info in self.SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                results["missing_headers"].append(header)
                self.add_finding(
                    title=f"Missing {header}",
                    description=info["description"],
                    severity=info["severity"],
                    remediation=info["remediation"]
                )
            else:
                # Check for weak configurations
                value = headers_lower[header.lower()]
                self._check_header_value(header, value)
        
        # Check for information leakage headers
        for header in self.INFO_LEAK_HEADERS:
            if header.lower() in headers_lower:
                results["info_leak_headers"][header] = headers_lower[header.lower()]
                self.add_finding(
                    title=f"Information Disclosure: {header}",
                    description=f"Server exposes {header}: {headers_lower[header.lower()]}",
                    severity="info",
                    remediation=f"Remove or obfuscate the {header} header."
                )
        
        # Check cookies
        cookies = response.cookies
        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite", "None"),
            }
            results["cookies"].append(cookie_info)
            
            # Check cookie security
            if not cookie.secure:
                self.add_finding(
                    title=f"Cookie Without Secure Flag: {cookie.name}",
                    description="Cookie can be transmitted over unencrypted connections.",
                    severity="medium",
                    remediation="Set the Secure flag on all cookies."
                )
            
            if not cookie_info["httponly"]:
                self.add_finding(
                    title=f"Cookie Without HttpOnly Flag: {cookie.name}",
                    description="Cookie accessible via JavaScript, vulnerable to XSS theft.",
                    severity="medium",
                    remediation="Set the HttpOnly flag on sensitive cookies."
                )
        
        results["findings"] = self.get_findings()
        return results
    
    def _check_header_value(self, header: str, value: str):
        """Check for weak header configurations."""
        header_lower = header.lower()
        value_lower = value.lower()
        
        if header_lower == "strict-transport-security":
            # Check HSTS max-age
            if "max-age=" in value_lower:
                try:
                    max_age = int(value_lower.split("max-age=")[1].split(";")[0].strip())
                    if max_age < 31536000:  # Less than 1 year
                        self.add_finding(
                            title="Weak HSTS max-age",
                            description=f"HSTS max-age is {max_age} seconds. Should be at least 1 year.",
                            severity="low",
                            remediation="Set max-age to at least 31536000 (1 year)."
                        )
                except ValueError:
                    pass
        
        elif header_lower == "content-security-policy":
            # Check for unsafe CSP directives
            if "unsafe-inline" in value_lower:
                self.add_finding(
                    title="CSP Allows unsafe-inline",
                    description="Content-Security-Policy allows inline scripts, reducing XSS protection.",
                    severity="medium",
                    remediation="Remove 'unsafe-inline' and use nonces or hashes instead."
                )
            if "unsafe-eval" in value_lower:
                self.add_finding(
                    title="CSP Allows unsafe-eval",
                    description="Content-Security-Policy allows eval(), reducing security.",
                    severity="medium",
                    remediation="Remove 'unsafe-eval' from CSP."
                )
        
        elif header_lower == "x-frame-options":
            if value_lower not in ["deny", "sameorigin"]:
                self.add_finding(
                    title="Weak X-Frame-Options",
                    description=f"X-Frame-Options value '{value}' may not provide adequate protection.",
                    severity="low",
                    remediation="Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options."
                )
