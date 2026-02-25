"""Vulnerability Scanner Module."""

import requests
from typing import Dict, Any, List
from urllib.parse import urljoin

from .base import BaseScanner


class VulnScanner(BaseScanner):
    """Check for known vulnerabilities and misconfigurations."""
    
    # Common sensitive paths to check
    SENSITIVE_PATHS = [
        "/.git/config",
        "/.git/HEAD",
        "/.env",
        "/.svn/entries",
        "/wp-config.php.bak",
        "/config.php.bak",
        "/phpinfo.php",
        "/server-status",
        "/server-info",
        "/.htaccess",
        "/.htpasswd",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/.well-known/security.txt",
        "/security.txt",
        "/humans.txt",
        "/readme.html",
        "/README.md",
        "/CHANGELOG.md",
        "/debug",
        "/trace",
        "/test",
        "/temp",
        "/tmp",
        "/log",
        "/logs",
        "/admin",
        "/administrator",
        "/phpmyadmin",
        "/pma",
        "/adminer.php",
    ]
    
    def scan(self) -> Dict[str, Any]:
        """Run vulnerability scan."""
        results = {
            "status": "completed",
            "exposed_paths": [],
            "version_disclosure": {},
            "security_txt": None,
            "robots_txt": None,
            "findings": [],
        }
        
        base_url = f"https://{self.target}"
        
        # Check sensitive paths
        for path in self.SENSITIVE_PATHS:
            result = self._check_path(base_url, path)
            if result:
                results["exposed_paths"].append(result)
        
        # Check for security.txt
        results["security_txt"] = self._check_security_txt(base_url)
        
        # Check robots.txt for sensitive paths
        results["robots_txt"] = self._check_robots_txt(base_url)
        
        # Check for version disclosure in common software
        results["version_disclosure"] = self._check_version_disclosure(base_url)
        
        results["findings"] = self.get_findings()
        return results
    
    def _check_path(self, base_url: str, path: str) -> Dict[str, Any] | None:
        """Check if a sensitive path is accessible."""
        try:
            url = urljoin(base_url, path)
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "FQDN-Security-Scanner/1.0"}
            )
            
            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")
                content_length = len(response.content)
                
                # Check if it's actual content (not error page)
                if content_length > 0 and content_length < 1000000:
                    result = {
                        "path": path,
                        "status": response.status_code,
                        "content_type": content_type,
                        "size": content_length,
                    }
                    
                    # Determine severity based on path
                    if any(x in path for x in [".git", ".env", ".sql", "config", "htpasswd"]):
                        severity = "critical"
                        desc = f"Critical file exposed: {path}"
                    elif any(x in path for x in [".svn", "phpinfo", "server-status", "server-info"]):
                        severity = "high"
                        desc = f"Sensitive information exposed: {path}"
                    elif any(x in path for x in ["admin", "phpmyadmin", "adminer"]):
                        severity = "medium"
                        desc = f"Admin interface found: {path}"
                    else:
                        severity = "low"
                        desc = f"Path accessible: {path}"
                    
                    self.add_finding(
                        title=f"Exposed Path: {path}",
                        description=desc,
                        severity=severity,
                        remediation=f"Restrict access to {path} or remove it from production."
                    )
                    
                    return result
                    
        except Exception:
            pass
        
        return None
    
    def _check_security_txt(self, base_url: str) -> Dict[str, Any] | None:
        """Check for security.txt file."""
        paths = ["/.well-known/security.txt", "/security.txt"]
        
        for path in paths:
            try:
                url = urljoin(base_url, path)
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200 and "Contact:" in response.text:
                    # Found security.txt - this is good!
                    return {
                        "found": True,
                        "path": path,
                        "content": response.text[:1000],
                    }
            except Exception:
                pass
        
        # No security.txt - add info finding
        self.add_finding(
            title="No security.txt Found",
            description="security.txt file not found. This file helps researchers report vulnerabilities.",
            severity="info",
            remediation="Add a security.txt at /.well-known/security.txt",
            references=["https://securitytxt.org/"]
        )
        
        return {"found": False}
    
    def _check_robots_txt(self, base_url: str) -> Dict[str, Any] | None:
        """Check robots.txt for sensitive paths."""
        try:
            url = urljoin(base_url, "/robots.txt")
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                content = response.text
                result = {
                    "found": True,
                    "disallowed_paths": [],
                }
                
                # Extract disallowed paths
                sensitive_found = []
                for line in content.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        result["disallowed_paths"].append(path)
                        
                        # Check for interesting paths
                        if any(x in path.lower() for x in 
                               ["admin", "login", "dashboard", "api", "internal", "secret", "private"]):
                            sensitive_found.append(path)
                
                if sensitive_found:
                    self.add_finding(
                        title="Sensitive Paths in robots.txt",
                        description=f"robots.txt reveals potentially sensitive paths: {', '.join(sensitive_found)}",
                        severity="low",
                        remediation="Consider if these paths should be disclosed in robots.txt"
                    )
                
                return result
                
        except Exception:
            pass
        
        return {"found": False}
    
    def _check_version_disclosure(self, base_url: str) -> Dict[str, str]:
        """Check for software version disclosure."""
        versions = {}
        
        try:
            response = requests.get(
                base_url,
                timeout=self.timeout,
                headers={"User-Agent": "FQDN-Security-Scanner/1.0"}
            )
            
            # Check headers for versions
            server = response.headers.get("Server", "")
            if server and "/" in server:
                versions["server"] = server
            
            x_powered = response.headers.get("X-Powered-By", "")
            if x_powered:
                versions["powered_by"] = x_powered
            
            # Check HTML for CMS/framework indicators
            html = response.text.lower()
            
            # WordPress
            if "wp-content" in html or "wordpress" in html:
                versions["cms"] = "WordPress"
                
                # Try to get version
                if 'name="generator" content="wordpress' in html:
                    try:
                        start = html.index('name="generator" content="wordpress')
                        end = html.index('"', start + 35)
                        versions["cms_version"] = html[start:end]
                    except ValueError:
                        pass
            
            # Drupal
            elif "drupal" in html:
                versions["cms"] = "Drupal"
            
            # Joomla
            elif "joomla" in html:
                versions["cms"] = "Joomla"
            
            # Add finding if versions are disclosed
            if versions:
                self.add_finding(
                    title="Software Version Disclosure",
                    description=f"Server discloses software versions: {versions}",
                    severity="low",
                    remediation="Hide version information from response headers and HTML."
                )
                
        except Exception:
            pass
        
        return versions
