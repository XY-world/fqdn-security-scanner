
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
