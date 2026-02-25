"""Port Scanner Module."""

import socket
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseScanner


class PortScanner(BaseScanner):
    """Scan common ports for services."""
    
    # Common ports to scan
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }
    
    # Ports that shouldn't be exposed publicly
    RISKY_PORTS = {
        21: "FTP is insecure, use SFTP instead",
        23: "Telnet transmits data in plaintext",
        445: "SMB often targeted for attacks",
        3306: "MySQL should not be publicly accessible",
        5432: "PostgreSQL should not be publicly accessible",
        5900: "VNC often has weak authentication",
        6379: "Redis without auth is extremely dangerous",
        27017: "MongoDB without auth is extremely dangerous",
        3389: "RDP is frequently targeted for brute force",
    }
    
    def scan(self) -> Dict[str, Any]:
        """Run port scan."""
        results = {
            "status": "completed",
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
            "findings": [],
        }
        
        # Resolve hostname
        try:
            ip_address = socket.gethostbyname(self.target)
            results["ip_address"] = ip_address
        except socket.gaierror:
            results["status"] = "error"
            results["error"] = f"Could not resolve hostname: {self.target}"
            return results
        
        # Scan ports in parallel
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip_address, port): port 
                for port in self.COMMON_PORTS.keys()
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_ports.append(port)
                        results["services"][port] = self.COMMON_PORTS[port]
                except Exception:
                    results["filtered_ports"].append(port)
        
        results["open_ports"] = sorted(open_ports)
        results["closed_ports"] = sorted([
            p for p in self.COMMON_PORTS.keys() 
            if p not in open_ports and p not in results["filtered_ports"]
        ])
        
        # Check for risky open ports
        for port in open_ports:
            if port in self.RISKY_PORTS:
                self.add_finding(
                    title=f"Risky Port Open: {port} ({self.COMMON_PORTS[port]})",
                    description=self.RISKY_PORTS[port],
                    severity="high" if port in [6379, 27017, 23] else "medium",
                    remediation=f"Consider closing port {port} or restricting access via firewall."
                )
        
        # Check if HTTP without HTTPS
        if 80 in open_ports and 443 not in open_ports:
            self.add_finding(
                title="HTTP Without HTTPS",
                description="Port 80 (HTTP) is open but port 443 (HTTPS) is not.",
                severity="medium",
                remediation="Enable HTTPS on port 443 with a valid SSL certificate."
            )
        
        # Check for unencrypted mail ports
        if 110 in open_ports and 995 not in open_ports:
            self.add_finding(
                title="Unencrypted POP3",
                description="POP3 (110) is open without POP3S (995).",
                severity="medium",
                remediation="Use POP3S (port 995) instead of unencrypted POP3."
            )
        
        if 143 in open_ports and 993 not in open_ports:
            self.add_finding(
                title="Unencrypted IMAP",
                description="IMAP (143) is open without IMAPS (993).",
                severity="medium",
                remediation="Use IMAPS (port 993) instead of unencrypted IMAP."
            )
        
        results["findings"] = self.get_findings()
        return results
    
    def _check_port(self, ip: str, port: int) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
