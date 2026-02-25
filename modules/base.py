"""Base scanner class."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class BaseScanner(ABC):
    """Base class for all security scanners."""
    
    def __init__(self, target: str, timeout: int = 30):
        """
        Initialize scanner.
        
        Args:
            target: Target FQDN to scan
            timeout: Timeout in seconds
        """
        self.target = target
        self.timeout = timeout
        self.findings: List[Dict[str, Any]] = []
    
    @abstractmethod
    def scan(self) -> Dict[str, Any]:
        """
        Run the scan and return results.
        
        Returns:
            Dictionary containing scan results and findings
        """
        pass
    
    def add_finding(
        self,
        title: str,
        description: str,
        severity: str = "info",
        remediation: str = "",
        references: List[str] = None
    ):
        """
        Add a finding to the results.
        
        Args:
            title: Short title of the finding
            description: Detailed description
            severity: critical, high, medium, low, info
            remediation: How to fix the issue
            references: List of reference URLs
        """
        self.findings.append({
            "title": title,
            "description": description,
            "severity": severity,
            "remediation": remediation,
            "references": references or [],
        })
    
    def get_findings(self) -> List[Dict[str, Any]]:
        """Return all findings."""
        return self.findings
