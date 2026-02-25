"""
Discovery Agent - Searches for new vulnerabilities, CVEs, and detection methods.

This agent runs on a schedule to:
1. Search security news sources for new vulnerabilities
2. Monitor CVE databases for relevant entries
3. Find new detection techniques and methods
4. Alert the Scanner Agent about new checks needed
"""

import json
from datetime import datetime, timezone
from typing import List, Dict
from .manager import agent_manager


class DiscoveryAgent:
    """Agent that discovers new security vulnerabilities and techniques."""
    
    SEARCH_TOPICS = [
        "FQDN security vulnerability",
        "DNS security CVE",
        "SSL TLS vulnerability",
        "HTTP security headers bypass",
        "subdomain takeover technique",
        "certificate transparency vulnerability",
        "DNSSEC bypass",
        "email security SPF DKIM DMARC bypass",
    ]
    
    CATEGORIES = {
        "cve": "CVE/Vulnerability",
        "technique": "New Technique",
        "tool": "Security Tool",
        "research": "Research Paper",
        "news": "Security News"
    }
    
    def __init__(self):
        self.name = "discovery"
    
    def start_search(self):
        """Begin a discovery search session."""
        agent_manager.update_agent_status(self.name, "active")
        agent_manager.add_activity(self.name, "Starting security discovery search...")
    
    def complete_search(self, found_count: int):
        """Mark search as complete."""
        agent_manager.update_agent_status(
            self.name, 
            "idle", 
            f"Found {found_count} new items"
        )
        agent_manager.add_activity(
            self.name, 
            f"Completed search. Found {found_count} new discoveries."
        )
    
    def add_finding(self, title: str, description: str, source: str, category: str = "vulnerability"):
        """Add a new finding to the discoveries list."""
        discovery = agent_manager.add_discovery(title, description, source, category)
        agent_manager.add_activity(
            self.name,
            f"New discovery: {title}"
        )
        return discovery
    
    def get_search_topics(self) -> List[str]:
        """Get the list of topics to search for."""
        return self.SEARCH_TOPICS
    
    def process_search_results(self, results: List[Dict]) -> List[Dict]:
        """Process and filter search results, adding relevant ones as discoveries."""
        new_discoveries = []
        
        for result in results:
            # Check if this is actually new and relevant
            title = result.get("title", "")
            description = result.get("description", "")
            url = result.get("url", "")
            
            # Add as discovery
            discovery = self.add_finding(
                title=title,
                description=description,
                source=url,
                category=result.get("category", "news")
            )
            new_discoveries.append(discovery)
        
        return new_discoveries


# Singleton instance
discovery_agent = DiscoveryAgent()
