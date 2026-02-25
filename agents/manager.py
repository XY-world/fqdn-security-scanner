"""
Agent Manager - Coordinates multiple AI agents for security scanning.

Agents:
- Discovery Agent: Searches for new vulnerabilities, CVEs, detection methods
- Scanner Agent: Dynamically enriches detection modules, runs scans
- PR Agent: Generates detection code and submits PRs to GitHub
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict
from enum import Enum

DATA_DIR = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

class AgentStatus(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    ERROR = "error"

@dataclass
class AgentState:
    name: str
    display_name: str
    icon: str
    status: str = "idle"
    last_run: Optional[str] = None
    last_result: Optional[str] = None
    stats: dict = None
    
    def __post_init__(self):
        if self.stats is None:
            self.stats = {}

class AgentManager:
    """Manages agent states and coordination."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self.state_file = DATA_DIR / "agent_states.json"
        self.activity_file = DATA_DIR / "agent_activity.json"
        self.discoveries_file = DATA_DIR / "discoveries.json"
        self.analysis_file = DATA_DIR / "coverage_analysis.json"
        
        self.coverage_analysis = {}
        
        # Initialize default agents
        self.agents = {
            "discovery": AgentState(
                name="discovery",
                display_name="Discovery Agent",
                icon="🔍",
                stats={"discoveries": 0, "last_search": None}
            ),
            "scanner": AgentState(
                name="scanner", 
                display_name="Scanner Agent",
                icon="🛡️",
                stats={"scans_completed": 0, "available_modules": 6}  # dns, ssl, headers, ports, subdomains, vulns
            ),
            "pr_agent": AgentState(
                name="pr_agent",
                display_name="PR Agent", 
                icon="🔧",
                stats={"prs_opened": 0, "prs_merged": 0}
            )
        }
        
        self.activities = []
        self.discoveries = []
        
        self._load_state()
    
    def _load_state(self):
        """Load persisted state from disk."""
        try:
            if self.state_file.exists():
                data = json.loads(self.state_file.read_text())
                for name, state in data.items():
                    if name in self.agents:
                        self.agents[name] = AgentState(**state)
        except Exception:
            pass
        
        try:
            if self.activity_file.exists():
                self.activities = json.loads(self.activity_file.read_text())[-100:]  # Keep last 100
        except Exception:
            self.activities = []
        
        try:
            if self.discoveries_file.exists():
                self.discoveries = json.loads(self.discoveries_file.read_text())[-50:]  # Keep last 50
        except Exception:
            self.discoveries = []
        
        try:
            if self.analysis_file.exists():
                self.coverage_analysis = json.loads(self.analysis_file.read_text())
        except Exception:
            self.coverage_analysis = {}
    
    def _save_state(self):
        """Persist state to disk."""
        try:
            state_data = {name: asdict(agent) for name, agent in self.agents.items()}
            self.state_file.write_text(json.dumps(state_data, indent=2))
            self.activity_file.write_text(json.dumps(self.activities[-100:], indent=2))
            self.discoveries_file.write_text(json.dumps(self.discoveries[-50:], indent=2))
            if self.coverage_analysis:
                self.analysis_file.write_text(json.dumps(self.coverage_analysis, indent=2))
        except Exception as e:
            print(f"Error saving agent state: {e}")
    
    def get_agent(self, name: str) -> Optional[AgentState]:
        return self.agents.get(name)
    
    def get_all_agents(self) -> dict:
        return {name: asdict(agent) for name, agent in self.agents.items()}
    
    def update_agent_status(self, name: str, status: str, result: str = None):
        """Update agent status and optionally its last result."""
        if name not in self.agents:
            return
        
        agent = self.agents[name]
        agent.status = status
        agent.last_run = datetime.now(timezone.utc).isoformat()
        if result:
            agent.last_result = result
        
        self._save_state()
    
    def increment_stat(self, agent_name: str, stat_name: str, amount: int = 1):
        """Increment a stat counter for an agent."""
        if agent_name in self.agents:
            agent = self.agents[agent_name]
            current = agent.stats.get(stat_name, 0)
            agent.stats[stat_name] = current + amount
            self._save_state()
    
    def add_activity(self, agent_name: str, message: str):
        """Add an activity log entry."""
        activity = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent_name,
            "message": message
        }
        self.activities.append(activity)
        self._save_state()
    
    def get_activities(self, limit: int = 20) -> list:
        """Get recent activities."""
        return self.activities[-limit:][::-1]  # Most recent first
    
    def add_discovery(self, title: str, description: str, source: str, category: str = "vulnerability"):
        """Add a new discovery from the Discovery Agent."""
        discovery = {
            "id": len(self.discoveries) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "title": title,
            "description": description,
            "source": source,
            "category": category,
            "status": "new"  # new, reviewing, implemented, dismissed
        }
        self.discoveries.append(discovery)
        self.increment_stat("discovery", "discoveries")
        self._save_state()
        return discovery
    
    def get_discoveries(self, limit: int = 10, status: str = None) -> list:
        """Get recent discoveries, optionally filtered by status."""
        results = self.discoveries
        if status:
            results = [d for d in results if d.get("status") == status]
        return results[-limit:][::-1]
    
    def update_discovery_status(self, discovery_id: int, status: str):
        """Update the status of a discovery."""
        for d in self.discoveries:
            if d.get("id") == discovery_id:
                d["status"] = status
                self._save_state()
                return True
        return False
    
    def set_coverage_analysis(self, analysis: dict):
        """Set the coverage analysis results."""
        self.coverage_analysis = analysis
        self._save_state()
    
    def get_coverage_analysis(self) -> dict:
        """Get the latest coverage analysis."""
        return self.coverage_analysis


# Global instance
agent_manager = AgentManager()
