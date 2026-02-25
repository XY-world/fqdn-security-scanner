#!/usr/bin/env python3
"""
FQDN Security Scanner - Web UI

A Flask-based web interface for the security scanner with multi-agent orchestration.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading

from modules.dns_scanner import DNSScanner
from modules.ssl_scanner import SSLScanner
from modules.header_scanner import HeaderScanner
from modules.port_scanner import PortScanner
from modules.subdomain_scanner import SubdomainScanner
from modules.vuln_scanner import VulnScanner
from report.generator import ReportGenerator
from agents.manager import agent_manager
from agents.discovery import discovery_agent
from agents.pr_agent import pr_agent

app = Flask(__name__)
CORS(app)

# Store scan results and status
scans = {}
scan_lock = threading.Lock()

AVAILABLE_MODULES = {
    "dns": {"class": DNSScanner, "name": "DNS Security", "icon": "🌐"},
    "ssl": {"class": SSLScanner, "name": "SSL/TLS", "icon": "🔒"},
    "headers": {"class": HeaderScanner, "name": "HTTP Headers", "icon": "📋"},
    "ports": {"class": PortScanner, "name": "Port Scan", "icon": "🚪"},
    "subdomains": {"class": SubdomainScanner, "name": "Subdomains", "icon": "🔍"},
    "vulns": {"class": VulnScanner, "name": "Vulnerabilities", "icon": "⚠️"},
}


def calculate_risk_score(findings):
    """Calculate overall risk score from findings."""
    severity_scores = {"critical": 40, "high": 25, "medium": 10, "low": 5, "info": 1}
    total = sum(severity_scores.get(f.get("severity", "info").lower(), 0) for f in findings)
    return min(total, 100)


def run_scan_async(scan_id, target, modules, timeout):
    """Run scan in background thread."""
    # Update scanner agent status
    agent_manager.update_agent_status("scanner", "active")
    agent_manager.add_activity("scanner", f"Starting scan of {target}")
    
    with scan_lock:
        scans[scan_id]["status"] = "running"
        scans[scan_id]["started_at"] = datetime.utcnow().isoformat()
    
    results = {
        "target": target,
        "scan_time": datetime.utcnow().isoformat(),
        "modules_run": modules,
        "findings": [],
        "module_results": {},
    }
    
    total_modules = len(modules)
    completed = 0
    
    for module_name in modules:
        if module_name not in AVAILABLE_MODULES:
            continue
        
        with scan_lock:
            scans[scan_id]["current_module"] = module_name
            scans[scan_id]["progress"] = int((completed / total_modules) * 100)
        
        try:
            scanner_class = AVAILABLE_MODULES[module_name]["class"]
            scanner = scanner_class(target, timeout=timeout)
            module_results = scanner.scan()
            
            results["module_results"][module_name] = module_results
            
            if "findings" in module_results:
                for finding in module_results["findings"]:
                    finding["module"] = module_name
                    results["findings"].append(finding)
                    
        except Exception as e:
            results["module_results"][module_name] = {
                "error": str(e),
                "status": "failed"
            }
        
        completed += 1
    
    # Calculate risk score and summary
    results["risk_score"] = calculate_risk_score(results["findings"])
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in results["findings"]:
        sev = finding.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    results["severity_summary"] = severity_counts
    
    with scan_lock:
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["progress"] = 100
        scans[scan_id]["results"] = results
        scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
    
    # Update scanner agent stats
    agent_manager.increment_stat("scanner", "scans_completed")
    agent_manager.update_agent_status("scanner", "idle", f"Completed scan of {target}")
    agent_manager.add_activity("scanner", f"Completed scan of {target} - {len(results['findings'])} findings")


@app.route("/")
def index():
    """Render main page."""
    # Only pass serializable data to template
    modules_data = {
        name: {"name": info["name"], "icon": info["icon"]}
        for name, info in AVAILABLE_MODULES.items()
    }
    agents_data = agent_manager.get_all_agents()
    return render_template("index.html", modules=modules_data, agents=agents_data)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    data = request.json
    target = data.get("target", "").strip().lower()
    modules = data.get("modules", list(AVAILABLE_MODULES.keys()))
    timeout = data.get("timeout", 30)
    
    # Validate target
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Extract domain from URL if needed
    if target.startswith("http://") or target.startswith("https://"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc
    
    # Generate scan ID
    scan_id = f"{target}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    
    with scan_lock:
        scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "modules": modules,
            "status": "pending",
            "progress": 0,
            "current_module": None,
            "results": None,
        }
    
    # Start scan in background
    executor = ThreadPoolExecutor(max_workers=1)
    executor.submit(run_scan_async, scan_id, target, modules, timeout)
    
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/<scan_id>")
def get_scan_status(scan_id):
    """Get scan status and results."""
    with scan_lock:
        if scan_id not in scans:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(scans[scan_id])


@app.route("/api/scan/<scan_id>/report")
def get_report(scan_id):
    """Get scan report in specified format."""
    format_type = request.args.get("format", "json")
    
    with scan_lock:
        if scan_id not in scans:
            return jsonify({"error": "Scan not found"}), 404
        
        scan = scans[scan_id]
        if scan["status"] != "completed":
            return jsonify({"error": "Scan not completed"}), 400
        
        results = scan["results"]
    
    generator = ReportGenerator(results)
    
    if format_type == "json":
        return Response(generator.to_json(), mimetype="application/json")
    elif format_type == "md":
        return Response(generator.to_markdown(), mimetype="text/markdown")
    elif format_type == "html":
        return Response(generator.to_html(), mimetype="text/html")
    else:
        return jsonify({"error": "Invalid format"}), 400


@app.route("/api/modules")
def get_modules():
    """Get available modules."""
    return jsonify({
        name: {"name": info["name"], "icon": info["icon"]}
        for name, info in AVAILABLE_MODULES.items()
    })


# ============ Agent API Endpoints ============

@app.route("/api/agents")
def get_agents():
    """Get all agent statuses."""
    return jsonify(agent_manager.get_all_agents())


@app.route("/api/agents/<agent_name>")
def get_agent(agent_name):
    """Get a specific agent's status."""
    agent = agent_manager.get_agent(agent_name)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    from dataclasses import asdict
    return jsonify(asdict(agent))


@app.route("/api/agents/activities")
def get_activities():
    """Get recent agent activities."""
    limit = request.args.get("limit", 20, type=int)
    return jsonify(agent_manager.get_activities(limit))


@app.route("/api/agents/discoveries")
def get_discoveries():
    """Get security discoveries."""
    limit = request.args.get("limit", 10, type=int)
    status = request.args.get("status")
    return jsonify(agent_manager.get_discoveries(limit, status))


@app.route("/api/agents/discoveries/<int:discovery_id>", methods=["PATCH"])
def update_discovery(discovery_id):
    """Update a discovery's status."""
    data = request.json
    status = data.get("status")
    if not status:
        return jsonify({"error": "Status is required"}), 400
    
    if agent_manager.update_discovery_status(discovery_id, status):
        return jsonify({"success": True})
    return jsonify({"error": "Discovery not found"}), 404


@app.route("/api/agents/discovery/trigger", methods=["POST"])
def trigger_discovery():
    """Manually trigger a discovery search (for demo/testing)."""
    discovery_agent.start_search()
    
    # Add a sample discovery for demo
    data = request.json or {}
    if data.get("demo"):
        discovery_agent.add_finding(
            title="Demo: New TLS 1.3 Extension Vulnerability",
            description="A new vulnerability in TLS 1.3 extension handling has been discovered that may allow...",
            source="https://example.com/cve-2026-demo",
            category="cve"
        )
    
    discovery_agent.complete_search(1 if data.get("demo") else 0)
    return jsonify({"success": True, "message": "Discovery search triggered"})


@app.route("/api/agents/pr/trigger", methods=["POST"])
def trigger_pr_agent():
    """Manually trigger the PR agent (for demo/testing)."""
    data = request.json or {}
    discovery_id = data.get("discovery_id")
    
    if discovery_id:
        pr_agent.start_task(f"Processing discovery #{discovery_id}")
        pr_agent.queue_detection_module(discovery_id, {
            "name": "TLS Extension Check",
            "description": "Check for TLS 1.3 extension vulnerability"
        })
        pr_agent.complete_task("Module code generated")
        return jsonify({"success": True, "message": "PR agent task completed"})
    
    return jsonify({"error": "discovery_id is required"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
