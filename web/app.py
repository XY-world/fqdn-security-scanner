#!/usr/bin/env python3
"""
FQDN Security Scanner - Web UI

A Flask-based web interface for the security scanner with multi-agent orchestration.
"""

import sys
import os
import importlib.util
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, Response, session
from flask_cors import CORS
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import threading
import secrets
import functools

from modules.dns_scanner import DNSScanner
from report.generator import ReportGenerator
from agents.manager import agent_manager
from agents.discovery import discovery_agent
from agents.pr_agent import pr_agent

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # For session management
CORS(app)

# Admin credentials (in production, use environment variables)
ADMIN_USERNAME = os.environ.get("SCANNER_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("SCANNER_ADMIN_PASS", "domainforge2026")


def require_admin(f):
    """Decorator to require admin authentication for agent endpoints."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session
        if session.get("admin_authenticated"):
            return f(*args, **kwargs)
        # Check header token
        auth_token = request.headers.get("X-Admin-Token")
        if auth_token == ADMIN_PASSWORD:
            return f(*args, **kwargs)
        return jsonify({"error": "Authentication required", "login_url": "/agents/login"}), 401
    return decorated_function

# Store scan results and status
scans = {}
scan_lock = threading.Lock()

# Base modules (always available)
AVAILABLE_MODULES = {
    "dns": {"class": DNSScanner, "name": "DNS Security", "icon": "🌐"},
}

# Hot-loadable modules registry (populated from dynamic_modules.json)
DYNAMIC_MODULES = {}

PROJECT_DIR = Path(__file__).parent.parent
DYNAMIC_MODULES_DIR = PROJECT_DIR / "dynamic_modules"


def load_dynamic_modules():
    """Load all dynamic modules from registry."""
    global DYNAMIC_MODULES
    DYNAMIC_MODULES = {}
    
    registry_file = PROJECT_DIR / "data" / "dynamic_modules.json"
    if not registry_file.exists():
        return
    
    try:
        registry = json.loads(registry_file.read_text())
        for module_id, info in registry.items():
            module_file = Path(info["file"])
            if not module_file.exists():
                continue
            
            try:
                spec = importlib.util.spec_from_file_location(module_id, module_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find the scanner class
                scanner_class = None
                for name in dir(module):
                    obj = getattr(module, name)
                    if isinstance(obj, type) and name.endswith("Scanner") and name != "BaseScanner":
                        scanner_class = obj
                        break
                
                if scanner_class:
                    DYNAMIC_MODULES[module_id] = {
                        "class": scanner_class,
                        "name": info["name"],
                        "icon": info["icon"]
                    }
                    print(f"Loaded dynamic module: {module_id}")
            except Exception as e:
                print(f"Error loading module {module_id}: {e}")
    except Exception as e:
        print(f"Error reading module registry: {e}")


def get_all_modules():
    """Get all available modules (static + dynamic)."""
    # Reload dynamic modules on each call to pick up newly loaded ones
    load_dynamic_modules()
    return {**AVAILABLE_MODULES, **DYNAMIC_MODULES}


def hot_load_module(module_id: str, module_class, name: str, icon: str):
    """Hot-load a new scanner module."""
    DYNAMIC_MODULES[module_id] = {
        "class": module_class,
        "name": name,
        "icon": icon
    }
    # Update scanner agent stats
    agent_manager.agents["scanner"].stats["available_modules"] = len(get_all_modules())
    agent_manager._save_state()


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
            scanner_class = get_all_modules()[module_name]["class"]
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
        for name, info in get_all_modules().items()
    }
    agents_data = agent_manager.get_all_agents()
    return render_template("index.html", modules=modules_data, agents=agents_data)


# ============ Admin Authentication ============

@app.route("/agents/login", methods=["GET", "POST"])
def agents_login():
    """Admin login page for agent management."""
    if request.method == "POST":
        data = request.json or request.form
        username = data.get("username", "")
        password = data.get("password", "")
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_authenticated"] = True
            if request.is_json:
                return jsonify({"success": True, "message": "Login successful"})
            return render_template("index.html", modules={}, agents={}, login_success=True)
        else:
            if request.is_json:
                return jsonify({"error": "Invalid credentials"}), 401
            return render_template("login.html", error="Invalid credentials")
    
    return render_template("login.html")


@app.route("/agents/logout")
def agents_logout():
    """Logout from admin."""
    session.pop("admin_authenticated", None)
    return jsonify({"success": True, "message": "Logged out"})


@app.route("/agents/check")
def agents_check():
    """Check if user is authenticated."""
    if session.get("admin_authenticated"):
        return jsonify({"authenticated": True})
    return jsonify({"authenticated": False}), 401


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new scan."""
    data = request.json
    target = data.get("target", "").strip().lower()
    modules = data.get("modules", list(get_all_modules().keys()))
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
        for name, info in get_all_modules().items()
    })


# ============ Agent API Endpoints (Protected) ============

@app.route("/api/agents")
@require_admin
def get_agents():
    """Get all agent statuses."""
    return jsonify(agent_manager.get_all_agents())


@app.route("/api/agents/<agent_name>")
@require_admin
def get_agent(agent_name):
    """Get a specific agent's status."""
    agent = agent_manager.get_agent(agent_name)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    from dataclasses import asdict
    return jsonify(asdict(agent))


@app.route("/api/agents/activities")
@require_admin
def get_activities():
    """Get recent agent activities."""
    limit = request.args.get("limit", 20, type=int)
    return jsonify(agent_manager.get_activities(limit))


@app.route("/api/agents/discoveries")
@require_admin
def get_discoveries():
    """Get security discoveries."""
    limit = request.args.get("limit", 10, type=int)
    status = request.args.get("status")
    return jsonify(agent_manager.get_discoveries(limit, status))


@app.route("/api/agents/coverage")
@require_admin
def get_coverage():
    """Get coverage analysis with latest discovery statuses."""
    coverage = agent_manager.get_coverage_analysis()
    
    # Merge latest discovery statuses into uncovered items
    if coverage and coverage.get("uncovered"):
        discoveries = agent_manager.get_discoveries(limit=100)
        status_map = {d.get("id"): d.get("status", "new") for d in discoveries}
        
        for item in coverage["uncovered"]:
            item_id = item.get("id")
            if item_id in status_map:
                item["status"] = status_map[item_id]
    
    return jsonify(coverage)


@app.route("/api/agents/discoveries/<int:discovery_id>", methods=["PATCH"])
@require_admin
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
@require_admin
def trigger_discovery():
    """Trigger a real discovery search using web search."""
    import subprocess
    import threading
    
    def run_discovery_async():
        try:
            subprocess.run(
                ["python3", "agents/discovery_runner.py"],
                cwd=str(Path(__file__).parent.parent),
                timeout=120
            )
        except Exception as e:
            agent_manager.update_agent_status("discovery", "error", str(e))
    
    # Run in background thread
    thread = threading.Thread(target=run_discovery_async)
    thread.start()
    
    return jsonify({"success": True, "message": "Discovery search started"})


@app.route("/api/agents/pr/trigger", methods=["POST"])
@require_admin
def trigger_pr_agent():
    """Trigger the PR agent to process a discovery."""
    import subprocess
    import threading
    
    data = request.json or {}
    discovery_id = data.get("discovery_id")
    
    if not discovery_id:
        return jsonify({"error": "discovery_id is required"}), 400
    
    def run_pr_agent_async(disc_id):
        try:
            subprocess.run(
                ["python3", "agents/pr_agent_runner.py", str(disc_id)],
                cwd=str(Path(__file__).parent.parent),
                timeout=120
            )
        except Exception as e:
            agent_manager.update_agent_status("pr_agent", "error", str(e))
    
    # Run in background thread
    thread = threading.Thread(target=run_pr_agent_async, args=(discovery_id,))
    thread.start()
    
    return jsonify({"success": True, "message": f"PR agent processing discovery #{discovery_id}"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
