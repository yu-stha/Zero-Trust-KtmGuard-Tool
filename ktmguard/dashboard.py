#!/usr/bin/env python3
"""KTMGuard Dashboard - a local Flask web UI that wraps the ktmguard.py CLI.

This file does not reimplement any KTMGuard scanning/policy-generation/
verification logic. Every action shells out to `ktmguard.py` (or, for
Apply, `kubectl apply`) as a subprocess and either streams its raw output
or reads the same JSON/YAML files ktmguard.py already writes to
ktmguard-output/. Runs on 127.0.0.1 only - same trust model as running
kubectl/ktmguard.py directly at a terminal, so there is no authentication.
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, send_file

try:
    import markdown as markdown_lib
except ImportError:
    print("Error: the 'markdown' package is not installed.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent
KTMGUARD_PY = BASE_DIR / "ktmguard.py"
OUTPUT_DIR = BASE_DIR / "ktmguard-output"
STATE_DIR = OUTPUT_DIR / ".state"
REPORT_PATH = OUTPUT_DIR / "report.md"

app = Flask(__name__)

# In-memory only, by design: the dashboard adds no persistent storage of its
# own beyond what ktmguard.py already writes to ktmguard-output/. "Defaults
# to last used" holds for the lifetime of this process, not across restarts.
_last_namespace = "boutique"

_lock = threading.Lock()
_job = {
    "action": None,
    "cmd": None,
    "lines": [],
    "running": False,
    "returncode": None,
}


def _reset_job(action, cmd):
    with _lock:
        _job["action"] = action
        _job["cmd"] = cmd
        _job["lines"] = []
        _job["running"] = True
        _job["returncode"] = None


def _append_line(line):
    with _lock:
        _job["lines"].append(line)


def _finish_job(returncode):
    with _lock:
        _job["running"] = False
        _job["returncode"] = returncode


def _run_subprocess(cmd):
    """Runs cmd with BASE_DIR as cwd (so ktmguard-output/ resolves the same
    way it does when running ktmguard.py directly), streaming each output
    line into the shared job state as it arrives. Runs in a background
    thread - never called on the Flask request thread."""
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(BASE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        _append_line(f"[dashboard] Failed to start command: {exc}")
        _finish_job(-1)
        return

    for line in proc.stdout:
        _append_line(line.rstrip("\n"))
    proc.wait()
    _finish_job(proc.returncode)


def _start_job(action, cmd):
    with _lock:
        if _job["running"]:
            return False
    _reset_job(action, cmd)
    threading.Thread(target=_run_subprocess, args=(cmd,), daemon=True).start()
    return True


def _ktmguard_cmd(*args):
    # -u: force the child interpreter's stdout unbuffered, so print()
    # output reaches the dashboard as it happens rather than sitting in a
    # buffer until the process exits (Python fully-buffers stdout by
    # default when it isn't a tty, which a subprocess pipe never is).
    return [sys.executable, "-u", str(KTMGUARD_PY), *args]


def _read_json(path):
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", namespace=_last_namespace)


# --------------------------------------------------------------------------
# Cluster status
# --------------------------------------------------------------------------

@app.route("/api/cluster-status")
def cluster_status():
    try:
        result = subprocess.run(
            ["kubectl", "get", "nodes"],
            capture_output=True, text=True, timeout=5,
        )
        connected = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        connected = False
    return jsonify({"connected": connected})


# --------------------------------------------------------------------------
# Run / stream
# --------------------------------------------------------------------------

@app.route("/api/run/<action>", methods=["POST"])
def run_action(action):
    global _last_namespace
    payload = request.get_json(silent=True) or {}

    with _lock:
        if _job["running"]:
            return jsonify({"error": "A command is already running."}), 409

    if action == "scan":
        namespace = (payload.get("namespace") or "").strip()
        if not namespace:
            return jsonify({"error": "Namespace is required."}), 400
        _last_namespace = namespace
        cmd = _ktmguard_cmd("scan", "--namespace", namespace)
        prometheus = (payload.get("prometheus") or "").strip()
        if prometheus:
            cmd += ["--prometheus", prometheus]
        if payload.get("tap"):
            tap_duration = payload.get("tap_duration") or 30
            try:
                tap_duration = int(tap_duration)
            except (TypeError, ValueError):
                return jsonify({"error": "tap_duration must be a number."}), 400
            cmd += ["--tap", "--tap-duration", str(tap_duration)]

    elif action == "generate":
        namespace = (payload.get("namespace") or "").strip()
        if not namespace:
            return jsonify({"error": "Namespace is required."}), 400
        _last_namespace = namespace
        cmd = _ktmguard_cmd("generate", "--namespace", namespace)
        if payload.get("dry_run"):
            cmd += ["--dry-run"]

    elif action == "apply":
        if not payload.get("confirm"):
            return jsonify({"error": "Apply requires confirmation."}), 400
        cmd = ["kubectl", "apply", "-f", "ktmguard-output/"]

    elif action == "verify":
        namespace = (payload.get("namespace") or "").strip()
        if not namespace:
            return jsonify({"error": "Namespace is required."}), 400
        _last_namespace = namespace
        cmd = _ktmguard_cmd("verify", "--namespace", namespace)

    elif action == "report":
        namespace = (payload.get("namespace") or "").strip()
        if not namespace:
            return jsonify({"error": "Namespace is required."}), 400
        _last_namespace = namespace
        cmd = _ktmguard_cmd(
            "report", "--namespace", namespace,
            "--output", str(REPORT_PATH),
        )

    else:
        return jsonify({"error": f"Unknown action '{action}'."}), 404

    started = _start_job(action, cmd)
    if not started:
        return jsonify({"error": "A command is already running."}), 409
    return jsonify({"started": True, "action": action})


@app.route("/api/stream")
def stream():
    try:
        since = int(request.args.get("since", 0))
    except ValueError:
        since = 0

    def generate():
        idx = since
        while True:
            with _lock:
                total = len(_job["lines"])
                new_lines = _job["lines"][idx:total]
                running = _job["running"]
                returncode = _job["returncode"]
            for line in new_lines:
                idx += 1
                yield f"data: {json.dumps({'line': line, 'index': idx})}\n\n"
            if not running and idx >= total:
                yield (
                    "event: done\n"
                    f"data: {json.dumps({'returncode': returncode})}\n\n"
                )
                break
            time.sleep(0.3)

    return Response(generate(), mimetype="text/event-stream")


# --------------------------------------------------------------------------
# Per-action results (read-only: parses files ktmguard.py already wrote)
# --------------------------------------------------------------------------

@app.route("/api/scan-result")
def scan_result():
    data = _read_json(STATE_DIR / "service-map.json")
    if data is None:
        return jsonify({"available": False})
    return jsonify({
        "available": True,
        "edges": data.get("edges", []),
        "manual_review_required": data.get("manual_review_required", False),
    })


@app.route("/api/generate-result")
def generate_result():
    files = {}
    for name in ("deny-all.yaml", "allow-policies.yaml", "linkerd-auth-policy.yaml"):
        path = OUTPUT_DIR / name
        if path.exists():
            try:
                files[name] = path.read_text()
            except OSError:
                pass
    return jsonify({"files": files})


@app.route("/api/verify-result")
def verify_result():
    data = _read_json(STATE_DIR / "verify-results.json")
    if data is None:
        return jsonify({"available": False})

    connectivity = []
    for r in data.get("connectivity", []):
        reachable = r.get("reachable")
        expected_blocked = r.get("expected_blocked")
        if reachable is None:
            status_text, matches = "UNKNOWN (probe failed)", None
        else:
            status_text = "BLOCKED" if not reachable else "REACHABLE"
            matches = reachable != expected_blocked
        connectivity.append({
            "src": r.get("src"), "dst": r.get("dst"), "port": r.get("port"),
            "status_text": status_text, "matches": matches,
        })

    return jsonify({
        "available": True,
        "pod_injection": data.get("pod_injection"),
        "network_policies": data.get("network_policies"),
        "auth_policies": data.get("auth_policies"),
        "overall_ok": data.get("overall_ok"),
        "connectivity": connectivity,
        "note": (
            "Connectivity results reflect TCP-layer reachability only. "
            "Linkerd's proxy may report a connection as reachable even when "
            "application-layer authorization blocks it. These results do not "
            "affect the overall verdict above - verify critical paths "
            "manually, e.g.: kubectl exec -it -n <ns> deploy/<src> -- "
            "wget -qO- --timeout=3 http://<dst>:<port>/"
        ),
    })


@app.route("/api/report-result")
def report_result():
    if not REPORT_PATH.exists():
        return jsonify({"available": False})
    try:
        raw = REPORT_PATH.read_text()
    except OSError:
        return jsonify({"available": False})
    html = markdown_lib.markdown(raw, extensions=["tables"])
    return jsonify({"available": True, "html": html})


@app.route("/api/report-download")
def report_download():
    if not REPORT_PATH.exists():
        return jsonify({"error": "No report has been generated yet."}), 404
    return send_file(str(REPORT_PATH), as_attachment=True, download_name="report.md")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, threaded=True)
