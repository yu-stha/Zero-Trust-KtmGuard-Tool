#!/usr/bin/env python3
"""KTMGuard Dashboard - a local Flask web UI that wraps the ktmguard.py CLI.

This file does not reimplement any KTMGuard scanning/policy-generation/
verification logic. Every action shells out to `ktmguard.py` (or, for
Apply, `kubectl apply`) as a subprocess and either streams its raw output
or reads the same JSON/YAML files ktmguard.py already writes to
ktmguard-output/. A handful of read-only `kubectl get`/`kubectl config
view` calls are used directly for dashboard-only display purposes
(cluster address, TLS status, live pod/policy counts for the Overview and
Apply pages) - these are simple resource listings, not a reimplementation
of any scan/generate/apply/verify decision logic, which always stays in
ktmguard.py and is only ever read back from its own output files.

Gated behind a single shared password (see Part 1 below) - the trust
model is "same as running kubectl/ktmguard.py directly at a terminal,"
extended with a login step since the dashboard is reachable over the
network (including from inside a Docker container), not just localhost.
"""

import hmac
import json
import os
import secrets
import stat
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, send_file, session, url_for,
)

try:
    import markdown as markdown_lib
except ImportError:
    print("Error: the 'markdown' package is not installed.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("Error: the 'PyYAML' package is not installed.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent
KTMGUARD_PY = BASE_DIR / "ktmguard.py"
OUTPUT_DIR = BASE_DIR / "ktmguard-output"
STATE_DIR = OUTPUT_DIR / ".state"
REPORT_MD_PATH = OUTPUT_DIR / "report.md"
REPORT_HTML_PATH = OUTPUT_DIR / "report.html"
PASSWORD_FILE = BASE_DIR / ".dashboard_password"
SECRET_KEY_FILE = BASE_DIR / ".dashboard_secret_key"
GENERATED_YAML_FILES = ("deny-all.yaml", "allow-policies.yaml", "linkerd-auth-policy.yaml")

app = Flask(__name__)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# In-memory only, by design: the dashboard adds no persistent storage of its
# own beyond what ktmguard.py already writes to ktmguard-output/, plus its
# own auth files below. "Defaults to last used" holds for the lifetime of
# this process, not across restarts.
_last_namespace = "boutique"
_last_report_format = "markdown"

_lock = threading.Lock()
_job = {
    "action": None,
    "cmd": None,
    "lines": [],
    "running": False,
    "returncode": None,
}


# --------------------------------------------------------------------------
# Part 1 - Authentication
# --------------------------------------------------------------------------

def _write_secret_file(path, value):
    path.write_text(value)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600; best-effort, e.g. no-op on Windows
    except OSError:
        pass


def _load_or_create_password():
    """Precedence: KTMGUARD_DASHBOARD_PASSWORD env var, then the persisted
    .dashboard_password file, then a freshly generated one. Only the latter
    two get printed at startup - if the operator set the env var themselves
    they already know the value."""
    env_password = os.environ.get("KTMGUARD_DASHBOARD_PASSWORD")
    if env_password:
        return env_password, "environment variable", False

    if PASSWORD_FILE.exists():
        try:
            existing = PASSWORD_FILE.read_text().strip()
            if existing:
                return existing, str(PASSWORD_FILE), True
        except OSError:
            pass

    generated = secrets.token_urlsafe(18)
    _write_secret_file(PASSWORD_FILE, generated)
    return generated, str(PASSWORD_FILE), True


def _load_or_create_secret_key():
    if SECRET_KEY_FILE.exists():
        try:
            existing = SECRET_KEY_FILE.read_text().strip()
            if existing:
                return existing
        except OSError:
            pass
    key = secrets.token_hex(32)
    _write_secret_file(SECRET_KEY_FILE, key)
    return key


_current_password, _password_source, _print_password_at_startup = _load_or_create_password()
app.secret_key = _load_or_create_secret_key()

# Simple in-memory login-attempt throttle - not persisted, resets on
# restart. Enough to blunt casual online brute-forcing of the login form
# without adding a new dependency or any external service.
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60
_login_attempts = {}
_login_attempts_lock = threading.Lock()


def _is_locked_out(ip):
    now = time.time()
    with _login_attempts_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_WINDOW_SECONDS]
        _login_attempts[ip] = attempts
        return len(attempts) >= _LOGIN_MAX_ATTEMPTS


def _record_failed_attempt(ip):
    with _login_attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


@app.before_request
def _require_auth():
    if request.path.startswith("/static/"):
        return None
    if request.path == "/login":
        return None
    if session.get("authenticated"):
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "Unauthorized. Please log in again."}), 401
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _is_locked_out(ip):
            error = f"Too many failed attempts. Wait {_LOGIN_WINDOW_SECONDS} seconds and try again."
        else:
            submitted = request.form.get("password", "")
            if hmac.compare_digest(submitted.encode(), _current_password.encode()):
                session.clear()
                session["authenticated"] = True
                session.permanent = True
                return redirect(url_for("index"))
            _record_failed_attempt(ip)
            error = "Incorrect password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/change-password", methods=["POST"])
def change_password():
    global _current_password
    payload = request.get_json(silent=True) or {}
    current = payload.get("current_password") or ""
    new_password = (payload.get("new_password") or "").strip()

    if not hmac.compare_digest(current.encode(), _current_password.encode()):
        return jsonify({"error": "Current password is incorrect."}), 403
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 400

    try:
        _write_secret_file(PASSWORD_FILE, new_password)
    except OSError as exc:
        return jsonify({"error": f"Failed to persist new password: {exc}"}), 500

    _current_password = new_password
    return jsonify({"ok": True})


# --------------------------------------------------------------------------
# Job runner (unchanged architecture: background thread + SSE stream)
# --------------------------------------------------------------------------

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
# Cluster introspection (dashboard-only display helpers - simple read-only
# `kubectl` calls, not a reimplementation of ktmguard.py's own logic)
# --------------------------------------------------------------------------

def _kube_config_view():
    """Returns (server_address, insecure_skip_tls_verify) for the active
    kubeconfig context, or (None, False) if it can't be determined."""
    try:
        result = subprocess.run(
            ["kubectl", "config", "view", "--minify", "-o", "json"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None, False
        config = json.loads(result.stdout)
        clusters = config.get("clusters") or []
        cluster = clusters[0].get("cluster", {}) if clusters else {}
        server = cluster.get("server")
        insecure = bool(cluster.get("insecure-skip-tls-verify", False))
        return server, insecure
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, IndexError):
        return None, False


def _kubectl_get_json(*args, timeout=8):
    """Runs `kubectl get ... -o json` and returns the parsed items list, or
    None if the command failed (missing CRD, no access, cluster down, etc)
    - callers treat None as "unknown," distinct from an empty-but-successful
    list."""
    try:
        result = subprocess.run(
            ["kubectl", "get", *args, "-o", "json"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout).get("items", [])
    except ValueError:
        return None


def _count_generated_resources():
    counts = {"NetworkPolicy": 0, "AuthorizationPolicy": 0}
    for name in GENERATED_YAML_FILES:
        path = OUTPUT_DIR / name
        if not path.exists():
            continue
        try:
            docs = yaml.safe_load_all(path.read_text())
            for doc in docs:
                if not doc:
                    continue
                kind = doc.get("kind")
                if kind in counts:
                    counts[kind] += 1
        except yaml.YAMLError:
            pass
    return counts


def _count_yaml_docs(content):
    try:
        return sum(1 for doc in yaml.safe_load_all(content) if doc)
    except yaml.YAMLError:
        return 0


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template(
        "index.html",
        namespace=_last_namespace,
        password_source=_password_source,
    )


# --------------------------------------------------------------------------
# Cluster status (topbar dot, TLS warning strip, Settings page)
# --------------------------------------------------------------------------

@app.route("/api/cluster-info")
def cluster_info():
    server, insecure = _kube_config_view()
    try:
        result = subprocess.run(
            ["kubectl", "get", "nodes"], capture_output=True, text=True, timeout=5,
        )
        connected = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        connected = False
    return jsonify({
        "connected": connected,
        "server": server,
        "insecure_skip_tls_verify": insecure,
    })


@app.route("/api/test-connection", methods=["POST"])
def test_connection():
    try:
        result = subprocess.run(
            ["kubectl", "get", "nodes", "-o", "json"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({"ok": False, "error": str(exc)})
    if result.returncode != 0:
        return jsonify({"ok": False, "error": (result.stderr or "kubectl get nodes failed.").strip()})
    try:
        node_count = len(json.loads(result.stdout).get("items", []))
    except ValueError:
        node_count = None
    return jsonify({"ok": True, "node_count": node_count})


@app.route("/api/settings")
def settings_info():
    server, insecure = _kube_config_view()
    return jsonify({
        "server": server,
        "insecure_skip_tls_verify": insecure,
        "password_source": _password_source,
    })


# --------------------------------------------------------------------------
# Overview ("Am I safe?" landing page)
# --------------------------------------------------------------------------

@app.route("/api/overview")
def overview():
    namespace = (request.args.get("namespace") or _last_namespace).strip()

    service_map = _read_json(STATE_DIR / "service-map.json")
    verify_data = _read_json(STATE_DIR / "verify-results.json")

    services_found = len(service_map.get("services", [])) if service_map else 0
    edges_detected = len(service_map.get("edges", [])) if service_map else 0
    last_scan = service_map.get("generated_at") if service_map else None

    # "Protected target" = any service that appears as a destination in the
    # last scan's edges - that's exactly what `generate` creates a Server /
    # AuthorizationPolicy trio for. Cross-referencing against the live
    # AuthorizationPolicy names already applied (each named "<dst>-authz",
    # per ktmguard.py's build_linkerd_auth_policies) tells us which of those
    # targets are still unprotected, without recomputing anything - just a
    # UI-layer diff of two data sources ktmguard.py already produces.
    protected_targets = sorted({e["dst"] for e in (service_map.get("edges", []) if service_map else [])})

    applied_authz_names = set()
    authz_items = _kubectl_get_json("authorizationpolicy.policy.linkerd.io", "-n", namespace) if namespace else None
    if authz_items is not None:
        for item in authz_items:
            name = item.get("metadata", {}).get("name", "")
            if name.endswith("-authz"):
                applied_authz_names.add(name[: -len("-authz")])

    if authz_items is None:
        # kubectl itself failed (unreachable cluster, CRD not installed, no
        # access) - that's "couldn't check," not "confirmed unprotected."
        # Claiming every target is a gap here would be actively misleading,
        # so report nothing rather than a false positive; the cluster-status
        # dot in the topbar is what actually tells the operator why.
        gaps = []
    else:
        gaps = [
            {"service": dst, "reason": "No AuthorizationPolicy applied yet for this service."}
            for dst in protected_targets if dst not in applied_authz_names
        ]

    network_policies = verify_data.get("network_policies") if verify_data else None
    pod_injection = verify_data.get("pod_injection") if verify_data else None
    auth_policies = verify_data.get("auth_policies") if verify_data else None
    overall_ok = verify_data.get("overall_ok") if verify_data else None

    if not network_policies or network_policies.get("count", 0) == 0:
        status = "not-applied"
    elif overall_ok:
        status = "fully-applied"
    else:
        status = "partially-applied"

    protected_count = len(applied_authz_names & set(protected_targets)) if protected_targets else 0

    return jsonify({
        "status": status,
        "namespace": namespace,
        "services_found": services_found,
        "edges_detected": edges_detected,
        "last_scan": last_scan,
        "pod_injection": pod_injection,
        "network_policies": network_policies,
        "auth_policies": auth_policies,
        "protected_count": protected_count,
        "total_targets": len(protected_targets),
        "gaps": gaps,
        "gap_check_available": authz_items is not None,
    })


# --------------------------------------------------------------------------
# Run / stream
# --------------------------------------------------------------------------

@app.route("/api/run/<action>", methods=["POST"])
def run_action(action):
    global _last_namespace, _last_report_format
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
        if payload.get("static"):
            cmd += ["--static"]
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
        report_format = payload.get("format") or "markdown"
        if report_format not in ("markdown", "html"):
            return jsonify({"error": "format must be 'markdown' or 'html'."}), 400
        _last_namespace = namespace
        _last_report_format = report_format
        output_path = REPORT_HTML_PATH if report_format == "html" else REPORT_MD_PATH
        cmd = _ktmguard_cmd(
            "report", "--namespace", namespace,
            "--format", report_format,
            "--output", str(output_path),
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
        "namespace": data.get("namespace"),
        "generated_at": data.get("generated_at"),
        "services": [s.get("name") for s in data.get("services", [])],
        "edges": data.get("edges", []),
        "manual_review_required": data.get("manual_review_required", False),
    })


@app.route("/api/generate-result")
def generate_result():
    files = {}
    rule_counts = {}
    for name in GENERATED_YAML_FILES:
        path = OUTPUT_DIR / name
        if path.exists():
            try:
                content = path.read_text()
                files[name] = content
                rule_counts[name] = _count_yaml_docs(content)
            except OSError:
                pass

    service_map = _read_json(STATE_DIR / "service-map.json")
    review_edges = []
    if service_map:
        for e in service_map.get("edges", []):
            if e.get("confidence") in ("unconfirmed", "observed-only"):
                review_edges.append({
                    "src": e.get("src"),
                    "dst": e.get("dst"),
                    "confidence": e.get("confidence"),
                })

    return jsonify({"files": files, "rule_counts": rule_counts, "review_edges": review_edges})


@app.route("/api/apply-preflight")
def apply_preflight():
    namespace = (request.args.get("namespace") or _last_namespace).strip()
    counts = _count_generated_resources()
    server, _insecure = _kube_config_view()
    files_exist = any((OUTPUT_DIR / n).exists() for n in GENERATED_YAML_FILES)
    return jsonify({
        "namespace": namespace,
        "network_policy_count": counts["NetworkPolicy"],
        "authorization_policy_count": counts["AuthorizationPolicy"],
        "server": server,
        "files_exist": files_exist,
    })


@app.route("/api/pod-health")
def pod_health():
    namespace = (request.args.get("namespace") or _last_namespace).strip()
    if not namespace:
        return jsonify({"error": "Namespace is required."}), 400

    items = _kubectl_get_json("pods", "-n", namespace)
    if items is None:
        return jsonify({"error": "Failed to list pods (kubectl get pods failed)."}), 500

    pods = []
    for item in items:
        name = item.get("metadata", {}).get("name", "?")
        spec = item.get("spec", {})
        status = item.get("status", {})
        # Native sidecars (Linkerd's proxy included, on Kubernetes 1.29+)
        # report status under initContainerStatuses, identified by
        # restartPolicy: Always on the initContainer's own spec - the same
        # field kubectl's own READY column reads to merge them into the
        # regular container count.
        sidecar_names = {
            c.get("name") for c in (spec.get("initContainers") or [])
            if c.get("restartPolicy") == "Always"
        }
        regular = status.get("containerStatuses") or []
        init_statuses = status.get("initContainerStatuses") or []
        sidecars = [c for c in init_statuses if c.get("name") in sidecar_names]
        statuses = regular + sidecars
        ready = sum(1 for c in statuses if c.get("ready"))
        total = len(statuses)
        phase = status.get("phase", "Unknown")
        pods.append({
            "name": name,
            "ready": ready,
            "total": total,
            "phase": phase,
            "healthy": total > 0 and ready == total and phase == "Running",
        })
    return jsonify({"pods": pods})


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
    if _last_report_format == "html":
        # report.html is already a complete, self-contained document (built
        # by _render_report_html in ktmguard.py) - handed back as-is for the
        # frontend to embed via an iframe, rather than re-parsed here.
        if not REPORT_HTML_PATH.exists():
            return jsonify({"available": False})
        try:
            html_document = REPORT_HTML_PATH.read_text()
        except OSError:
            return jsonify({"available": False})
        return jsonify({"available": True, "format": "html", "html_document": html_document})

    if not REPORT_MD_PATH.exists():
        return jsonify({"available": False})
    try:
        raw = REPORT_MD_PATH.read_text()
    except OSError:
        return jsonify({"available": False})
    html = markdown_lib.markdown(raw, extensions=["tables"])
    return jsonify({"available": True, "format": "markdown", "html": html})


@app.route("/api/report-download")
def report_download():
    path = REPORT_HTML_PATH if _last_report_format == "html" else REPORT_MD_PATH
    if not path.exists():
        return jsonify({"error": "No report has been generated yet."}), 404
    download_name = "report.html" if _last_report_format == "html" else "report.md"
    return send_file(str(path), as_attachment=True, download_name=download_name)


if __name__ == "__main__":
    if _print_password_at_startup:
        print("=" * 60)
        print("KTMGuard Dashboard")
        print(f"Password ({_password_source}): {_current_password}")
        print("=" * 60)
    else:
        print("KTMGuard Dashboard - password set via KTMGUARD_DASHBOARD_PASSWORD.")

    # Binds to all interfaces by default (needed for Docker's -p mapping to
    # reach it at all) now that every route is gated behind the password
    # above. Set KTMGUARD_DASHBOARD_HOST=127.0.0.1 to restrict to localhost
    # only, e.g. when deliberately relying on an SSH tunnel instead.
    host = os.environ.get("KTMGUARD_DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("KTMGUARD_DASHBOARD_PORT", "5000"))
    app.run(host=host, port=port, threaded=True)
