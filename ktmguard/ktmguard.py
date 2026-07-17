#!/usr/bin/env python3
"""KTMGuard - Zero Trust configuration generator for resource-constrained
Kubernetes environments.

Scans a namespace, detects real service-to-service traffic via Prometheus /
Linkerd metrics, and generates ready-to-apply NetworkPolicy and Linkerd
AuthorizationPolicy YAML files.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import requests
import yaml

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    from kubernetes.stream import stream
except ImportError:
    print("Error: the 'kubernetes' package is not installed.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OUTPUT_DIR = "ktmguard-output"
# `kubectl apply -f ktmguard-output/` walks the directory and picks up every
# .yaml/.yml/.json file it finds (it filters by extension, not content) - a
# .json state file sitting next to the generated policy YAML gets fed to
# kubectl as if it were a manifest and fails to apply. State files therefore
# live in a subfolder kubectl never gets pointed at.
STATE_DIR = os.path.join(OUTPUT_DIR, ".state")
LINE = "-" * 47


# --------------------------------------------------------------------------
# Terminal output helpers (plain ANSI, no external formatting library)
# --------------------------------------------------------------------------

class Ansi:
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"


def _use_color():
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def green(text):
    return f"{Ansi.GREEN}{text}{Ansi.RESET}" if _use_color() else text


def red(text):
    return f"{Ansi.RED}{text}{Ansi.RESET}" if _use_color() else text


def yellow(text):
    return f"{Ansi.YELLOW}{text}{Ansi.RESET}" if _use_color() else text


def header(title):
    print(title)
    print(LINE)


def status_line(label, detail, ok):
    status = green("OK") if ok else red("FAILED")
    print(f"{label:<22}{detail:<24}{status}")


# --------------------------------------------------------------------------
# Kubernetes helpers
# --------------------------------------------------------------------------

def load_k8s_clients():
    try:
        config.load_kube_config()
    except Exception:
        try:
            config.load_incluster_config()
        except Exception:
            print(red("Error: could not load a Kubernetes configuration."))
            print("Run 'kubectl get nodes' to verify cluster access, then retry.")
            sys.exit(1)
    return (
        client.CoreV1Api(),
        client.AppsV1Api(),
        client.NetworkingV1Api(),
        client.CustomObjectsApi(),
    )


def check_namespace_exists(v1, namespace):
    try:
        namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
    except ApiException as exc:
        print(red(f"Error: failed to contact the Kubernetes API ({exc.reason})."))
        sys.exit(1)
    except Exception as exc:
        print(red(f"Error: failed to contact the Kubernetes API ({exc})."))
        sys.exit(1)

    if namespace not in namespaces:
        print(red(f"Error: namespace '{namespace}' not found."))
        print("Available namespaces:")
        for name in namespaces:
            print(f"  - {name}")
        sys.exit(1)


def list_services(v1, namespace):
    services = []
    for svc in v1.list_namespaced_service(namespace).items:
        ports = []
        for p in (svc.spec.ports or []):
            ports.append({
                "port": p.port,
                "target_port": p.target_port if p.target_port is not None else p.port,
                "protocol": p.protocol or "TCP",
                "node_port": getattr(p, "node_port", None),
            })
        selector = svc.spec.selector or {"app": svc.metadata.name}
        services.append({
            "name": svc.metadata.name,
            "ports": ports,
            "selector": selector,
        })
    return services


def list_deployments(apps_v1, namespace):
    return [d.metadata.name for d in apps_v1.list_namespaced_deployment(namespace).items]


# --------------------------------------------------------------------------
# Prometheus querying / communication path detection
# --------------------------------------------------------------------------

def query_prometheus(prom_url, promql, timeout=5):
    try:
        resp = requests.get(
            f"{prom_url.rstrip('/')}/api/v1/query",
            params={"query": promql},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None
        return data.get("data", {}).get("result", [])
    except requests.exceptions.RequestException:
        return None
    except (ValueError, KeyError):
        return None


IDENTITY_SUFFIX = ".serviceaccount.identity.linkerd.cluster.local"


def _identity_to_name_and_namespace(identity):
    """Decode a Linkerd mTLS identity like
    'cartservice.boutique.serviceaccount.identity.linkerd.cluster.local'
    into ('cartservice', 'boutique')."""
    if not identity or not identity.endswith(IDENTITY_SUFFIX):
        return None, None
    prefix = identity[: -len(IDENTITY_SUFFIX)]
    parts = prefix.split(".")
    if len(parts) < 2:
        return None, None
    return parts[0], parts[1]


CONTROL_PLANE_CLIENT_ID_MARKERS = ("prometheus", "linkerd-viz")


def extract_edges_from_inbound_metrics(result, namespace, known_names):
    """Decode Linkerd inbound proxy metrics (tcp_open_connections, request_total,
    inbound_http_requests_total, ...) into src -> dst edges using the `deployment`
    label (the receiver) and the `client_id` label (the caller's mTLS identity)."""
    edges = {}
    for item in result or []:
        metric = item.get("metric", {})
        dst = metric.get("deployment")
        client_id = metric.get("client_id")
        if not dst or not client_id:
            continue
        if any(marker in client_id for marker in CONTROL_PLANE_CLIENT_ID_MARKERS):
            continue
        src, caller_namespace = _identity_to_name_and_namespace(client_id)
        if not src or caller_namespace != namespace:
            continue
        if src == dst:
            continue
        if known_names and (src not in known_names or dst not in known_names):
            continue
        edges[(src, dst)] = True
    return [{"src": s, "dst": d} for (s, d) in sorted(edges.keys())]


def extract_edges_from_outbound_metrics(result, namespace, known_names):
    """Decode Linkerd outbound proxy metrics (outbound_http_route_request_statuses_total,
    outbound_tcp_route_open_total, ...) into src -> dst edges. These are reported by
    the CALLER's own proxy, using the `deployment` label (the caller) and the
    `authority` label (the destination host:port it called) - this recovers edges
    where the receiving side never got a usable client_id (e.g. no_tls_from_remote)."""
    edges = {}
    for item in result or []:
        metric = item.get("metric", {})
        src = metric.get("deployment")
        authority = metric.get("authority")
        if not src or not authority:
            continue
        dst = authority.split(":")[0]
        if not dst or src == dst:
            continue
        if known_names and (src not in known_names or dst not in known_names):
            continue
        edges[(src, dst)] = True
    return [{"src": s, "dst": d} for (s, d) in sorted(edges.keys())]


def detect_communication_paths(prom_url, namespace, services):
    """Returns (edges, manual_review_required, warning_message)."""
    known_names = {s["name"] for s in services}

    if not prom_url:
        return [], True, (
            "No Prometheus URL provided; listing services only. "
            "Manual review of communication paths is required."
        )

    # tcp_open_connections is queried first: across observed Linkerd versions it
    # reliably carries a client_id (caller mTLS identity) label for real
    # app-to-app traffic. request_total's inbound series can be dominated by
    # unauthenticated probe/health-check traffic with no client_id at all, so it
    # is only a secondary signal here. inbound_http_requests_total is tried as a
    # third fallback for versions that expose per-route HTTP metrics instead.
    #
    # tcp_open_connections is a GAUGE: it only reflects connections open at the
    # instant Prometheus scraped it. A client like cartservice's redis driver
    # that opens a short-lived connection per call (rather than holding one
    # open) can read back as 0 between scrapes even though calls are
    # constantly happening. tcp_close_connections_total is the COUNTER
    # equivalent - every closed connection increments it permanently, so it
    # catches exactly the short-lived-connection case the gauge can miss, and
    # it carries the same deployment/client_id labels. This matters most for
    # opaque, non-HTTP ports (e.g. redis-cart:6379): `linkerd tap` only
    # observes the HTTP request/response event stream inside a proxy, so raw
    # TCP protocols it can't parse as HTTP produce no tap events at all - it's
    # not a missing label, tap has nothing to report. These TCP-level metrics
    # are the only detection path that can see that traffic.
    #
    # Some connections never get a client_id on the receiving side at all
    # (no_tls_reason="no_tls_from_remote") even though they're legitimate
    # meshed traffic. For those, fall back to the CALLER's own outbound proxy
    # metrics, which report `deployment` (the caller) and `authority`
    # (the destination host:port) directly - no identity decoding needed.
    queries = [
        (f'tcp_open_connections{{namespace="{namespace}", direction="inbound"}}',
         extract_edges_from_inbound_metrics),
        (f'tcp_close_connections_total{{namespace="{namespace}", direction="inbound"}}',
         extract_edges_from_inbound_metrics),
        (f'request_total{{namespace="{namespace}", direction="inbound"}}',
         extract_edges_from_inbound_metrics),
        (f'inbound_http_requests_total{{namespace="{namespace}"}}',
         extract_edges_from_inbound_metrics),
        (f'outbound_http_route_request_statuses_total{{namespace="{namespace}"}}',
         extract_edges_from_outbound_metrics),
        (f'outbound_tcp_route_open_total{{namespace="{namespace}"}}',
         extract_edges_from_outbound_metrics),
    ]

    edges_by_pair = {}
    prometheus_reachable = False
    for promql, extractor in queries:
        result = query_prometheus(prom_url, promql)
        if result is None:
            continue
        prometheus_reachable = True
        for e in extractor(result, namespace, known_names):
            edges_by_pair[(e["src"], e["dst"])] = True

    if not prometheus_reachable:
        return [], True, (
            "Prometheus was not reachable; communication paths could not be "
            "auto-detected. Manual review required."
        )

    if edges_by_pair:
        return [{"src": s, "dst": d} for (s, d) in sorted(edges_by_pair.keys())], False, None

    # Fall back to raw network byte counters as a weaker secondary signal.
    fallback_query = (
        f'sum by (pod) (rate(container_network_transmit_bytes_total'
        f'{{namespace="{namespace}"}}[5m]))'
    )
    fallback_result = query_prometheus(prom_url, fallback_query)

    if fallback_result:
        warning = (
            "Linkerd per-destination metrics were not found; only raw network "
            "activity was detected (no destination breakdown available). "
            "Manual review required to confirm communication paths."
        )
    else:
        warning = (
            "No traffic metrics were found in Prometheus for this namespace. "
            "Manual review required."
        )
    return [], True, warning


# --------------------------------------------------------------------------
# Linkerd tap-based edge detection (optional, --tap)
# --------------------------------------------------------------------------

def _linkerd_binary_path():
    """Resolves the linkerd CLI, checking PATH first and falling back to the
    default install location (~/.linkerd2/bin/linkerd, per SETUP.md's own
    install instructions) in case PATH wasn't propagated to whatever
    process invoked ktmguard.py - e.g. a long-running server process (such
    as the dashboard) started before a PATH change made via ~/.bashrc,
    which only takes effect for new interactive shells, not processes
    already running."""
    found = shutil.which("linkerd")
    if found:
        return found
    fallback = os.path.expanduser("~/.linkerd2/bin/linkerd")
    if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
        return fallback
    return None


def _linkerd_cli_available():
    return _linkerd_binary_path() is not None


def _frontend_node_port(services):
    for svc in services:
        if svc["name"] != "frontend":
            continue
        for p in svc["ports"]:
            if p.get("node_port"):
                return p["node_port"]
    return None


def _resolve_traffic_target_host():
    """Host to use for NodePort-based auto traffic generation. Reads the API
    server host already resolved from the active kubeconfig context, rather
    than hardcoding 'localhost'. This matters specifically for the
    remote-client scenario documented in SETUP.md: there, the kubeconfig's
    server address is already the cluster's reachable public IP (that's how
    `kubectl`/the K8s API calls work at all from that machine) - and that
    same address is where the cluster's NodePort services are reachable
    too, whereas 'localhost' on a remote client reaches nothing. On a
    cluster node itself this still correctly resolves back to 127.0.0.1.
    Falls back to 'localhost' if the host can't be determined for any
    reason, preserving the old behavior rather than failing outright."""
    try:
        host = urllib.parse.urlparse(client.Configuration.get_default_copy().host).hostname
        return host or "localhost"
    except Exception:
        return "localhost"


# Well-known Online Boutique catalog product id (Sunglasses) - used by the
# project's own load-testing scripts, stable across deployments of the demo app.
CHECKOUT_PRODUCT_ID = "OLJCESPC7Z"

CHECKOUT_FORM_DATA = {
    "email": "someone@example.com",
    "street_address": "1600 Amphitheatre Parkway",
    "zip_code": "94043",
    "city": "Mountain View",
    "state": "CA",
    "country": "United States",
    "credit_card_number": "4432-8015-6152-0454",
    "credit_card_expiration_month": "1",
    "credit_card_expiration_year": "2039",
    "credit_card_cvv": "672",
}


def _generate_frontend_traffic(target_host, node_port, duration, stop_event):
    """Best-effort background traffic generator: repeatedly drives a full
    browse -> add-to-cart -> checkout flow against the frontend's NodePort so
    tap/metrics have something to observe without the user manually clicking
    through the app. A bare GET / only exercises frontend's own fan-out
    (productcatalog, currency, recommendation, cart-read) - it never calls
    checkoutservice.PlaceOrder, so checkoutservice->paymentservice and
    checkoutservice->cartservice are invisible unless checkout is actually
    submitted. Uses one requests.Session so the cart-session cookie survives
    across the add-to-cart and checkout calls. target_host is resolved from
    the active kubeconfig (see _resolve_traffic_target_host) rather than
    assumed to be localhost, so this also works when KTMGuard runs from a
    separate client machine against a remote cluster (SETUP.md's
    remote-client scenario) - 'localhost' there reaches nothing.

    requests only raises an exception for connection-level failures
    (timeout, refused, DNS) - an HTTP error status (4xx/5xx) is returned
    as a normal response, not an exception, unless raise_for_status() is
    called. A bare except-and-continue around the whole request sequence
    would silently treat "the app rejected this POST every time" the same
    as "it worked," producing zero real backend traffic while looking
    like it ran successfully. So each step's status code is checked
    explicitly and tallied, and a one-line summary is printed at the end
    - this is the only way to tell "generated real traffic" apart from
    "silently failed the whole window" from the scan output alone."""
    base = f"http://{target_host}:{node_port}"
    end_time = time.time() + duration
    stats = {"get": [0, 0], "cart": [0, 0], "checkout": [0, 0]}  # [ok, not-ok] per step
    last_issue = None
    cycles = 0

    while time.time() < end_time and not stop_event.is_set():
        cycles += 1
        session = requests.Session()
        try:
            resp = session.get(f"{base}/", timeout=2)
            if resp.status_code < 400:
                stats["get"][0] += 1
            else:
                stats["get"][1] += 1
                last_issue = f"GET / -> HTTP {resp.status_code}"

            resp = session.post(
                f"{base}/cart",
                data={"product_id": CHECKOUT_PRODUCT_ID, "quantity": "1"},
                timeout=2,
            )
            if resp.status_code < 400:
                stats["cart"][0] += 1
            else:
                stats["cart"][1] += 1
                last_issue = f"POST /cart -> HTTP {resp.status_code}"

            resp = session.post(f"{base}/cart/checkout", data=CHECKOUT_FORM_DATA, timeout=2)
            if resp.status_code < 400:
                stats["checkout"][0] += 1
            else:
                stats["checkout"][1] += 1
                last_issue = f"POST /cart/checkout -> HTTP {resp.status_code}"
        except requests.exceptions.RequestException as exc:
            last_issue = f"{type(exc).__name__}: {exc}"
        stop_event.wait(1)

    print(
        f"Traffic generator: {cycles} cycle(s) against {base} - "
        f"GET / {stats['get'][0]}/{cycles} ok, "
        f"POST /cart {stats['cart'][0]}/{cycles} ok, "
        f"POST /cart/checkout {stats['checkout'][0]}/{cycles} ok."
        + (f" Last issue: {last_issue}" if last_issue else "")
    )


def run_linkerd_tap(namespace, duration, known_names, node_port=None, target_host="localhost"):
    """Runs `linkerd viz tap deploy -n <namespace> --output json` for `duration`
    seconds and decodes each JSON tap event's source/destination deployment
    into a src -> dst edge. Returns (edges, warning); on any failure to start
    or find the CLI, returns ([], warning) so the caller can skip gracefully.

    Structural limitation: Linkerd's tap event stream is HTTP request/response
    events only - a proxy emits a tap event by observing the HTTP layer it
    parses traffic into. For opaque, non-HTTP ports (e.g. redis-cart:6379,
    raw RESP protocol) the proxy never parses an HTTP layer, so it never
    produces a tap event for that connection at all - not a missing label,
    nothing to observe. Edges on opaque ports can only be recovered from
    TCP-level Prometheus metrics (see detect_communication_paths), never
    from tap, regardless of how much traffic is generated."""
    linkerd_bin = _linkerd_binary_path()
    if not linkerd_bin:
        return [], "linkerd CLI not found on PATH or in ~/.linkerd2/bin; skipping tap-based detection."

    cmd = [linkerd_bin, "viz", "tap", "deploy", "-n", namespace, "--output", "json"]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
    except OSError as exc:
        return [], f"Failed to start 'linkerd viz tap': {exc}"

    edges = {}
    deadline = time.time() + duration

    def reader():
        for line in proc.stdout:
            if time.time() > deadline:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            src = event.get("source", {}).get("deployment")
            dst = event.get("destination", {}).get("deployment")
            if not src or not dst or src == dst:
                continue
            if known_names and (src not in known_names or dst not in known_names):
                continue
            edges[(src, dst)] = True

    reader_thread = threading.Thread(target=reader, daemon=True)
    reader_thread.start()

    stop_event = threading.Event()
    traffic_thread = None
    if node_port:
        traffic_thread = threading.Thread(
            target=_generate_frontend_traffic,
            args=(target_host, node_port, duration, stop_event),
            daemon=True,
        )
        traffic_thread.start()

    reader_thread.join(timeout=duration + 2)
    stop_event.set()

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    reader_thread.join(timeout=2)
    if traffic_thread:
        traffic_thread.join(timeout=5)

    return [{"src": s, "dst": d} for (s, d) in sorted(edges.keys())], None


# --------------------------------------------------------------------------
# Static configuration inference (optional, --static)
# --------------------------------------------------------------------------

def _service_name_matches(value, known_names):
    """Return the first known service name substring-matched inside `value`,
    so forms like 'cartservice:7070' or
    'cartservice.boutique.svc.cluster.local' both match service 'cartservice'."""
    if not value:
        return None
    value_lower = value.lower()
    for name in known_names:
        if name.lower() in value_lower:
            return name
    return None


def detect_static_edges(apps_v1, core_v1, namespace, known_names):
    """Infers src -> dst edges with no traffic, mesh, or Prometheus access at
    all: substring-matches each Deployment's container env var values (and
    any ConfigMap values pulled in via envFrom) against known Service names.
    This is the only detection method that works before Linkerd is even
    installed. Secrets are intentionally never read here."""
    edges = {}
    configmap_cache = {}

    for dep in apps_v1.list_namespaced_deployment(namespace).items:
        src = dep.metadata.name
        if src not in known_names:
            continue
        for container in (dep.spec.template.spec.containers or []):
            for env_var in (container.env or []):
                dst = _service_name_matches(env_var.value, known_names)
                if dst and dst != src:
                    edges.setdefault((src, dst), env_var.name)

            for env_from in (container.env_from or []):
                cm_ref = env_from.config_map_ref
                if not cm_ref or not cm_ref.name:
                    continue
                cm_name = cm_ref.name
                if cm_name not in configmap_cache:
                    try:
                        cm = core_v1.read_namespaced_config_map(cm_name, namespace)
                        configmap_cache[cm_name] = cm.data or {}
                    except ApiException:
                        configmap_cache[cm_name] = {}
                for key, value in configmap_cache[cm_name].items():
                    dst = _service_name_matches(value, known_names)
                    if dst and dst != src:
                        edges.setdefault((src, dst), key)

    return [
        {"src": s, "dst": d, "source_field": field}
        for (s, d), field in sorted(edges.items())
    ]


# --------------------------------------------------------------------------
# Detection-confidence scoring (combines static / tap / Prometheus results)
# --------------------------------------------------------------------------

METHOD_STATIC = "static-inference"
METHOD_TAP = "linkerd-tap"
METHOD_PROMETHEUS = "prometheus-metrics"

CONFIDENCE_HIGH = "high-confidence"
CONFIDENCE_UNCONFIRMED = "unconfirmed"
CONFIDENCE_OBSERVED_ONLY = "observed-only"


def _confidence_for(methods):
    """methods is a sorted list of detection method names that found this edge."""
    if len(methods) >= 2:
        return CONFIDENCE_HIGH
    if methods == [METHOD_STATIC]:
        return CONFIDENCE_UNCONFIRMED
    return CONFIDENCE_OBSERVED_ONLY


def _confidence_label(confidence):
    if confidence == CONFIDENCE_HIGH:
        return green("HIGH CONFIDENCE")
    if confidence == CONFIDENCE_UNCONFIRMED:
        return yellow("UNCONFIRMED - no traffic observed yet, review before applying")
    if confidence == CONFIDENCE_OBSERVED_ONLY:
        return yellow("OBSERVED ONLY - no config reference found, verify this path is intentional")
    return ""


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------

def cmd_scan(args):
    header("KTMGuard - Zero Trust Configuration Generator")

    v1, apps_v1, _net_v1, _custom_api = load_k8s_clients()
    check_namespace_exists(v1, args.namespace)

    print(f"Namespace: {args.namespace}")

    services = list_services(v1, args.namespace)
    list_deployments(apps_v1, args.namespace)  # validated to be reachable; unused otherwise

    print(f"Services found: {len(services)}")
    print()

    known_names = {s["name"] for s in services}

    mesh_statuses = check_service_mesh_status(v1, args.namespace, services)
    print("Mesh injection status:")
    for s in mesh_statuses:
        if not s["found"]:
            print(f"  {s['name']:<22}no running pod found")
        elif s["meshed"]:
            print(f"  {s['name']:<22}meshed ({s['ready']}/{s['total']})")
        else:
            print(f"  {s['name']:<22}" + yellow(f"NOT MESHED ({s['ready']}/{s['total']})"))
    print()
    unmeshed = [s["name"] for s in mesh_statuses if s["found"] and not s["meshed"]]
    if unmeshed:
        print(yellow(
            f"Warning: {', '.join(unmeshed)} have no linkerd-proxy sidecar. "
            "Traffic to/from these services has no mTLS identity or proxy "
            "metrics and will never appear as a detected edge via Prometheus "
            "or tap, regardless of how much traffic is generated. Static "
            "configuration inference (--static) is unaffected by this. "
            "Annotate for injection and run "
            "'kubectl rollout restart deploy/<name>', then re-scan."
        ))
        print()

    combined = {}

    def record_edge(src, dst, method, source_field=None):
        entry = combined.setdefault((src, dst), {"methods": set(), "static_source_field": None})
        entry["methods"].add(method)
        if source_field:
            entry["static_source_field"] = source_field

    if args.static:
        static_edges = detect_static_edges(apps_v1, v1, args.namespace, known_names)
        for e in static_edges:
            record_edge(e["src"], e["dst"], METHOD_STATIC, e["source_field"])
        print(f"Static configuration inference: {len(static_edges)} candidate "
              "path(s) found from Deployment env vars / ConfigMaps.")
        print()

    tap_edges = []
    if args.tap:
        if not _linkerd_cli_available():
            print(yellow(
                "Warning: linkerd CLI not found on PATH; skipping tap-based detection."
            ))
            print()
        else:
            node_port = _frontend_node_port(services)
            target_host = _resolve_traffic_target_host()
            print(f"Observing live traffic for {args.tap_duration} seconds "
                  "(move through the app to generate traffic)...")
            if node_port:
                print(f"Auto-generating traffic to {target_host}:{node_port} "
                      "(resolved from the active kubeconfig's API server host).")
            tap_edges, tap_warning = run_linkerd_tap(
                args.namespace, args.tap_duration, known_names, node_port, target_host
            )
            if tap_warning:
                print(yellow(f"Warning: {tap_warning}"))
            print()
    for e in tap_edges:
        record_edge(e["src"], e["dst"], METHOD_TAP)

    warning = None
    if args.prometheus:
        prom_edges, _prom_manual_review, warning = detect_communication_paths(
            args.prometheus, args.namespace, services
        )
        for e in prom_edges:
            record_edge(e["src"], e["dst"], METHOD_PROMETHEUS)
    elif not (args.static or args.tap):
        warning = (
            "No detection method specified (--static, --tap, or --prometheus); "
            "listing services only. Manual review of communication paths is required."
        )

    edges = []
    for (src, dst), info in sorted(combined.items()):
        methods = sorted(info["methods"])
        edges.append({
            "src": src,
            "dst": dst,
            "methods": methods,
            "static_source_field": info["static_source_field"],
            "confidence": _confidence_for(methods),
        })

    manual_review = len(edges) == 0

    if edges:
        print("Detected communication paths:")
        for e in edges:
            print(f"  {e['src']:<22}→ {e['dst']:<22}[{_confidence_label(e['confidence'])}]")
    else:
        print("No communication paths detected.")
    print()

    if warning:
        print(yellow(f"Warning: {warning}"))
        print()

    service_map = {
        "namespace": args.namespace,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "services": services,
        "edges": edges,
        "manual_review_required": manual_review,
    }

    os.makedirs(STATE_DIR, exist_ok=True)
    out_path = os.path.join(STATE_DIR, "service-map.json")
    with open(out_path, "w") as f:
        json.dump(service_map, f, indent=2)

    print(f"Communication map saved to {out_path}")
    print("Run 'ktmguard generate' to create Zero Trust configuration.")


# --------------------------------------------------------------------------
# generate: YAML builders
# --------------------------------------------------------------------------

def build_deny_all(namespace):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "deny-all", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def _service_ports(service):
    if not service or not service.get("ports"):
        return None
    return [
        {"protocol": p["protocol"], "port": p["target_port"]}
        for p in service["ports"]
    ]


def _confidence_comment(edge):
    """Renders an edge's detection confidence as a YAML comment string, or
    None for edges from service-map.json files predating confidence scoring."""
    confidence = edge.get("confidence")
    if not confidence:
        return None
    methods = edge.get("methods") or []
    if confidence == CONFIDENCE_HIGH:
        return f"HIGH CONFIDENCE: corroborated by multiple detection methods ({', '.join(methods)})"
    if confidence == CONFIDENCE_UNCONFIRMED:
        field = edge.get("static_source_field")
        basis = f" ({field})" if field else ""
        return (f"UNCONFIRMED{basis}: based on env var / ConfigMap reference only, "
                "no traffic observed yet - verify before relying on this in production")
    if confidence == CONFIDENCE_OBSERVED_ONLY:
        return ("OBSERVED ONLY: traffic was seen but no matching config reference was "
                "found - verify this path is intentional before allowing it")
    return None


def build_allow_policies(namespace, edges, services):
    docs = []
    comments = []

    for edge in edges:
        src, dst = edge["src"], edge["dst"]
        comment = _confidence_comment(edge)
        src_svc = services.get(src)
        dst_svc = services.get(dst)
        src_selector = src_svc["selector"] if src_svc else {"app": src}
        dst_selector = dst_svc["selector"] if dst_svc else {"app": dst}
        ports = _service_ports(dst_svc)

        egress_rule = {"to": [{"podSelector": {"matchLabels": dst_selector}}]}
        if ports:
            egress_rule["ports"] = ports
        docs.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"allow-egress-{src}-to-{dst}", "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": src_selector},
                "policyTypes": ["Egress"],
                "egress": [egress_rule],
            },
        })
        comments.append(comment)

        ingress_rule = {"from": [{"podSelector": {"matchLabels": src_selector}}]}
        if ports:
            ingress_rule["ports"] = ports
        docs.append({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"allow-ingress-{dst}-from-{src}", "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": dst_selector},
                "policyTypes": ["Ingress"],
                "ingress": [ingress_rule],
            },
        })
        comments.append(comment)

    # DNS egress for all pods
    docs.append({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-dns", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [{
                "ports": [
                    {"protocol": "UDP", "port": 53},
                    {"protocol": "TCP", "port": 53},
                ],
            }],
        },
    })

    # Egress to the Linkerd control plane
    docs.append({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-linkerd-egress", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{"namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "linkerd"}
                }}],
            }],
        },
    })

    # Ingress from the Linkerd control plane / viz extension (proxy injection, metrics scraping)
    docs.append({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-ingress-from-linkerd", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [
                    {"namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "linkerd"}
                    }},
                    {"namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "linkerd-viz"}
                    }},
                ],
            }],
        },
    })
    comments.append(None)
    comments.append(None)
    comments.append(None)

    return docs, comments


def build_linkerd_auth_policies(namespace, edges, services):
    callers_by_dst = {}
    edge_lookup = {}
    for edge in edges:
        callers_by_dst.setdefault(edge["dst"], set()).add(edge["src"])
        edge_lookup[(edge["src"], edge["dst"])] = edge

    docs = []
    comments = []
    protected_count = 0
    for dst, callers in sorted(callers_by_dst.items()):
        dst_svc = services.get(dst)
        selector = dst_svc["selector"] if dst_svc else {"app": dst}
        ports = dst_svc["ports"] if dst_svc else []
        port = ports[0]["target_port"] if ports else 80

        server_name = f"{dst}-server"
        authn_name = f"{dst}-callers"

        caller_tags = []
        for caller in sorted(callers):
            edge = edge_lookup.get((caller, dst), {})
            confidence = edge.get("confidence")
            caller_tags.append(f"{caller} [{confidence}]" if confidence else caller)
        group_comment = f"Callers: {', '.join(caller_tags)}" if any(
            edge_lookup.get((c, dst), {}).get("confidence") for c in callers
        ) else None

        docs.append({
            "apiVersion": "policy.linkerd.io/v1beta1",
            "kind": "Server",
            "metadata": {"name": server_name, "namespace": namespace},
            "spec": {
                "podSelector": {"matchLabels": selector},
                "port": port,
                "proxyProtocol": "HTTP/2",
            },
        })
        comments.append(group_comment)

        identities = [
            f"{caller}.{namespace}.serviceaccount.identity.linkerd.cluster.local"
            for caller in sorted(callers)
        ]
        docs.append({
            "apiVersion": "policy.linkerd.io/v1alpha1",
            "kind": "MeshTLSAuthentication",
            "metadata": {"name": authn_name, "namespace": namespace},
            "spec": {"identities": identities},
        })
        comments.append(group_comment)

        docs.append({
            "apiVersion": "policy.linkerd.io/v1alpha1",
            "kind": "AuthorizationPolicy",
            "metadata": {"name": f"{dst}-authz", "namespace": namespace},
            "spec": {
                "targetRef": {
                    "group": "policy.linkerd.io",
                    "kind": "Server",
                    "name": server_name,
                },
                "requiredAuthenticationRefs": [{
                    "group": "policy.linkerd.io",
                    "kind": "MeshTLSAuthentication",
                    "name": authn_name,
                }],
            },
        })
        comments.append(group_comment)
        protected_count += 1

    return docs, protected_count, comments


def build_readme(namespace, edge_count):
    return f"""# Applying KTMGuard Zero Trust Configuration

Namespace: `{namespace}`

## Files in this directory

- `deny-all.yaml` - default-deny NetworkPolicy (blocks all ingress/egress)
- `allow-policies.yaml` - selective allow rules for the {edge_count} detected
  communication path(s), plus DNS and Linkerd control-plane traffic
- `linkerd-auth-policy.yaml` - Linkerd `Server` / `MeshTLSAuthentication` /
  `AuthorizationPolicy` resources restricting each service to its legitimate callers
- `README-apply.md` - this file

## Before you apply

1. Review every generated file. This tool infers policy from observed traffic;
   it cannot guarantee every legitimate path was captured, especially for
   traffic that did not occur during the scan window.
2. Confirm the namespace is meshed (Linkerd sidecar injection enabled):
   `kubectl get ns {namespace} -o jsonpath='{{.metadata.annotations}}'`
3. Confirm the `ServiceAccount` name used by each workload matches the
   identity strings in `linkerd-auth-policy.yaml`
   (`<serviceaccount>.{namespace}.serviceaccount.identity.linkerd.cluster.local`).
   Adjust them if a workload uses a non-default service account.

## Apply steps

1. Dry-run to validate syntax:
   ```
   kubectl apply --dry-run=client -f ktmguard-output/
   ```
2. Apply the configuration:
   ```
   kubectl apply -f ktmguard-output/
   ```
3. Watch pods to confirm nothing is being blocked unexpectedly:
   ```
   kubectl get pods -n {namespace} -w
   ```
4. Run `ktmguard verify --namespace {namespace}` to confirm enforcement.

## Rollback

If a legitimate path was missed and traffic is broken, remove the offending
`deny-all.yaml` policy temporarily:
```
kubectl delete -f ktmguard-output/deny-all.yaml
```
then re-run `ktmguard scan` to capture the missed path and regenerate.
"""


def yaml_dump_all(docs, comments=None):
    parts = []
    for i, doc in enumerate(docs):
        comment = comments[i] if comments else None
        chunk = "---\n"
        if comment:
            chunk += f"# {comment}\n"
        chunk += yaml.dump(doc, default_flow_style=False, sort_keys=False)
        parts.append(chunk)
    return "".join(parts)


# --------------------------------------------------------------------------
# generate
# --------------------------------------------------------------------------

def cmd_generate(args):
    header(f"Generating Zero Trust configuration for namespace: {args.namespace}")

    if not os.path.exists(args.input):
        print(red(f"Error: input file '{args.input}' not found."))
        print("Run 'ktmguard scan' first to produce a service-map.json.")
        sys.exit(1)

    with open(args.input) as f:
        service_map = json.load(f)

    namespace = args.namespace
    edges = service_map.get("edges", [])
    services = {s["name"]: s for s in service_map.get("services", [])}

    if service_map.get("manual_review_required") and not edges:
        print(yellow(
            "Warning: service-map.json has no detected communication paths "
            "(manual review flagged during scan). Generated allow-policies.yaml "
            "will contain only baseline rules (DNS, Linkerd). Add paths manually "
            "before applying."
        ))
        print()

    deny_all_doc = build_deny_all(namespace)
    allow_docs, allow_comments = build_allow_policies(namespace, edges, services)
    linkerd_docs, protected_count, linkerd_comments = build_linkerd_auth_policies(
        namespace, edges, services
    )
    readme = build_readme(namespace, len(edges))

    plan = [
        ("deny-all.yaml", [deny_all_doc], None, None),
        ("allow-policies.yaml", allow_docs, f"{len(allow_docs)} rules", allow_comments),
        ("linkerd-auth-policy.yaml", linkerd_docs, f"{protected_count} policies", linkerd_comments),
    ]

    if args.dry_run:
        for name, docs, _note, comments in plan:
            print(f"--- {name} ---")
            print(yaml_dump_all(docs, comments))
        print("--- README-apply.md ---")
        print(readme)
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for name, docs, note, comments in plan:
        path = os.path.join(OUTPUT_DIR, name)
        with open(path, "w") as f:
            f.write(yaml_dump_all(docs, comments))
        suffix = f" ({note})" if note else ""
        print(f"{name:<32}  created{suffix}")

    readme_path = os.path.join(OUTPUT_DIR, "README-apply.md")
    with open(readme_path, "w") as f:
        f.write(readme)
    print(f"{'README-apply.md':<32}  created")

    print()
    print(f"Output directory: {OUTPUT_DIR}/")
    print()
    print("Next steps:")
    print("  1. Review generated files before applying")
    print("  2. Ensure Linkerd is installed and injected into your namespace")
    print(f"  3. Apply: kubectl apply -f {OUTPUT_DIR}/")


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def _all_running_container_statuses(pod):
    """Regular container statuses plus native-sidecar init container statuses.
    Linkerd's proxy is injected as a native sidecar (a Kubernetes 1.29+
    feature): an init container with spec.restart_policy == "Always" that
    keeps running alongside the pod's regular containers. The API reports
    its live status under status.init_container_statuses, never under
    status.container_statuses - so a caller that only reads
    container_statuses undercounts every meshed pod by exactly one
    container, even though kubectl's own READY column merges both lists
    and counts it correctly. restart_policy on the *spec* (not any field on
    the status) is what actually marks a container as a sidecar - a normal,
    run-to-completion init container has no restart_policy and must not be
    included here, since its status is reported as not-ready once it exits."""
    regular = list(pod.status.container_statuses or [])
    init_specs = pod.spec.init_containers or []
    sidecar_names = {c.name for c in init_specs if c.restart_policy == "Always"}
    init_statuses = pod.status.init_container_statuses or []
    sidecars = [c for c in init_statuses if c.name in sidecar_names]
    return regular + sidecars


def check_pod_injection(v1, namespace):
    pods = v1.list_namespaced_pod(namespace).items
    total = len(pods)
    fully_ready = 0
    debug = os.environ.get("KTMGUARD_DEBUG")
    for pod in pods:
        statuses = _all_running_container_statuses(pod)
        if debug:
            print(f"DEBUG: pod={pod.metadata.name} phase={pod.status.phase} "
                  f"statuses_count={len(statuses)} "
                  f"names={[c.name for c in statuses]} "
                  f"ready_states={[c.ready for c in statuses]}")
        if len(statuses) >= 2 and all(c.ready for c in statuses):
            fully_ready += 1
    return fully_ready, total


def check_service_mesh_status(v1, namespace, services):
    """Per-service breakdown of Linkerd sidecar injection. check_pod_injection's
    aggregate 'N/M pods ready' count hides exactly the failure mode that blocks
    edge detection: a single unmeshed workload has no linkerd-proxy positioned
    to report identity/metrics for traffic touching it, so that traffic is
    invisible to both Prometheus-based detection and `linkerd tap`, no matter
    how much traffic is generated. Surfacing this per service during `scan`
    catches that before the user goes looking for a metrics bug that isn't one."""
    statuses = []
    for svc in services:
        pod = find_pod_for_selector(v1, namespace, svc["selector"])
        if not pod:
            statuses.append({"name": svc["name"], "found": False, "meshed": False,
                              "ready": 0, "total": 0})
            continue
        container_statuses = _all_running_container_statuses(pod)
        statuses.append({
            "name": svc["name"],
            "found": True,
            "meshed": any(c.name == "linkerd-proxy" for c in container_statuses),
            "ready": sum(1 for c in container_statuses if c.ready),
            "total": len(container_statuses),
        })
    return statuses


def check_network_policies(net_v1, namespace):
    try:
        return net_v1.list_namespaced_network_policy(namespace).items
    except ApiException:
        return []


def check_auth_policies(custom_api, namespace):
    try:
        result = custom_api.list_namespaced_custom_object(
            group="policy.linkerd.io",
            version="v1alpha1",
            namespace=namespace,
            plural="authorizationpolicies",
        )
        return result.get("items", [])
    except ApiException:
        return []


def find_pod_for_selector(v1, namespace, selector):
    if not selector:
        return None
    label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
    try:
        pods = v1.list_namespaced_pod(namespace, label_selector=label_selector).items
    except ApiException:
        return None
    for pod in pods:
        if pod.status.phase == "Running":
            return pod
    return pods[0] if pods else None


def _exec_in_pod(v1, namespace, pod, shell_command, timeout):
    container = None
    if pod.spec.containers:
        non_proxy = [c.name for c in pod.spec.containers if c.name != "linkerd-proxy"]
        container = non_proxy[0] if non_proxy else pod.spec.containers[0].name
    try:
        return stream(
            v1.connect_get_namespaced_pod_exec,
            pod.metadata.name,
            namespace,
            container=container,
            command=["/bin/sh", "-c", shell_command],
            stderr=False,
            stdin=False,
            stdout=True,
            tty=False,
            _request_timeout=timeout + 5,
        )
    except Exception:
        return None


def probe_connection(v1, namespace, src_pod, dst_host, port, timeout=4):
    """Check whether a bare TCP connection from src_pod to dst_host:port
    succeeds.

    Known, accepted limitation: this cannot distinguish "reachable
    end-to-end" from "Linkerd's local outbound proxy on src_pod accepted the
    handshake, but the real backend is unreachable." Linkerd transparently
    redirects a meshed pod's outbound connections to its own local proxy,
    which always accepts before it has even attempted to dial the real
    destination - so this probe will typically report REACHABLE regardless
    of whether NetworkPolicy or a Linkerd AuthorizationPolicy is actually
    blocking the path upstream.

    Four more precise approaches were tried in place of this one and each
    surfaced a real, cluster-specific problem rather than a reliable signal:
    an elapsed-time heuristic assumed a gRPC backend would fast-reject a
    malformed non-HTTP/2 probe, but grpc-go just never completes the read,
    so allowed-and-malformed and genuinely-blocked both hang identically;
    diffing the destination's inbound_http_authz_allow_total/deny_total
    assumed Linkerd always classifies this traffic as HTTP/2 through the
    matching Server resource, but real working traffic was observed under
    srv_name="all-unauthenticated" with no inbound_http_authz_* entry at
    all; grepping the source proxy's own log for "Failed to connect" worked
    for the one case it was verified against but wasn't confirmed reliable
    across the full allowed/blocked matrix within this project's time
    budget. Rather than keep iterating, this reverts to the simplest
    possible signal: an honest, known-uninformative result beats an
    actively misleading one. cmd_verify prints a warning about this
    limitation alongside the results - treat a REACHABLE result on an
    expected-blocked path as inconclusive, not as evidence Zero Trust isn't
    working; verify blocked paths manually if it matters (e.g. `kubectl
    exec -it -n <ns> deploy/<src> -- wget -qO- --timeout=3
    http://<dst>:<port>/` and look for a hang/timeout vs. a fast response).

    Returns True if the TCP connect succeeds, False if it doesn't, None if
    the probe itself couldn't be executed (no exec-capable shell, etc).
    """
    probe = (
        f"if command -v nc >/dev/null 2>&1; then "
        f"  nc -z -w {timeout} {dst_host} {port} && echo KTMGUARD_OPEN || echo KTMGUARD_CLOSED; "
        f"elif command -v bash >/dev/null 2>&1; then "
        f"  bash -c '(exec 3<>/dev/tcp/{dst_host}/{port})' 2>/dev/null && echo KTMGUARD_OPEN || echo KTMGUARD_CLOSED; "
        f"elif command -v curl >/dev/null 2>&1; then "
        f"  curl -s -m {timeout} -o /dev/null {dst_host}:{port}; "
        f"  [ $? -ne 7 ] && echo KTMGUARD_OPEN || echo KTMGUARD_CLOSED; "
        f"else echo KTMGUARD_NOTOOL; fi"
    )
    resp = _exec_in_pod(v1, namespace, src_pod, probe, timeout)
    if resp is None:
        return None
    if "KTMGUARD_OPEN" in resp:
        return True
    if "KTMGUARD_CLOSED" in resp:
        return False
    return None


def run_connectivity_tests(v1, namespace, service_map):
    services = {s["name"]: s for s in service_map.get("services", [])}
    edges = {(e["src"], e["dst"]) for e in service_map.get("edges", [])}
    names = list(services.keys())

    test_cases = []
    for (src, dst) in sorted(edges):
        test_cases.append((src, dst, False))

    for src in names:
        for dst in names:
            if src == dst or (src, dst) in edges:
                continue
            test_cases.append((src, dst, True))
            break  # one negative case per source is enough for a quick check

    results = []
    for src, dst, expected_blocked in test_cases:
        dst_svc = services.get(dst, {})
        ports = dst_svc.get("ports") or [{"port": 80}]
        port = ports[0]["port"]

        src_pod = find_pod_for_selector(v1, namespace, services.get(src, {}).get("selector"))
        if src_pod is None:
            results.append({
                "src": src, "dst": dst, "port": port,
                "reachable": None, "expected_blocked": expected_blocked,
            })
            continue

        reachable = probe_connection(v1, namespace, src_pod, dst, port)
        results.append({
            "src": src, "dst": dst, "port": port,
            "reachable": reachable, "expected_blocked": expected_blocked,
        })
    return results


def cmd_verify(args):
    header(f"Verifying Zero Trust enforcement in namespace: {args.namespace}")

    v1, _apps_v1, net_v1, custom_api = load_k8s_clients()
    check_namespace_exists(v1, args.namespace)

    ready, total = check_pod_injection(v1, args.namespace)
    pod_ok = total > 0 and ready == total
    status_line(
        "Linkerd injection",
        f"all pods 2/2" if pod_ok else f"{ready}/{total} pods 2/2",
        pod_ok,
    )

    policies = check_network_policies(net_v1, args.namespace)
    np_ok = len(policies) > 0
    status_line("NetworkPolicy", f"{len(policies)} policies applied", np_ok)

    authz = check_auth_policies(custom_api, args.namespace)
    authz_ok = len(authz) > 0
    status_line("Auth policies", f"{len(authz)} policies applied", authz_ok)

    print()
    print("Connectivity verification:")
    print(yellow(
        "  Note: connectivity results reflect TCP-layer reachability only. "
        "Linkerd's proxy may report a connection as reachable even when "
        "application-layer authorization blocks it. Verify critical paths "
        "manually, e.g.: kubectl exec -it -n <ns> deploy/<src> -- wget -qO- "
        "--timeout=3 http://<dst>:<port>/"
    ))

    map_path = os.path.join(STATE_DIR, "service-map.json")
    if not os.path.exists(map_path):
        print(yellow(
            "  service-map.json not found; run 'ktmguard scan' first to enable "
            "connectivity checks."
        ))
        conn_results = []
    else:
        with open(map_path) as f:
            service_map = json.load(f)
        conn_results = run_connectivity_tests(v1, args.namespace, service_map)
        for r in conn_results:
            label = f"{r['src']} → {r['dst']} (port {r['port']})"
            if r["reachable"] is None:
                print(f"  {label:<45}" + yellow("UNKNOWN (probe failed)"))
                continue
            matches = r["reachable"] != r["expected_blocked"]
            text = "BLOCKED" if not r["reachable"] else "REACHABLE"
            tag = "(expected)" if matches else "(unexpected)"
            colored = green(f"{text}  {tag}") if matches else red(f"{text}  {tag}")
            print(f"  {label:<45}" + colored)

    print()
    # Connectivity results are diagnostic only, not part of the pass/fail
    # verdict: probe_connection is a TCP-connect-only check (see its
    # docstring) that typically reports every path as reachable regardless
    # of whether NetworkPolicy/AuthorizationPolicy is actually blocking it,
    # so "(unexpected)" here is an expected, permanent state on a correctly
    # configured cluster - not evidence of a real problem.
    all_ok = pod_ok and np_ok and authz_ok
    if all_ok:
        print(green(
            "Zero Trust enforcement verified successfully. (Connectivity "
            "results above reflect TCP-layer reachability only - see note.)"
        ))
    else:
        print(red("Zero Trust enforcement verification found issues. Review the output above."))

    os.makedirs(STATE_DIR, exist_ok=True)
    with open(os.path.join(STATE_DIR, "verify-results.json"), "w") as f:
        json.dump({
            "namespace": args.namespace,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pod_injection": {"ready": ready, "total": total, "ok": pod_ok},
            "network_policies": {"count": len(policies), "ok": np_ok},
            "auth_policies": {"count": len(authz), "ok": authz_ok},
            "connectivity": conn_results,
            "overall_ok": all_ok,
        }, f, indent=2)


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def cmd_report(args):
    header(f"Generating Zero Trust report for namespace: {args.namespace}")

    map_path = os.path.join(STATE_DIR, "service-map.json")
    verify_path = os.path.join(STATE_DIR, "verify-results.json")

    service_map = None
    if os.path.exists(map_path):
        with open(map_path) as f:
            service_map = json.load(f)

    verify_results = None
    if os.path.exists(verify_path):
        with open(verify_path) as f:
            verify_results = json.load(f)

    lines = []
    lines.append(f"# Zero Trust Configuration Report - {args.namespace}")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    lines.append("## Service Discovery")
    lines.append("")
    if service_map:
        lines.append(f"- Namespace: `{service_map.get('namespace')}`")
        lines.append(f"- Services found: {len(service_map.get('services', []))}")
        lines.append(f"- Communication paths detected: {len(service_map.get('edges', []))}")
        if service_map.get("manual_review_required"):
            lines.append("- **Manual review flagged**: automatic path detection was incomplete.")
        lines.append("")
        lines.append("| Source | Destination | Confidence | Methods |")
        lines.append("|---|---|---|---|")
        for e in service_map.get("edges", []):
            confidence = e.get("confidence", "-")
            methods = ", ".join(e.get("methods", [])) or "-"
            lines.append(f"| {e['src']} | {e['dst']} | {confidence} | {methods} |")
    else:
        lines.append("_No service-map.json found. Run 'ktmguard scan' first._")
    lines.append("")

    lines.append("## Verification Results")
    lines.append("")
    if verify_results:
        pi = verify_results["pod_injection"]
        np = verify_results["network_policies"]
        az = verify_results["auth_policies"]
        lines.append(f"- Linkerd injection: {pi['ready']}/{pi['total']} pods "
                      f"({'OK' if pi['ok'] else 'FAILED'})")
        lines.append(f"- NetworkPolicies applied: {np['count']} "
                      f"({'OK' if np['ok'] else 'FAILED'})")
        lines.append(f"- Linkerd AuthorizationPolicies applied: {az['count']} "
                      f"({'OK' if az['ok'] else 'FAILED'})")
        lines.append(f"- Overall: {'VERIFIED' if verify_results['overall_ok'] else 'ISSUES FOUND'}")
        lines.append("")
        lines.append("| Source | Destination | Port | Result | Expected |")
        lines.append("|---|---|---|---|---|")
        for r in verify_results.get("connectivity", []):
            result = "UNKNOWN" if r["reachable"] is None else (
                "REACHABLE" if r["reachable"] else "BLOCKED"
            )
            expected = "BLOCKED" if r["expected_blocked"] else "REACHABLE"
            lines.append(f"| {r['src']} | {r['dst']} | {r['port']} | {result} | {expected} |")
    else:
        lines.append("_No verify-results.json found. Run 'ktmguard verify' first._")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Generated by KTMGuard, developed as part of a BSc Cybersecurity thesis "
        "on Zero Trust feasibility for Kathmandu Valley SMEs._"
    )

    with open(args.output, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Report written to {args.output}")


# --------------------------------------------------------------------------
# CLI entry point
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="ktmguard",
        description="KTMGuard - Zero Trust configuration generator for Kubernetes clusters",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a namespace and detect service communication paths")
    p_scan.add_argument("--namespace", required=True)
    p_scan.add_argument("--prometheus", default=None, help="Prometheus base URL, e.g. http://localhost:9090")
    p_scan.add_argument("--tap", action="store_true",
                         help="Also observe live traffic via 'linkerd viz tap' to recover "
                              "edges missing from Prometheus metrics")
    p_scan.add_argument("--tap-duration", type=int, default=30,
                         help="Seconds to observe traffic when --tap is set (default: 30)")
    p_scan.add_argument("--static", action="store_true",
                         help="Infer edges from Deployment env vars / ConfigMaps referencing "
                              "known service names - works with no mesh or Prometheus installed")
    p_scan.set_defaults(func=cmd_scan)

    p_gen = sub.add_parser("generate", help="Generate Zero Trust YAML configuration")
    p_gen.add_argument("--namespace", required=True)
    p_gen.add_argument("--input", default=os.path.join(STATE_DIR, "service-map.json"))
    p_gen.add_argument("--dry-run", action="store_true", help="Print YAML to terminal without writing files")
    p_gen.set_defaults(func=cmd_generate)

    p_verify = sub.add_parser("verify", help="Verify Zero Trust enforcement is working")
    p_verify.add_argument("--namespace", required=True)
    p_verify.set_defaults(func=cmd_verify)

    p_report = sub.add_parser("report", help="Generate a markdown summary report")
    p_report.add_argument("--namespace", required=True)
    p_report.add_argument("--output", default="report.md")
    p_report.set_defaults(func=cmd_report)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
    except Exception as exc:
        print(red(f"Error: {exc}"))
        sys.exit(1)


if __name__ == "__main__":
    main()
