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
    # Some connections never get a client_id on the receiving side at all
    # (no_tls_reason="no_tls_from_remote") even though they're legitimate
    # meshed traffic. For those, fall back to the CALLER's own outbound proxy
    # metrics, which report `deployment` (the caller) and `authority`
    # (the destination host:port) directly - no identity decoding needed.
    queries = [
        (f'tcp_open_connections{{namespace="{namespace}", direction="inbound"}}',
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

def _linkerd_cli_available():
    return shutil.which("linkerd") is not None


def _frontend_node_port(services):
    for svc in services:
        if svc["name"] != "frontend":
            continue
        for p in svc["ports"]:
            if p.get("node_port"):
                return p["node_port"]
    return None


def _generate_frontend_traffic(node_port, duration, stop_event):
    """Best-effort background traffic generator: repeatedly hits the frontend's
    NodePort so tap has something to observe without the user manually clicking
    through the app. Assumes the NodePort is reachable at localhost, i.e. that
    KTMGuard is running on a cluster node; silently gives up on request errors
    since this is auxiliary, not required for tap itself to work."""
    url = f"http://localhost:{node_port}/"
    end_time = time.time() + duration
    while time.time() < end_time and not stop_event.is_set():
        try:
            requests.get(url, timeout=2)
        except requests.exceptions.RequestException:
            pass
        stop_event.wait(1)


def run_linkerd_tap(namespace, duration, known_names, node_port=None):
    """Runs `linkerd viz tap deploy -n <namespace> --output json` for `duration`
    seconds and decodes each JSON tap event's source/destination deployment
    into a src -> dst edge. Returns (edges, warning); on any failure to start
    or find the CLI, returns ([], warning) so the caller can skip gracefully."""
    if not _linkerd_cli_available():
        return [], "linkerd CLI not found on PATH; skipping tap-based detection."

    cmd = ["linkerd", "viz", "tap", "deploy", "-n", namespace, "--output", "json"]
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
            args=(node_port, duration, stop_event),
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

    tap_edges = []
    if args.tap:
        if not _linkerd_cli_available():
            print(yellow(
                "Warning: linkerd CLI not found on PATH; skipping tap-based detection."
            ))
            print()
        else:
            node_port = _frontend_node_port(services)
            print(f"Observing live traffic for {args.tap_duration} seconds "
                  "(move through the app to generate traffic)...")
            if node_port:
                print(f"Auto-generating traffic to frontend NodePort {node_port}.")
            tap_edges, tap_warning = run_linkerd_tap(
                args.namespace, args.tap_duration, known_names, node_port
            )
            if tap_warning:
                print(yellow(f"Warning: {tap_warning}"))
            print()

    edges, manual_review, warning = detect_communication_paths(
        args.prometheus, args.namespace, services
    )

    if tap_edges:
        combined = {(e["src"], e["dst"]): True for e in edges}
        new_from_tap = sum(1 for e in tap_edges if (e["src"], e["dst"]) not in combined)
        for e in tap_edges:
            combined[(e["src"], e["dst"])] = True
        edges = [{"src": s, "dst": d} for (s, d) in sorted(combined.keys())]
        if new_from_tap:
            print(f"Linkerd tap detected {new_from_tap} additional path(s) "
                  "not seen in Prometheus metrics.")
            print()

    if edges:
        manual_review = False
        print("Detected communication paths:")
        for e in edges:
            print(f"  {e['src']:<22}→ {e['dst']}")
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

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, "service-map.json")
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


def build_allow_policies(namespace, edges, services):
    docs = []

    for edge in edges:
        src, dst = edge["src"], edge["dst"]
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

    return docs


def build_linkerd_auth_policies(namespace, edges, services):
    callers_by_dst = {}
    for edge in edges:
        callers_by_dst.setdefault(edge["dst"], set()).add(edge["src"])

    docs = []
    protected_count = 0
    for dst, callers in sorted(callers_by_dst.items()):
        dst_svc = services.get(dst)
        selector = dst_svc["selector"] if dst_svc else {"app": dst}
        ports = dst_svc["ports"] if dst_svc else []
        port = ports[0]["target_port"] if ports else 80

        server_name = f"{dst}-server"
        authn_name = f"{dst}-callers"

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
        protected_count += 1

    return docs, protected_count


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


def yaml_dump_all(docs):
    return yaml.dump_all(docs, default_flow_style=False, sort_keys=False, explicit_start=True)


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
    allow_docs = build_allow_policies(namespace, edges, services)
    linkerd_docs, protected_count = build_linkerd_auth_policies(namespace, edges, services)
    readme = build_readme(namespace, len(edges))

    plan = [
        ("deny-all.yaml", [deny_all_doc], None),
        ("allow-policies.yaml", allow_docs, f"{len(allow_docs)} rules"),
        ("linkerd-auth-policy.yaml", linkerd_docs, f"{protected_count} policies"),
    ]

    if args.dry_run:
        for name, docs, _ in plan:
            print(f"--- {name} ---")
            print(yaml_dump_all(docs))
        print("--- README-apply.md ---")
        print(readme)
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for name, docs, note in plan:
        path = os.path.join(OUTPUT_DIR, name)
        with open(path, "w") as f:
            f.write(yaml_dump_all(docs))
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

def check_pod_injection(v1, namespace):
    pods = v1.list_namespaced_pod(namespace).items
    total = len(pods)
    fully_ready = 0
    for pod in pods:
        statuses = pod.status.container_statuses or []
        if len(statuses) >= 2 and all(c.ready for c in statuses):
            fully_ready += 1
    return fully_ready, total


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


def probe_connection(v1, namespace, pod, dst_host, port, timeout=3):
    """Attempt a TCP connection from inside `pod` to dst_host:port.

    Returns True if reachable, False if blocked/unreachable, None if the
    probe itself could not be executed (no exec-capable shell, etc).
    """
    probe = (
        f"if command -v nc >/dev/null 2>&1; then "
        f"  nc -z -w {timeout} {dst_host} {port} && echo KTMGUARD_OPEN || echo KTMGUARD_CLOSED; "
        f"elif command -v bash >/dev/null 2>&1; then "
        f"  bash -c '(exec 3<>/dev/tcp/{dst_host}/{port})' 2>/dev/null && echo KTMGUARD_OPEN || echo KTMGUARD_CLOSED; "
        f"elif command -v curl >/dev/null 2>&1; then "
        f"  curl -s -m {timeout} -o /dev/null {dst_host}:{port} ; "
        f"  [ $? -ne 7 ] && echo KTMGUARD_OPEN || echo KTMGUARD_CLOSED; "
        f"else echo KTMGUARD_NOTOOL; fi"
    )
    command = ["/bin/sh", "-c", probe]
    container = None
    if pod.spec.containers:
        non_proxy = [c.name for c in pod.spec.containers if c.name != "linkerd-proxy"]
        container = non_proxy[0] if non_proxy else pod.spec.containers[0].name
    try:
        resp = stream(
            v1.connect_get_namespaced_pod_exec,
            pod.metadata.name,
            namespace,
            container=container,
            command=command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _request_timeout=timeout + 5,
        )
    except Exception:
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

        pod = find_pod_for_selector(v1, namespace, services.get(src, {}).get("selector"))
        if pod is None:
            results.append({
                "src": src, "dst": dst, "port": port,
                "reachable": None, "expected_blocked": expected_blocked,
            })
            continue

        reachable = probe_connection(v1, namespace, pod, dst, port)
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

    map_path = os.path.join(OUTPUT_DIR, "service-map.json")
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
    conn_ok = all(
        r["reachable"] is not None and (r["reachable"] != r["expected_blocked"])
        for r in conn_results
    ) if conn_results else True

    all_ok = pod_ok and np_ok and authz_ok and conn_ok
    if all_ok:
        print(green("Zero Trust enforcement verified successfully."))
    else:
        print(red("Zero Trust enforcement verification found issues. Review the output above."))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "verify-results.json"), "w") as f:
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

    map_path = os.path.join(OUTPUT_DIR, "service-map.json")
    verify_path = os.path.join(OUTPUT_DIR, "verify-results.json")

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
        lines.append("| Source | Destination |")
        lines.append("|---|---|")
        for e in service_map.get("edges", []):
            lines.append(f"| {e['src']} | {e['dst']} |")
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
    p_scan.set_defaults(func=cmd_scan)

    p_gen = sub.add_parser("generate", help="Generate Zero Trust YAML configuration")
    p_gen.add_argument("--namespace", required=True)
    p_gen.add_argument("--input", default=os.path.join(OUTPUT_DIR, "service-map.json"))
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
