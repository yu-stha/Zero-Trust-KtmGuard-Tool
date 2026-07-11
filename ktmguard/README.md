# KTMGuard

KTMGuard is a Zero Trust configuration generator for Kubernetes clusters,
built for resource-constrained SME environments where a dedicated security
team to hand-map service dependencies does not exist. It scans a namespace,
observes real service-to-service traffic through Prometheus and Linkerd
metrics, and generates ready-to-apply Kubernetes NetworkPolicy and Linkerd
AuthorizationPolicy YAML files - turning the most error-prone step in Zero
Trust adoption (manual dependency mapping, which if done wrong silently
breaks production traffic) into a repeatable, auditable process.

## Prerequisites

- `kubectl` configured with access to a running Kubernetes cluster
  (verify with `kubectl get nodes`)
- Python 3.10+
- (Recommended) [Linkerd](https://linkerd.io) installed and the target
  namespace annotated for sidecar injection
- (Recommended) A reachable Prometheus instance (Linkerd's built-in Prometheus,
  or your own) for automatic traffic detection

## Installation

```
pip install -r requirements.txt
```

## Usage

### 1. Scan a namespace

```
python ktmguard.py scan --namespace boutique --prometheus http://localhost:9090
```

Connects to the cluster, lists services/deployments in the namespace, queries
Prometheus for observed traffic, and writes a communication map to
`ktmguard-output/.state/service-map.json`. State files live in `.state/` so
that `kubectl apply -f ktmguard-output/` (which picks up every `.yaml`/`.json`
file it finds in the directory) only ever sees the generated Kubernetes
manifests. If Prometheus is unreachable, KTMGuard falls back to listing
services only and flags the result for manual review.

### 2. Generate Zero Trust configuration

```
python ktmguard.py generate --namespace boutique --input ktmguard-output/.state/service-map.json
```

Produces, inside `ktmguard-output/`:

- `deny-all.yaml` - default-deny NetworkPolicy
- `allow-policies.yaml` - allow rules for each detected path, plus DNS and
  Linkerd control-plane traffic
- `linkerd-auth-policy.yaml` - `Server` / `MeshTLSAuthentication` /
  `AuthorizationPolicy` resources per protected service
- `README-apply.md` - step-by-step apply instructions

Use `--dry-run` to print the generated YAML to the terminal without writing
any files:

```
python ktmguard.py generate --namespace boutique --dry-run
```

### 3. Verify enforcement

```
python ktmguard.py verify --namespace boutique
```

Checks that pods are meshed (2/2 ready) and that NetworkPolicies and Linkerd
AuthorizationPolicies are applied. Also runs a TCP-connect probe between
service pairs, but note its limit: Linkerd transparently redirects a meshed
pod's outbound connections to its own local proxy, which accepts the
connection before attempting to reach the real destination - so this probe
typically reports every path as reachable regardless of whether
NetworkPolicy or AuthorizationPolicy is actually blocking it upstream. It
can't be relied on to confirm a disallowed path is blocked; treat a
REACHABLE result on a path that should be denied as inconclusive, not as
evidence enforcement isn't working, and verify important paths manually
(`kubectl exec -it -n <ns> deploy/<src> -- wget -qO- --timeout=3
http://<dst>:<port>/` - a genuinely blocked path will hang to the timeout).

### 4. Generate a report

```
python ktmguard.py report --namespace boutique --output report.md
```

Writes a markdown summary of the detected topology and verification results,
suitable for inclusion in project or thesis documentation.

## Notes

This tool was developed as part of a BSc Cybersecurity thesis on Zero Trust
feasibility for Kathmandu Valley SMEs. It is intended as a decision-support
aid, not a fully autonomous system - always review generated policies before
applying them to a production cluster.
