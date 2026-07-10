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
`ktmguard-output/service-map.json`. If Prometheus is unreachable, KTMGuard
falls back to listing services only and flags the result for manual review.

### 2. Generate Zero Trust configuration

```
python ktmguard.py generate --namespace boutique --input ktmguard-output/service-map.json
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

Checks that pods are meshed (2/2 ready), that NetworkPolicies and Linkerd
AuthorizationPolicies are applied, and runs a connectivity test to confirm
disallowed paths are blocked and allowed paths still work.

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
