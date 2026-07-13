# KTMGuard Setup and Usage Guide

Step-by-step instructions to install and run KTMGuard against a Kubernetes cluster, either from the cluster's own node or from a completely separate client machine.

## What KTMGuard Does

KTMGuard automates the two most error-prone steps in adopting Zero Trust on Kubernetes:

1. **Discovering** which services actually talk to which other services (`scan`)
2. **Generating** correct, ready-to-apply Kubernetes NetworkPolicy and Linkerd AuthorizationPolicy YAML from that map (`generate`)

It also includes `verify` (confirms the policy is applied and reports connectivity, with documented limitations — see below) and `report` (produces a Markdown summary).

## Prerequisites

- A running Kubernetes cluster with Linkerd installed and the target namespace injected (see the lab repository's `SETUP.md`)
- `kubectl` installed and configured with a working `kubeconfig` pointed at the cluster
- Python 3.10+

KTMGuard does **not** need to run on the cluster's own node. It works identically from any machine with `kubectl` access to the cluster — see the "Remote Client Setup" section below.

## Part 1 — Local Installation (Same Machine as the Cluster)

```bash
git clone https://github.com/yu-stha/Zero-Trust-KtmGuard-Tool.git
cd Zero-Trust-KtmGuard-Tool/ktmguard
sudo apt install -y python3.14-venv python3-pip   # if venv creation fails
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Confirm `kubectl` already works before proceeding:

```bash
kubectl get nodes
```

### Optional — Install the Linkerd CLI for `--tap` Detection

Prometheus-based detection works without this. The Linkerd CLI is only needed for the `--tap` flag, which observes live traffic directly rather than reading historical metrics:

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
export PATH=$PATH:$HOME/.linkerd2/bin
echo 'export PATH=$PATH:$HOME/.linkerd2/bin' >> ~/.bashrc
```

### Port-Forward Prometheus

KTMGuard reads traffic metrics from Linkerd Viz's own Prometheus instance (not a general-purpose Prometheus, if you have one installed separately):

```bash
kubectl port-forward -n linkerd-viz svc/prometheus 9091:9090 > /tmp/pf-prom.log 2>&1 &
sleep 2
cat /tmp/pf-prom.log
```

Confirm it shows `Forwarding from 127.0.0.1:9091 -> 9090` before continuing.

## Part 2 — Remote Client Setup (Separate Machine, No Cluster Components)

This setup validates a realistic scenario: an engineer operating from their own workstation against a production cluster, without SSH access to the cluster node itself.

### Step 1 — Base Setup

On the client machine:

```bash
sudo apt update && sudo apt install -y python3-pip python3-venv kubectl
git clone https://github.com/yu-stha/Zero-Trust-KtmGuard-Tool.git
cd Zero-Trust-KtmGuard-Tool/ktmguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

(If `kubectl` is not available via `apt`, install it directly:)

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

### Step 2 — Transfer the Kubeconfig Securely

Do **not** copy-paste kubeconfig content through a terminal — long base64-encoded certificate fields are easily corrupted by terminal line-wrapping, which produces a `P256 point not on curve` error that is difficult to diagnose. Use `scp` instead:

On the client, generate an SSH key if one doesn't already exist:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
cat ~/.ssh/id_ed25519.pub
```

On the cluster node, authorize that key:

```bash
echo "<paste the client's public key here>" >> ~/.ssh/authorized_keys
```

Back on the client, transfer the file directly:

```bash
scp -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no ubuntu@<cluster-public-ip>:~/.kube/config ~/.kube/config-raw
```

### Step 3 — Point the Config at the Cluster's Public IP

K3s's default kubeconfig points at `127.0.0.1`, which is only valid on the cluster node itself. Update it:

```bash
sed -i 's|https://127.0.0.1:6443|https://<cluster-public-ip>:6443|' ~/.kube/config-raw
```

K3s's default TLS certificate is issued only for internal cluster IPs and will not validate against the public IP. For lab/testing purposes, disable strict TLS verification rather than reissuing certificates:

```bash
sed -i '/certificate-authority-data:/c\    insecure-skip-tls-verify: true' ~/.kube/config-raw
cp ~/.kube/config-raw ~/.kube/config
```

### Step 4 — Confirm Connectivity

```bash
export KUBECONFIG=~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
kubectl get nodes
```

This should return the cluster's node in `Ready` state.

### Step 5 — Ensure the Cluster's API Port Is Reachable

The cluster's security group must allow inbound traffic on port `6443` from the client's IP.

### Step 6 — Port-Forward Prometheus from the Client

`kubectl port-forward` works the same way remotely as it does locally, tunneling through the API server:

```bash
kubectl port-forward -n linkerd-viz svc/prometheus 9091:9090 > /tmp/pf-prom.log 2>&1 &
sleep 2
cat /tmp/pf-prom.log
```

## Part 3 — Running KTMGuard

All commands below work identically whether run locally on the cluster node or from a remote client, once the setup above is complete.

### Scan

```bash
python3 ktmguard.py scan --namespace boutique --prometheus http://localhost:9091 --tap --tap-duration 30
```

- `--tap` observes live traffic directly via the Linkerd CLI, in addition to Prometheus metrics. Recommended when available — it detects communication paths that Prometheus's historical metrics can miss.
- If `linkerd` is not installed on the machine running KTMGuard, the tool degrades gracefully and falls back to Prometheus-only detection, printing a warning rather than failing.
- Traffic must actually be occurring during the scan window for edges to be detected. If your application is idle, generate some traffic first (e.g., loading the frontend a few times) or rely on `--tap`'s built-in auto-traffic-generation against the frontend's NodePort.

Output is written to `ktmguard-output/.state/service-map.json`.

### Generate

```bash
python3 ktmguard.py generate --namespace boutique
```

Add `--dry-run` to preview the YAML in the terminal without writing files — useful for review before committing to `apply`.

Produces:
- `ktmguard-output/deny-all.yaml`
- `ktmguard-output/allow-policies.yaml`
- `ktmguard-output/linkerd-auth-policy.yaml`
- `ktmguard-output/README-apply.md`

### Apply

```bash
kubectl apply --dry-run=client -f ktmguard-output/   # validate first
kubectl apply -f ktmguard-output/
kubectl get pods -n boutique                          # confirm nothing broke
```

### Verify

```bash
python3 ktmguard.py verify --namespace boutique
```

Reports:
- Whether all pods have the Linkerd sidecar injected
- How many NetworkPolicies and AuthorizationPolicies are applied
- A connectivity table for every known and unknown service pair

**Important limitation, stated plainly:** the connectivity table reflects TCP-layer reachability only. Linkerd's proxy accepts the initial TCP handshake locally before attempting to reach the real destination, so a path blocked at the application layer can still report as "reachable" here. For definitive confirmation of a specific path, test manually:

```bash
kubectl exec -it -n boutique deploy/<source-service> -- wget -qO- --timeout=3 http://<destination-service>:<port>/
```

A timeout or error response confirms the block; a normal response confirms the path is genuinely open.

### Report

```bash
python3 ktmguard.py report --namespace boutique --output report.md
```

Combines the results of the most recent `scan` and `verify` into a single Markdown summary.

## Part 4 — Web Dashboard (Optional)

A Flask-based dashboard wraps the same CLI commands with a browser interface.

```bash
pip install flask markdown
python3 dashboard.py
```

The dashboard binds to all interfaces by default. For security, access it via SSH tunnel rather than exposing a public port, since it has no authentication and can trigger real cluster changes:

```bash
ssh -i your-key.pem -L 5000:localhost:5000 ubuntu@<client-or-cluster-ip>
```

Then browse to `http://localhost:5000` on your local machine.

If you do choose to expose it directly, restrict the security group rule to your own IP only, and remove the rule once you're done testing.

## Common Issues

| Symptom | Cause | Fix |
|---|---|---|
| `scan` reports 0 edges despite real traffic | Traffic didn't occur during the scan window, or all services share the `default` ServiceAccount (identities collapse to `default`, making the source unidentifiable) | Generate traffic during the scan; create named ServiceAccounts per service (see lab `SETUP.md`) |
| `kubectl apply -f ktmguard-output/` fails with a YAML validation error on `service-map.json` | Older versions wrote state files into the same directory as the generated policy YAML | Update to the current version, which stores state under `ktmguard-output/.state/` |
| `verify` reports every connection as `BLOCKED`, including known-allowed paths | A prior redesign of the connectivity probe relied on Linkerd proxy metrics that don't reliably populate for all traffic patterns | Use the current version, which defaults to a documented TCP-layer check and flags its own limitation rather than guessing |
| `P256 point not on curve` when using a remote kubeconfig | Certificate data corrupted during manual copy-paste through a terminal | Transfer the kubeconfig with `scp` instead, never by pasting base64 content directly |
| `linkerd viz tap` returns a 404 from a remote client | The Kubernetes aggregated API path for the Tap APIService did not resolve correctly from that client's network path | Fall back to Prometheus-only detection (omit `--tap`); this is a known limitation of tap-based detection from certain remote network configurations |
