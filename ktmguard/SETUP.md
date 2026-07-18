# KTMGuard Setup and Usage Guide

Step-by-step instructions to install and run KTMGuard against a Kubernetes cluster, either from the cluster's own node or from a completely separate client machine.

## What KTMGuard Does

KTMGuard automates the two most error-prone steps in adopting Zero Trust on Kubernetes:

1. **Discovering** which services actually talk to which other services (`scan`)
2. **Generating** correct, ready-to-apply Kubernetes NetworkPolicy and Linkerd AuthorizationPolicy YAML from that map (`generate`)

It also includes `verify` (confirms the policy is applied and reports connectivity, with documented limitations — see below) and `report` (produces a Markdown summary).

### Which Detection Method for Which Adoption Tier

`scan` supports three detection methods, matching the thesis's tiered Zero Trust adoption roadmap:

| Method | Flag | Needs a mesh installed? | Roadmap tier |
|---|---|---|---|
| Static configuration inference | `--static` | No | **Level 1** — NetworkPolicy-only |
| Prometheus metrics | `--prometheus <url>` | Yes (Linkerd + its Prometheus) | **Level 1+** — NetworkPolicy + Linkerd mTLS |
| Live tap | `--tap` | Yes (Linkerd CLI) | **Level 1+** |

**If you have not installed a service mesh yet, start with `--static` alone.** It reads Deployment env vars and any ConfigMap values they reference via `envFrom`, and matches those values against known Service names in the namespace (e.g. an env var set to `cartservice:7070` or `cartservice.boutique.svc.cluster.local` both match the `cartservice` Service). This is exactly how most Kubernetes applications already declare their own dependencies, so it typically finds real edges immediately, with zero cluster prerequisites beyond `kubectl` access — see Part 3 below for the exact command.

Every edge `scan` finds is tagged with which method(s) found it:
- **HIGH CONFIDENCE** — corroborated by 2+ methods
- **UNCONFIRMED** — found only by `--static`: documented, but no traffic observed confirming it's actually used
- **OBSERVED ONLY** — found only by `--tap`/`--prometheus`, with no matching `--static` declaration: traffic is happening that isn't documented in any env var or ConfigMap — worth investigating before assuming it's intentional

`generate` carries this straight through into a comment on each generated policy.

## Prerequisites

- A running Kubernetes cluster with Linkerd installed and the target namespace injected (see the lab repository's `SETUP.md`)
- `kubectl` installed and configured with a working `kubeconfig` pointed at the cluster
- Python 3.10+ (Option A) or Docker (Option B) — see below

KTMGuard does **not** need to run on the cluster's own node. It works identically from any machine with `kubectl` access to the cluster — see the "Remote Client Setup" section below.

If you're starting with `--static` detection only (no mesh installed yet), that's all you need — `kubectl` access and Python (or Docker). The Linkerd CLI and Prometheus port-forward steps below are only required for `--tap`/`--prometheus`.

## Two Ways to Install KTMGuard

| | Option A: git clone | Option B: Docker |
|---|---|---|
| Best for | Cluster-adjacent machine, comfortable with Python/CLI setup | Personal laptop, minimal setup desired |
| Requires | Python 3.10+, pip, kubectl, optionally Linkerd CLI | Docker only |
| Setup steps | ~8 steps | 2 steps: build/pull image, run with mounted kubeconfig |
| Updates | `git pull` + reinstall deps | `docker pull` a new image tag (or rebuild) |
| Runs the CLI (`scan`/`generate`/`verify`/`report`) | Yes, directly | Yes, via `docker exec` into the running container |
| Runs the web dashboard | Yes (`python3 dashboard.py`) | Yes — this is what the image's default `CMD` runs |

Both options run the exact same `ktmguard.py` and `dashboard.py` — Option B just packages Option A's dependencies (Python, kubectl, the Linkerd CLI) into one image instead of installing them by hand. Pick whichever fits your machine; nothing else in this guide changes based on which you choose.

## Part 1 — Option A: git clone Installation (Same Machine as the Cluster)

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

## Part 1B — Option B: Docker Installation

**Read this before you run anything:** the container is designed to run on **the operator's own machine** — a junior engineer's laptop, or any client machine with a working kubeconfig pointed at the target cluster — **not** on the Kubernetes cluster's own infrastructure node. This is the same "runs wherever `kubectl` runs" model as Option A, just containerized.

The container shares its host machine's network access. If the host can already reach the cluster's API server — via its kubeconfig, and whatever security group / firewall rules that requires — the containerized dashboard can too, with no additional network configuration. Nothing needs to be exposed to the cluster's own network; the container only ever makes outbound calls to the API server your kubeconfig already points at.

Your kubeconfig is **mounted**, never baked into the image. Changing which cluster you're pointed at means updating the host's `~/.kube/config` and restarting the container — no image rebuild needed.

### Build and Run

```bash
git clone https://github.com/yu-stha/Zero-Trust-KtmGuard-Tool.git
cd Zero-Trust-KtmGuard-Tool/ktmguard

docker build -t ktmguard-dashboard .
docker run -d --restart=unless-stopped \
  -v ~/.kube/config:/root/.kube/config:ro \
  -p 5000:5000 --name ktmguard-dashboard ktmguard-dashboard
```

That's it — two steps. Then:

```bash
docker logs ktmguard-dashboard
```

to read the auto-generated dashboard password (see "Web Dashboard" below), and browse to `http://localhost:5000`.

### Or: docker-compose

```bash
docker compose up -d --build
```

Uses the included `docker-compose.yml`, which mounts `~/.kube/config` read-only, maps port 5000, and sets `restart: unless-stopped` — equivalent to the `docker run` command above.

### A Docker-Specific Gotcha: the Password File

`.dashboard_password` (see "Web Dashboard" below) is written inside the container's own filesystem. `restart: unless-stopped` / `docker restart` keep the **same** container, so the password survives normal restarts. But `docker rm` + recreate (or `docker compose down` followed by `up`, depending on your compose version) destroys that filesystem and a fresh random password gets generated next time. For Docker deployments, it's simplest to set the password explicitly rather than rely on the generated one:

```bash
docker run -d --restart=unless-stopped \
  -v ~/.kube/config:/root/.kube/config:ro \
  -e KTMGUARD_DASHBOARD_PASSWORD=your-own-password \
  -p 5000:5000 --name ktmguard-dashboard ktmguard-dashboard
```

### Running CLI Commands Inside the Container

The dashboard is the default entrypoint, but the same image can run `ktmguard.py` directly:

```bash
docker exec -it ktmguard-dashboard python ktmguard.py scan --namespace boutique --static
```

### Updating

```bash
git pull
docker build -t ktmguard-dashboard .
docker stop ktmguard-dashboard && docker rm ktmguard-dashboard
docker run -d --restart=unless-stopped -v ~/.kube/config:/root/.kube/config:ro -p 5000:5000 --name ktmguard-dashboard ktmguard-dashboard
```

(Note the password-file gotcha above applies here too, since this recreates the container.)

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

**Level 1 — no mesh installed:**

```bash
python3 ktmguard.py scan --namespace boutique --static
```

Works purely by reading Deployment env vars / ConfigMaps — no traffic, no Linkerd, no Prometheus needed. Every edge it finds is tagged `UNCONFIRMED` (documented, but not yet confirmed by observed traffic) unless corroborated below.

**Level 1+ — combine all three once Linkerd is installed:**

```bash
python3 ktmguard.py scan --namespace boutique --static --prometheus http://localhost:9091 --tap --tap-duration 30
```

- `--static` infers edges from configuration alone (see "Which Detection Method for Which Adoption Tier" above) — safe to always include, since it needs no mesh/Prometheus access to run.
- `--tap` observes live traffic directly via the Linkerd CLI, in addition to Prometheus metrics. Recommended when available — it detects communication paths that Prometheus's historical metrics can miss.
- If `linkerd` is not installed on the machine running KTMGuard, `--tap` degrades gracefully and is skipped, printing a warning rather than failing.
- Traffic must actually be occurring during the scan window for `--tap`/`--prometheus` to detect an edge. If your application is idle, generate some traffic first (e.g., loading the frontend a few times) or rely on `--tap`'s built-in auto-traffic-generation against the frontend's NodePort.
- Edges found by more than one method print as `HIGH CONFIDENCE`; a `--tap`/`--prometheus`-only edge with no matching `--static` declaration prints as `OBSERVED ONLY` — treat that as a signal to check whether that traffic is actually supposed to be happening.

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
python3 ktmguard.py report --namespace boutique --format markdown
python3 ktmguard.py report --namespace boutique --format html
```

Combines the results of the most recent `scan` and `verify` into a single summary. `--format` accepts `markdown` (default, unchanged behavior) or `html`:

- `markdown` writes `report.md` by default - the same plain-Markdown output as before.
- `html` writes `report.html` by default - the same content converted to a self-contained HTML document with embedded CSS, openable directly in a browser with no other files or network access needed.

`--output <path>` still works with either format to name the file explicitly; when omitted, the default filename's extension (`.md` / `.html`) follows whichever `--format` you chose.

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
| `--static` finds fewer edges than expected | It only matches values a container actually references directly — a value pulled from a Secret (deliberately never read, for security) or an individually-mapped `valueFrom.configMapKeyRef` env var (rather than a literal value or a whole `envFrom` ConfigMap) won't be seen | Cross-check with `--tap`/`--prometheus` once a mesh is available; an edge that's real but invisible to `--static` will show as `OBSERVED ONLY` rather than `UNCONFIRMED` |
