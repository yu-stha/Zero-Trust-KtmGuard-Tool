# KTMGuard

**An automated Zero Trust configuration generator for resource-constrained Kubernetes environments.**

KTMGuard was developed as part of a BSc (Hons) Cybersecurity and Ethical Hacking thesis investigating the operational feasibility of Zero Trust network security for small and medium enterprises (SMEs) in Kathmandu Valley, Nepal — organisations that typically operate without a dedicated security engineer, on limited cloud infrastructure budgets.

---

## The Problem

Adopting Zero Trust on Kubernetes requires two things that are genuinely difficult to get right by hand:

1. **Knowing exactly which service is allowed to talk to which other service** — get this wrong and you either leave dangerous paths open, or silently break your own application.
2. **Writing correct Kubernetes NetworkPolicy and Linkerd AuthorizationPolicy YAML** for every one of those paths — tedious, error-prone, and requires Kubernetes networking expertise most small teams don't have in-house.

Existing Zero Trust guidance assumes enterprise-scale teams with dedicated security staff. Nothing addresses the reality of a 3–5 person Kathmandu SME team running production workloads on a single budget cloud instance.

## What KTMGuard Does

KTMGuard automates the two steps above:

| Command | Purpose |
|---|---|
| `scan` | Builds a communication map via three independent, combinable detection methods — no manual guessing required |
| `generate` | Converts that map into ready-to-apply, correctly-scoped NetworkPolicy and Linkerd AuthorizationPolicy YAML |
| `verify` | Confirms the generated policy is applied and reports on pod injection, policy counts, and connectivity |
| `report` | Produces a Markdown summary of scan and verify results |

A lightweight Flask web dashboard is also included as an optional browser-based interface over the same CLI commands.

## Detection Methods and the Adoption Roadmap

`scan` supports three independent, combinable detection methods, matching the thesis's tiered Zero Trust adoption roadmap for SMEs:

| Flag | Requires | Roadmap tier | What it gives you |
|---|---|---|---|
| `--static` | Nothing beyond `kubectl` access — no mesh, no Prometheus | **Level 1** (NetworkPolicy-only) | Infers edges from Deployment env vars / ConfigMap values referencing known service names. The recommended starting point for an SME that hasn't installed a service mesh yet. |
| `--prometheus <url>` | Linkerd + its Prometheus instance | **Level 1+** (NetworkPolicy + Linkerd mTLS) | Edges from observed historical traffic metrics. |
| `--tap` | Linkerd CLI | **Level 1+** | Edges from live-observed traffic, cross-validates with Prometheus. |

All three can be combined in one `scan`. Every detected edge is tagged with **which** method(s) found it and a resulting confidence level:

- **HIGH CONFIDENCE** — found by 2+ methods (e.g. a config reference *and* observed traffic)
- **UNCONFIRMED** — found only by `--static`: a documented dependency with no traffic seen yet during the scan window
- **OBSERVED ONLY** — found only by `--tap`/`--prometheus`, with no matching config reference: traffic is happening that isn't documented anywhere — worth investigating before allowing it

Confidence is carried through into a comment on each generated policy in `generate`'s output, so the reasoning isn't lost between `scan` and applying the YAML.

## Getting Started

**Full step-by-step setup instructions — for both local use and use from a separate remote client machine — are in [`ktmguard/SETUP.md`](ktmguard/SETUP.md).**

That guide covers:
- Installing KTMGuard alongside a Kubernetes cluster
- Running KTMGuard from a completely separate machine with no cluster components installed (the realistic "engineer's own laptop" scenario)
- Every command's usage, output, and known limitations
- A troubleshooting table built from real issues encountered during testing

Quick start — Level 1, no service mesh required:

```bash
git clone https://github.com/yu-stha/Zero-Trust-KtmGuard-Tool.git
cd Zero-Trust-KtmGuard-Tool/ktmguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 ktmguard.py scan --namespace <your-namespace> --static
python3 ktmguard.py generate --namespace <your-namespace>
kubectl apply -f ktmguard-output/
python3 ktmguard.py verify --namespace <your-namespace>
```

Quick start — Level 1+, with Linkerd already installed and injected:

```bash
kubectl port-forward -n linkerd-viz svc/prometheus 9091:9090 &

python3 ktmguard.py scan --namespace <your-namespace> --static --prometheus http://localhost:9091 --tap
python3 ktmguard.py generate --namespace <your-namespace>
kubectl apply -f ktmguard-output/
python3 ktmguard.py verify --namespace <your-namespace>
```

## Design Principles

- **Reads, never guesses.** KTMGuard only proposes policy for traffic it actually observed. It never assumes a communication path is legitimate — if traffic didn't occur during the scan window, that path won't appear in the generated policy, and a warning is printed asking for manual review.
- **Transparent about its own limits.** `verify`'s connectivity check is documented as TCP-layer-only rather than presented as a definitive application-layer guarantee — a limitation discovered and confirmed through direct testing against Linkerd's proxy architecture, not assumed.
- **No production dependency.** KTMGuard is an operator-side tool. It runs from wherever the engineer runs `kubectl` and does not need to be deployed inside the cluster itself.

## Companion Repository

This tool was built to support the experimental lab in [`Zero-Trust-Inter-Microservices-Communications-SME-KATHMANDU`](https://github.com/yu-stha/Zero-Trust-Inter-Microservices-Communications-SME-KATHMANDU), which contains the underlying Zero Trust lab environment (K3s, Linkerd, and a 7-service microservices application) that KTMGuard was tested against, along with the baseline attack simulations and overhead measurements referenced in the accompanying thesis.

## Known Limitations

- `scan` detection quality (for `--prometheus`/`--tap`) depends on traffic actually occurring during the observation window
- `--static` can only find edges a workload's own configuration documents (env vars / ConfigMaps referencing another service by name); it cannot see traffic that exists but was never declared that way — that's exactly what `--tap`/`--prometheus`'s "OBSERVED ONLY" tag is for
- Services sharing a common ServiceAccount (e.g. the Kubernetes `default`) cannot be individually identified — each service should have its own named ServiceAccount
- `verify`'s connectivity results reflect TCP-layer reachability only; application-layer enforcement should be confirmed manually for critical paths (see `SETUP.md` for the exact command)
- `tap`-based detection has shown variable reliability when run from a remote client, depending on network path to the cluster's aggregated API

See `ktmguard/SETUP.md` for the full troubleshooting reference.

## Author

BSc (Hons) Cybersecurity and Ethical Hacking
Softwarica College of IT & E-Commerce × Coventry University
Kathmandu Valley, Nepal, 2026