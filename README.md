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
| `scan` | Observes real service-to-service traffic (via Prometheus metrics and optional Linkerd `tap`) and builds a communication map — no manual guessing required |
| `generate` | Converts that map into ready-to-apply, correctly-scoped NetworkPolicy and Linkerd AuthorizationPolicy YAML |
| `verify` | Confirms the generated policy is applied and reports on pod injection, policy counts, and connectivity |
| `report` | Produces a Markdown summary of scan and verify results |

A lightweight Flask web dashboard is also included as an optional browser-based interface over the same CLI commands.

## Getting Started

**Full step-by-step setup instructions — for both local use and use from a separate remote client machine — are in [`ktmguard/SETUP.md`](ktmguard/SETUP.md).**

That guide covers:
- Installing KTMGuard alongside a Kubernetes cluster
- Running KTMGuard from a completely separate machine with no cluster components installed (the realistic "engineer's own laptop" scenario)
- Every command's usage, output, and known limitations
- A troubleshooting table built from real issues encountered during testing

Quick start, assuming a cluster with Linkerd already installed and injected:

```bash
git clone https://github.com/yu-stha/Zero-Trust-KtmGuard-Tool.git
cd Zero-Trust-KtmGuard-Tool/ktmguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

kubectl port-forward -n linkerd-viz svc/prometheus 9091:9090 &

python3 ktmguard.py scan --namespace <your-namespace> --prometheus http://localhost:9091 --tap
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

- `scan` detection quality depends on traffic actually occurring during the observation window
- Services sharing a common ServiceAccount (e.g. the Kubernetes `default`) cannot be individually identified — each service should have its own named ServiceAccount
- `verify`'s connectivity results reflect TCP-layer reachability only; application-layer enforcement should be confirmed manually for critical paths (see `SETUP.md` for the exact command)
- `tap`-based detection has shown variable reliability when run from a remote client, depending on network path to the cluster's aggregated API

See `ktmguard/SETUP.md` for the full troubleshooting reference.

## Author

BSc (Hons) Cybersecurity and Ethical Hacking
Softwarica College of IT & E-Commerce × Coventry University
Kathmandu Valley, Nepal, 2026