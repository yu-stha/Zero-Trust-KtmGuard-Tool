# KTMGuard Dashboard - Option B installation path (see SETUP.md).
#
# This image is meant to run on the OPERATOR'S OWN machine (a laptop, a
# bastion host, any machine with a working kubeconfig for the target
# cluster) - NOT on the Kubernetes cluster's own infrastructure. It shares
# the host's network access: whatever the host's kubeconfig can already
# reach, the container can reach too, with no extra network configuration.
# The kubeconfig is always mounted at runtime, never baked into the image -
# changing clusters means updating the host's ~/.kube/config and
# restarting the container, not rebuilding this image.

FROM python:3.11-slim

# --------------------------------------------------------------------------
# kubectl - official static binary from dl.k8s.io, not the Debian package
# repositories (which lag behind upstream and pull in unrelated deps).
# --------------------------------------------------------------------------
ARG KUBECTL_VERSION=v1.31.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /usr/local/bin/kubectl \
       "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl

# --------------------------------------------------------------------------
# Linkerd CLI - needed for the dashboard's --tap detection method.
# Installs to /root/.linkerd2/bin; the PATH entry below makes it resolve
# like any other binary for the subprocess calls in ktmguard.py.
# --------------------------------------------------------------------------
RUN curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
ENV PATH="/root/.linkerd2/bin:${PATH}"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ktmguard.py dashboard.py ./
COPY static/ ./static/
COPY templates/ ./templates/

# Mount point for the operator's own kubeconfig - see docker-compose.yml /
# SETUP.md. Never baked into the image.
ENV KUBECONFIG=/root/.kube/config

EXPOSE 5000

CMD ["python", "dashboard.py"]
