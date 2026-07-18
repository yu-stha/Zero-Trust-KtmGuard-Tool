(function () {
  "use strict";

  const namespaceEl = document.getElementById("namespace");
  const state = { eventSources: {} };

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function fetchJson(url, opts) {
    return fetch(url, opts).then((r) => r.json().then((data) => ({ ok: r.ok, data })));
  }

  // ---------------------------------------------------------------------
  // Sidebar navigation (page switching)
  // ---------------------------------------------------------------------

  function showPage(page) {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
    document.querySelectorAll(".page").forEach((p) => p.classList.add("hidden"));
    const target = document.getElementById("page-" + page);
    if (target) {
      target.classList.remove("hidden");
      target.classList.remove("fade-in");
      // eslint-disable-next-line no-unused-expressions
      target.offsetHeight; // force reflow so the animation replays
      target.classList.add("fade-in");
    }
    if (page === "overview") refreshOverview();
    if (page === "apply") refreshApplyPreflight();
    if (page === "settings") refreshSettings();
  }

  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => showPage(btn.dataset.page));
  });

  document.addEventListener("click", (e) => {
    const goto = e.target.closest("[data-goto-page]");
    if (goto) showPage(goto.dataset.gotoPage);
  });

  // ---------------------------------------------------------------------
  // Cluster status + TLS warning strip
  // ---------------------------------------------------------------------

  function refreshClusterStatus() {
    fetch("/api/cluster-info")
      .then((r) => r.json())
      .then((data) => {
        document.getElementById("cluster-dot").className = "dot " + (data.connected ? "dot-green" : "dot-red");
        document.getElementById("cluster-text").textContent = data.connected
          ? (data.server ? "connected — " + data.server : "cluster reachable")
          : "cluster unreachable";
        document.getElementById("tls-warning").classList.toggle("hidden", !data.insecure_skip_tls_verify);
      })
      .catch(() => {
        document.getElementById("cluster-dot").className = "dot dot-red";
        document.getElementById("cluster-text").textContent = "cluster unreachable";
      });
  }
  refreshClusterStatus();
  setInterval(refreshClusterStatus, 20000);

  // ---------------------------------------------------------------------
  // Terminal / SSE streaming / run orchestration (per-page terminal)
  // ---------------------------------------------------------------------

  function terminalFor(action) {
    return document.getElementById("terminal-" + action);
  }

  function resetTerminal(action) {
    const el = terminalFor(action);
    if (!el) return;
    el.classList.remove("error-border");
    el.textContent = "";
  }

  function appendTerminalLine(action, line) {
    const el = terminalFor(action);
    if (!el) return;
    el.textContent += line + "\n";
    el.scrollTop = el.scrollHeight;
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll(".btn-primary, .btn-danger").forEach((b) => (b.disabled = disabled));
  }

  function streamOutput(action, onDone) {
    if (state.eventSources[action]) state.eventSources[action].close();
    const es = new EventSource("/api/stream?since=0");
    state.eventSources[action] = es;
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      appendTerminalLine(action, data.line);
    };
    es.addEventListener("done", (e) => {
      es.close();
      state.eventSources[action] = null;
      const data = JSON.parse(e.data);
      if (data.returncode !== 0) terminalFor(action).classList.add("error-border");
      onDone(data.returncode);
    });
    es.onerror = () => {
      es.close();
      state.eventSources[action] = null;
      appendTerminalLine(action, "[dashboard] Connection to server lost.");
      const el = terminalFor(action);
      if (el) el.classList.add("error-border");
      setButtonsDisabled(false);
    };
  }

  function runAction(action, payload, resultsElId, onSuccess) {
    resetTerminal(action);
    const resultsEl = document.getElementById(resultsElId);
    if (resultsEl) resultsEl.innerHTML = "";
    setButtonsDisabled(true);

    fetchJson("/api/run/" + action, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then(({ ok, data }) => {
        if (!ok) {
          appendTerminalLine(action, "[dashboard] " + data.error);
          const el = terminalFor(action);
          if (el) el.classList.add("error-border");
          if (resultsEl) resultsEl.innerHTML = `<div class="error-panel">${escapeHtml(data.error)}</div>`;
          setButtonsDisabled(false);
          return;
        }
        streamOutput(action, (returncode) => {
          setButtonsDisabled(false);
          if (returncode === 0) {
            if (onSuccess) onSuccess();
          } else if (resultsEl) {
            resultsEl.innerHTML =
              `<div class="error-panel">Command exited with code ${returncode}. See output above.</div>`;
          }
        });
      })
      .catch((err) => {
        appendTerminalLine(action, "[dashboard] Request failed: " + err);
        const el = terminalFor(action);
        if (el) el.classList.add("error-border");
        setButtonsDisabled(false);
      });
  }

  // ---------------------------------------------------------------------
  // Overview
  // ---------------------------------------------------------------------

  function statusCardInfo(status, protectedCount, totalTargets) {
    if (status === "fully-applied") {
      return { cls: "status-full", text: `Fully Applied (${totalTargets} of ${totalTargets})` };
    }
    if (status === "partially-applied") {
      return { cls: "status-partial", text: `Partially Applied (${protectedCount} of ${totalTargets} services protected)` };
    }
    return { cls: "status-not-applied", text: "Zero Trust Not Applied" };
  }

  function refreshOverview() {
    const namespace = namespaceEl.value.trim();
    const badgeEl = document.getElementById("overview-status-badge");
    const subEl = document.getElementById("overview-status-sub");
    badgeEl.className = "status-card-badge status-loading";
    badgeEl.textContent = "Checking cluster state…";
    subEl.textContent = "";

    fetch("/api/overview?namespace=" + encodeURIComponent(namespace))
      .then((r) => r.json())
      .then((data) => {
        const info = statusCardInfo(data.status, data.protected_count, data.total_targets);
        badgeEl.className = "status-card-badge " + info.cls;
        badgeEl.textContent = info.text;
        subEl.textContent =
          data.status === "not-applied"
            ? "Run Scan → Generate → Apply → Verify to get started."
            : `Namespace: ${data.namespace}`;

        document.getElementById("ov-services").textContent = data.services_found;
        document.getElementById("ov-edges").textContent = data.edges_detected;
        document.getElementById("ov-mesh").textContent = data.pod_injection
          ? `${data.pod_injection.ready}/${data.pod_injection.total} pods`
          : "not verified yet";
        document.getElementById("ov-lastscan").textContent = data.last_scan
          ? new Date(data.last_scan).toLocaleString()
          : "never";

        const gapsEl = document.getElementById("overview-gaps-list");
        if (!data.gap_check_available) {
          gapsEl.innerHTML = '<p class="hint">Could not check applied AuthorizationPolicies (cluster unreachable or CRD not installed) — see cluster status above.</p>';
          return;
        }
        if (!data.gaps.length) {
          gapsEl.innerHTML = data.total_targets
            ? '<p class="hint">All detected destinations have an AuthorizationPolicy applied.</p>'
            : '<p class="hint">Run Scan to detect communication paths first.</p>';
          return;
        }
        gapsEl.innerHTML = data.gaps
          .map(
            (g) => `
          <div class="gap-row">
            <div class="gap-row-text">
              <div class="gap-service">${escapeHtml(g.service)}</div>
              <div class="gap-reason">${escapeHtml(g.reason)}</div>
            </div>
            <button class="btn-secondary" data-goto-page="generate">Go to Generate</button>
          </div>`
          )
          .join("");
      })
      .catch(() => {
        badgeEl.className = "status-card-badge status-not-applied";
        badgeEl.textContent = "Unable to determine status";
      });
  }

  // ---------------------------------------------------------------------
  // Scan
  // ---------------------------------------------------------------------

  const CONFIDENCE_META = {
    "high-confidence": { cls: "high", badge: "badge-high", label: "HIGH CONFIDENCE" },
    "unconfirmed": { cls: "unconfirmed", badge: "badge-unconfirmed", label: "UNCONFIRMED" },
    "observed-only": { cls: "observed", badge: "badge-observed", label: "OBSERVED ONLY" },
  };
  function confidenceMeta(confidence) {
    return CONFIDENCE_META[confidence] || { cls: "unknown", badge: "", label: confidence || "-" };
  }

  function syncMethodCardStyling() {
    document.querySelectorAll(".method-card").forEach((card) => {
      const cb = card.querySelector("input[type=checkbox]");
      card.classList.toggle("checked", cb.checked);
    });
  }
  document.querySelectorAll(".method-card input[type=checkbox]").forEach((cb) => {
    cb.addEventListener("change", syncMethodCardStyling);
  });
  syncMethodCardStyling();

  function syncScanFieldAvailability() {
    document.getElementById("prometheus-url-row").classList.toggle(
      "disabled", !document.getElementById("method-prometheus").checked);
    document.getElementById("tap-duration-row").classList.toggle(
      "disabled", !document.getElementById("method-tap").checked);
  }
  document.getElementById("method-prometheus").addEventListener("change", syncScanFieldAvailability);
  document.getElementById("method-tap").addEventListener("change", syncScanFieldAvailability);
  syncScanFieldAvailability();

  document.getElementById("run-scan").addEventListener("click", () => {
    const payload = {
      namespace: namespaceEl.value.trim(),
      static: document.getElementById("method-static").checked,
      tap: document.getElementById("method-tap").checked,
      tap_duration: document.getElementById("tap-duration").value,
      prometheus: document.getElementById("method-prometheus").checked
        ? document.getElementById("prometheus-url").value.trim()
        : "",
    };
    runAction("scan", payload, "scan-results", renderScanResults);
  });

  function buildScanMap(svg, services, edges) {
    const width = 600, height = 420, cx = width / 2, cy = height / 2, r = Math.min(width, height) / 2 - 70;
    const nodeR = 30;
    const positions = {};
    const n = services.length || 1;
    services.forEach((name, i) => {
      const angle = (2 * Math.PI * i) / n - Math.PI / 2;
      positions[name] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    });

    let defs = `<defs>`;
    ["high", "unconfirmed", "observed", "unknown"].forEach((cls) => {
      defs += `<marker id="arrow-${cls}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M0,0 L10,5 L0,10 z" class="map-arrowhead-${cls}"></path></marker>`;
    });
    defs += `</defs>`;

    let edgesHtml = "";
    edges.forEach((e, idx) => {
      const a = positions[e.src], b = positions[e.dst];
      if (!a || !b) return;
      const dx = b.x - a.x, dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const ux = dx / dist, uy = dy / dist;
      const x1 = a.x + ux * (nodeR + 2), y1 = a.y + uy * (nodeR + 2);
      const x2 = b.x - ux * (nodeR + 8), y2 = b.y - uy * (nodeR + 8);
      const meta = confidenceMeta(e.confidence);
      edgesHtml += `<path class="map-edge map-edge-${meta.cls}" data-edge-idx="${idx}"
        marker-end="url(#arrow-${meta.cls})"
        d="M${x1.toFixed(1)},${y1.toFixed(1)} L${x2.toFixed(1)},${y2.toFixed(1)}"></path>`;
    });

    let nodesHtml = "";
    services.forEach((name) => {
      const p = positions[name];
      nodesHtml += `<circle class="map-node-circle" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${nodeR}"></circle>
        <text class="map-node-label" x="${p.x.toFixed(1)}" y="${(p.y + 4).toFixed(1)}">${escapeHtml(
        name.length > 12 ? name.slice(0, 11) + "…" : name
      )}</text>`;
    });

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    // edges drawn first so node circles sit visually on top of arrow tails
    svg.innerHTML = defs + edgesHtml + nodesHtml;

    const tooltip = document.getElementById("map-tooltip");
    svg.querySelectorAll(".map-edge").forEach((path) => {
      const e = edges[Number(path.dataset.edgeIdx)];
      path.addEventListener("mousemove", (evt) => {
        const meta = confidenceMeta(e.confidence);
        const methods = (e.methods || []).join(", ") || "-";
        tooltip.innerHTML =
          `<div class="map-tooltip-title">${escapeHtml(e.src)} → ${escapeHtml(e.dst)}</div>` +
          `<div class="map-tooltip-row">Confidence: ${escapeHtml(meta.label)}</div>` +
          `<div class="map-tooltip-row">Method(s): ${escapeHtml(methods)}</div>` +
          (e.static_source_field
            ? `<div class="map-tooltip-row">Source field: ${escapeHtml(e.static_source_field)}</div>`
            : "");
        const wrapRect = svg.parentElement.getBoundingClientRect();
        tooltip.style.left = evt.clientX - wrapRect.left + 14 + "px";
        tooltip.style.top = evt.clientY - wrapRect.top + 14 + "px";
        tooltip.classList.remove("hidden");
      });
      path.addEventListener("mouseleave", () => tooltip.classList.add("hidden"));
    });
  }

  function edgesTableHtml(edges) {
    let html =
      '<table class="result-table" id="scan-edges-table"><thead><tr>' +
      '<th class="sortable" data-sort="src">Source</th>' +
      '<th class="sortable" data-sort="dst">Destination</th>' +
      '<th class="sortable" data-sort="confidence">Confidence</th>' +
      '<th class="sortable" data-sort="methods">Methods</th>' +
      "</tr></thead><tbody>";
    edges.forEach((e) => {
      const meta = confidenceMeta(e.confidence);
      html += `<tr><td>${escapeHtml(e.src)}</td><td>${escapeHtml(e.dst)}</td>` +
        `<td><span class="badge ${meta.badge}">${escapeHtml(meta.label)}</span></td>` +
        `<td>${escapeHtml((e.methods || []).join(", "))}</td></tr>`;
    });
    html += "</tbody></table>";
    return html;
  }

  function wireSortableTable(tableId, rowsGetter, renderRow) {
    const table = document.getElementById(tableId);
    if (!table) return;
    let sortKey = null, sortAsc = true;
    table.querySelectorAll("th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        sortAsc = sortKey === key ? !sortAsc : true;
        sortKey = key;
        table.querySelectorAll("th.sortable").forEach((h) => h.classList.remove("sort-active"));
        th.classList.add("sort-active");
        const rows = rowsGetter().slice();
        rows.sort((a, b) => {
          const av = String(a[key] || (Array.isArray(a.methods) ? a.methods.join(",") : "")).toLowerCase();
          const bv = String(b[key] || (Array.isArray(b.methods) ? b.methods.join(",") : "")).toLowerCase();
          if (av < bv) return sortAsc ? -1 : 1;
          if (av > bv) return sortAsc ? 1 : -1;
          return 0;
        });
        const tbody = table.querySelector("tbody");
        tbody.innerHTML = rows.map(renderRow).join("");
      });
    });
  }

  function renderScanResults() {
    fetch("/api/scan-result")
      .then((r) => r.json())
      .then((data) => {
        const el = document.getElementById("scan-results");
        if (!data.available) {
          el.innerHTML = '<p class="hint">No service-map.json found.</p>';
          return;
        }
        if (!data.edges.length) {
          el.innerHTML = '<p class="hint">No communication paths detected.</p>';
          return;
        }

        let banner = "";
        if (data.manual_review_required) {
          banner = '<div class="banner">Manual review flagged during scan.</div>';
        }

        el.innerHTML =
          banner +
          '<div class="tabs">' +
          '<button class="tab-btn active" data-tab="map">Visual Map</button>' +
          '<button class="tab-btn" data-tab="table">Table</button>' +
          "</div>" +
          '<div class="tab-panel" id="scan-tab-map">' +
          '<div class="scan-map-wrap"><svg id="scan-map-svg" class="scan-map"></svg>' +
          '<div class="map-tooltip hidden" id="map-tooltip"></div></div>' +
          '<div class="map-legend">' +
          '<span><span class="legend-line legend-high"></span>High confidence</span>' +
          '<span><span class="legend-line legend-unconfirmed"></span>Unconfirmed</span>' +
          '<span><span class="legend-line legend-observed"></span>Observed only</span>' +
          "</div></div>" +
          '<div class="tab-panel hidden" id="scan-tab-table">' + edgesTableHtml(data.edges) + "</div>";

        el.querySelectorAll(".tab-btn").forEach((btn) => {
          btn.addEventListener("click", () => {
            el.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            el.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
            document.getElementById("scan-tab-" + btn.dataset.tab).classList.remove("hidden");
          });
        });

        buildScanMap(document.getElementById("scan-map-svg"), data.services, data.edges);
        wireSortableTable("scan-edges-table", () => data.edges, (e) => {
          const meta = confidenceMeta(e.confidence);
          return `<tr><td>${escapeHtml(e.src)}</td><td>${escapeHtml(e.dst)}</td>` +
            `<td><span class="badge ${meta.badge}">${escapeHtml(meta.label)}</span></td>` +
            `<td>${escapeHtml((e.methods || []).join(", "))}</td></tr>`;
        });
      });
  }

  // ---------------------------------------------------------------------
  // Generate
  // ---------------------------------------------------------------------

  document.getElementById("run-generate").addEventListener("click", () => {
    const dryRun = document.getElementById("dry-run").checked;
    const payload = { namespace: namespaceEl.value.trim(), dry_run: dryRun };
    runAction("generate", payload, "generate-results", () => {
      const el = document.getElementById("generate-results");
      if (dryRun) {
        el.innerHTML = '<p class="hint">Dry run — see YAML in the output above. No files were written.</p>';
        return;
      }
      renderGenerateResults();
    });
  });

  // Minimal hand-rolled YAML token coloring - deliberately not an external
  // highlighter dependency, to keep the dashboard fully self-contained.
  function highlightYaml(text) {
    return text
      .split("\n")
      .map((line) => {
        const escaped = escapeHtml(line);

        const commentMatch = escaped.match(/^(\s*)(#.*)$/);
        if (commentMatch) {
          return commentMatch[1] + '<span class="y-comment">' + commentMatch[2] + "</span>";
        }

        let prefix = "";
        let rest = escaped;
        const listMatch = escaped.match(/^(\s*)(-\s)(.*)$/);
        if (listMatch) {
          prefix = listMatch[1] + '<span class="y-dash">' + listMatch[2] + "</span>";
          rest = listMatch[3];
        }

        const kvMatch = rest.match(/^([A-Za-z0-9_.\-/]+:)(\s?)(.*)$/);
        if (kvMatch) {
          let value = kvMatch[3];
          if (value) value = '<span class="y-str">' + value + "</span>";
          rest = '<span class="y-key">' + kvMatch[1] + "</span>" + kvMatch[2] + value;
        }

        return prefix + rest;
      })
      .join("\n");
  }

  function renderGenerateResults() {
    fetch("/api/generate-result")
      .then((r) => r.json())
      .then((data) => {
        const el = document.getElementById("generate-results");
        const names = ["deny-all.yaml", "allow-policies.yaml", "linkerd-auth-policy.yaml"];
        const available = names.filter((n) => data.files[n] !== undefined);

        if (!available.length) {
          el.innerHTML = '<p class="hint">No generated files found.</p>';
          return;
        }

        let banner = "";
        if (data.review_edges && data.review_edges.length) {
          banner =
            '<div class="banner banner-amber"><strong>Review before applying:</strong> the following edges feeding ' +
            "into this generation are not yet corroborated by observed traffic.<ul>" +
            data.review_edges
              .map((e) => {
                const meta = confidenceMeta(e.confidence);
                return `<li>${escapeHtml(e.src)} → ${escapeHtml(e.dst)} — ${escapeHtml(meta.label)}</li>`;
              })
              .join("") +
            "</ul></div>";
        }

        let tabs = '<div class="tabs">';
        let panels = "";
        available.forEach((name, i) => {
          const count = data.rule_counts[name] || 0;
          tabs += `<button class="tab-btn${i === 0 ? " active" : ""}" data-tab="${escapeHtml(name)}">` +
            `${escapeHtml(name)}<span class="yaml-tab-count">(${count})</span></button>`;
          panels += `<div class="tab-panel${i === 0 ? "" : " hidden"}" id="gen-tab-${escapeHtml(name)}">` +
            `<div class="yaml-panel-body">${highlightYaml(data.files[name])}</div></div>`;
        });
        tabs += "</div>";

        el.innerHTML = banner + tabs + panels;

        el.querySelectorAll(".tab-btn").forEach((btn) => {
          btn.addEventListener("click", () => {
            el.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            el.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
            document.getElementById("gen-tab-" + btn.dataset.tab).classList.remove("hidden");
          });
        });
      });
  }

  // ---------------------------------------------------------------------
  // Apply
  // ---------------------------------------------------------------------

  function refreshApplyPreflight() {
    const namespace = namespaceEl.value.trim();
    const el = document.getElementById("apply-preflight-text");
    el.textContent = "Loading preflight summary…";
    fetch("/api/apply-preflight?namespace=" + encodeURIComponent(namespace))
      .then((r) => r.json())
      .then((data) => {
        if (!data.files_exist) {
          el.innerHTML = '<span class="text-amber">No generated policy files found yet — run Generate first.</span>';
          return;
        }
        el.innerHTML =
          `This will apply <strong>${data.network_policy_count}</strong> NetworkPolicy and ` +
          `<strong>${data.authorization_policy_count}</strong> AuthorizationPolicy resources to namespace ` +
          `<strong>${escapeHtml(data.namespace)}</strong> on cluster ` +
          `<strong>${escapeHtml(data.server || "unknown")}</strong>.`;
      });
  }

  const applyModal = document.getElementById("apply-modal");
  const applyModalInput = document.getElementById("apply-modal-input");
  const applyConfirmBtn = document.getElementById("apply-confirm");

  document.getElementById("run-apply").addEventListener("click", () => {
    const namespace = namespaceEl.value.trim();
    document.getElementById("apply-modal-namespace").textContent = namespace;
    fetch("/api/apply-preflight?namespace=" + encodeURIComponent(namespace))
      .then((r) => r.json())
      .then((data) => {
        document.getElementById("apply-modal-server").textContent = data.server || "unknown";
      });
    applyModalInput.value = "";
    applyConfirmBtn.disabled = true;
    applyModal.classList.remove("hidden");
    applyModalInput.focus();
  });

  applyModalInput.addEventListener("input", () => {
    applyConfirmBtn.disabled = applyModalInput.value.trim() !== namespaceEl.value.trim();
  });

  document.getElementById("apply-cancel").addEventListener("click", () => {
    applyModal.classList.add("hidden");
  });

  applyConfirmBtn.addEventListener("click", () => {
    applyModal.classList.add("hidden");
    runAction("apply", { confirm: true }, "apply-results", () => {
      document.getElementById("apply-results").innerHTML =
        '<p class="hint">Apply completed. Checking pod health…</p>';
      renderPodHealth();
    });
  });

  function renderPodHealth() {
    const namespace = namespaceEl.value.trim();
    fetch("/api/pod-health?namespace=" + encodeURIComponent(namespace))
      .then((r) => r.json().then((data) => ({ ok: r.ok, data })))
      .then(({ ok, data }) => {
        const el = document.getElementById("apply-results");
        if (!ok) {
          el.innerHTML = `<div class="error-panel">${escapeHtml(data.error || "Failed to check pod health.")}</div>`;
          return;
        }
        let html = '<div class="card"><h2 class="card-title">Pod Health After Apply</h2>';
        if (!data.pods.length) {
          html += '<p class="hint">No pods found in this namespace.</p>';
        } else {
          data.pods.forEach((p) => {
            const cls = p.healthy ? "dot-green" : "dot-red";
            html += `<div class="pod-health-row"><span>${escapeHtml(p.name)}</span>` +
              `<span><span class="dot ${cls}"></span> ${p.ready}/${p.total} — ${escapeHtml(p.phase)}</span></div>`;
          });
        }
        html += "</div>";
        el.innerHTML = html;
      });
  }

  // ---------------------------------------------------------------------
  // Verify
  // ---------------------------------------------------------------------

  document.getElementById("run-verify").addEventListener("click", () => {
    const payload = { namespace: namespaceEl.value.trim() };
    runAction("verify", payload, "verify-results", renderVerifyResults);
  });

  function badgeItem(label, info) {
    if (!info) return "";
    const cls = info.ok ? "badge-ok" : "badge-failed";
    const text = info.ok ? "OK" : "FAILED";
    const detail = info.total !== undefined ? `${info.ready}/${info.total}` : `${info.count} applied`;
    return (
      `<div class="badge-item">${escapeHtml(label)}<br>` +
      `<span class="status-badge-big ${cls}">${text}</span><br>${escapeHtml(detail)}</div>`
    );
  }

  function renderVerifyResults() {
    fetch("/api/verify-result")
      .then((r) => r.json())
      .then((data) => {
        const el = document.getElementById("verify-results");
        if (!data.available) {
          el.innerHTML = '<p class="hint">No verify-results.json found.</p>';
          return;
        }

        let html = '<div class="badge-row">';
        html += badgeItem("Pod Injection", data.pod_injection);
        html += badgeItem("NetworkPolicy", data.network_policies);
        html += badgeItem("AuthorizationPolicy", data.auth_policies);
        html += "</div>";

        html += `<div class="banner">${escapeHtml(data.note)}</div>`;
        html += `<div class="callout-box">Connectivity results are diagnostic only and do not affect the pass/fail verdict above — see the warning banner for why.</div>`;

        if (data.connectivity.length) {
          html +=
            '<table class="result-table"><thead><tr><th>Source</th><th>Destination</th>' +
            "<th>Port</th><th>Result</th></tr></thead><tbody>";
          data.connectivity.forEach((r) => {
            let cls = "text-amber";
            let tag = "";
            if (r.matches === true) {
              cls = "text-green";
              tag = " (expected)";
            } else if (r.matches === false) {
              cls = "text-red";
              tag = " (unexpected)";
            }
            html +=
              `<tr><td>${escapeHtml(r.src)}</td><td>${escapeHtml(r.dst)}</td><td>${r.port}</td>` +
              `<td class="${cls}">${escapeHtml(r.status_text)}${tag}</td></tr>`;
          });
          html += "</tbody></table>";
        }

        html += data.overall_ok
          ? '<div class="verdict verdict-ok">Zero Trust enforcement verified successfully.</div>'
          : '<div class="verdict verdict-fail">Zero Trust enforcement verification found issues.</div>';

        el.innerHTML = html;
      });
  }

  // ---------------------------------------------------------------------
  // Report
  // ---------------------------------------------------------------------

  document.getElementById("run-report").addEventListener("click", () => {
    const format = document.getElementById("report-format-html").checked ? "html" : "markdown";
    const payload = { namespace: namespaceEl.value.trim(), format };
    runAction("report", payload, "report-results", renderReportResults);
  });

  // Escaping rules for an HTML attribute value differ from tag content:
  // only `&` and the quote character delimiting the attribute need
  // escaping - `<`/`>` are literal text inside an attribute value, and
  // escaping them would corrupt the raw markup srcdoc is meant to render.
  function escapeAttr(s) {
    return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;");
  }

  function renderReportResults() {
    fetch("/api/report-result")
      .then((r) => r.json())
      .then((data) => {
        const el = document.getElementById("report-results");
        if (!data.available) {
          el.innerHTML = '<p class="hint">No report found.</p>';
          return;
        }
        if (data.format === "html") {
          // report.html is already a complete, self-contained document
          // (built server-side in ktmguard.py) - an iframe with srcdoc
          // renders it exactly as it would look opened directly as a
          // file, with its own styling isolated from the dashboard's.
          el.innerHTML =
            `<iframe class="report-iframe" srcdoc="${escapeAttr(data.html_document)}"></iframe>` +
            '<a class="download-btn" href="/api/report-download">Download .html</a>';
          return;
        }
        el.innerHTML =
          `<div class="report-html">${data.html}</div>` +
          '<a class="download-btn" href="/api/report-download">Download .md</a>';
      });
  }

  // ---------------------------------------------------------------------
  // Settings
  // ---------------------------------------------------------------------

  function refreshSettings() {
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data) => {
        document.getElementById("settings-server").textContent = data.server || "unknown";
        document.getElementById("settings-tls").innerHTML = data.insecure_skip_tls_verify
          ? '<span class="text-amber">Disabled (insecure-skip-tls-verify)</span>'
          : '<span class="text-green">Verified</span>';
        document.getElementById("settings-password-source").textContent =
          "Password source: " + data.password_source;
      });
  }

  document.getElementById("settings-test-connection").addEventListener("click", () => {
    const btn = document.getElementById("settings-test-connection");
    const resultEl = document.getElementById("settings-test-result");
    btn.disabled = true;
    resultEl.textContent = "Testing…";
    fetchJson("/api/test-connection", { method: "POST" })
      .then(({ data }) => {
        resultEl.textContent = data.ok
          ? `Connected — ${data.node_count != null ? data.node_count : "?"} node(s) found.`
          : "Failed: " + (data.error || "unknown error");
        resultEl.className = "hint " + (data.ok ? "text-green" : "text-red");
      })
      .finally(() => {
        btn.disabled = false;
      });
  });

  document.getElementById("settings-change-password").addEventListener("click", () => {
    const btn = document.getElementById("settings-change-password");
    const resultEl = document.getElementById("settings-password-result");
    const current = document.getElementById("settings-current-password").value;
    const next = document.getElementById("settings-new-password").value;
    btn.disabled = true;
    resultEl.textContent = "";
    fetchJson("/api/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: current, new_password: next }),
    })
      .then(({ ok, data }) => {
        if (ok) {
          resultEl.textContent = "Password changed successfully.";
          resultEl.className = "hint text-green";
          document.getElementById("settings-current-password").value = "";
          document.getElementById("settings-new-password").value = "";
        } else {
          resultEl.textContent = data.error || "Failed to change password.";
          resultEl.className = "hint text-red";
        }
      })
      .finally(() => {
        btn.disabled = false;
      });
  });

  // ---------------------------------------------------------------------
  // Initial page
  // ---------------------------------------------------------------------

  refreshOverview();
})();
