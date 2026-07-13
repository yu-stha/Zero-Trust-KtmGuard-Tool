(function () {
  "use strict";

  const state = { eventSource: null };
  const terminalEl = document.getElementById("terminal");
  const namespaceEl = document.getElementById("namespace");

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // ---------------------------------------------------------------------
  // Sidebar navigation
  // ---------------------------------------------------------------------

  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const action = btn.dataset.action;
      document.querySelectorAll(".action-panel").forEach((p) => p.classList.add("hidden"));
      document.getElementById("panel-" + action).classList.remove("hidden");
    });
  });

  // ---------------------------------------------------------------------
  // Cluster status
  // ---------------------------------------------------------------------

  function refreshClusterStatus() {
    fetch("/api/cluster-status")
      .then((r) => r.json())
      .then((data) => {
        document.getElementById("cluster-dot").className =
          "dot " + (data.connected ? "dot-green" : "dot-red");
        document.getElementById("cluster-text").textContent =
          data.connected ? "cluster reachable" : "cluster unreachable";
      })
      .catch(() => {
        document.getElementById("cluster-dot").className = "dot dot-red";
        document.getElementById("cluster-text").textContent = "cluster unreachable";
      });
  }
  refreshClusterStatus();
  setInterval(refreshClusterStatus, 20000);

  // ---------------------------------------------------------------------
  // Terminal / SSE streaming / run orchestration
  // ---------------------------------------------------------------------

  function resetTerminal() {
    terminalEl.classList.remove("error-border");
    terminalEl.textContent = "";
  }

  function appendTerminalLine(line) {
    terminalEl.textContent += line + "\n";
    terminalEl.scrollTop = terminalEl.scrollHeight;
  }

  function setButtonsDisabled(disabled) {
    document.querySelectorAll(".run-btn").forEach((b) => (b.disabled = disabled));
  }

  function streamOutput(onDone) {
    if (state.eventSource) {
      state.eventSource.close();
    }
    const es = new EventSource("/api/stream?since=0");
    state.eventSource = es;
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      appendTerminalLine(data.line);
    };
    es.addEventListener("done", (e) => {
      es.close();
      state.eventSource = null;
      const data = JSON.parse(e.data);
      if (data.returncode !== 0) {
        terminalEl.classList.add("error-border");
      }
      onDone(data.returncode);
    });
    es.onerror = () => {
      es.close();
      state.eventSource = null;
      appendTerminalLine("[dashboard] Connection to server lost.");
      terminalEl.classList.add("error-border");
      setButtonsDisabled(false);
    };
  }

  function runAction(action, payload, resultsElId, onSuccess) {
    resetTerminal();
    const resultsEl = document.getElementById(resultsElId);
    if (resultsEl) resultsEl.innerHTML = "";
    setButtonsDisabled(true);

    fetch("/api/run/" + action, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
      .then((r) => r.json().then((data) => ({ ok: r.ok, data })))
      .then(({ ok, data }) => {
        if (!ok) {
          appendTerminalLine("[dashboard] " + data.error);
          terminalEl.classList.add("error-border");
          if (resultsEl) {
            resultsEl.innerHTML = `<div class="error-panel">${escapeHtml(data.error)}</div>`;
          }
          setButtonsDisabled(false);
          return;
        }
        streamOutput((returncode) => {
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
        appendTerminalLine("[dashboard] Request failed: " + err);
        terminalEl.classList.add("error-border");
        setButtonsDisabled(false);
      });
  }

  // ---------------------------------------------------------------------
  // Scan
  // ---------------------------------------------------------------------

  document.getElementById("run-scan").addEventListener("click", () => {
    const payload = {
      namespace: namespaceEl.value.trim(),
      prometheus: document.getElementById("prometheus").value.trim(),
      tap: document.getElementById("tap").checked,
      tap_duration: document.getElementById("tap-duration").value,
    };
    runAction("scan", payload, "scan-results", renderScanResults);
  });

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
        let html = "";
        if (data.manual_review_required) {
          html += '<div class="banner">Manual review flagged during scan.</div>';
        }
        html +=
          '<table class="result-table"><thead><tr><th>Source</th><th>Destination</th></tr></thead><tbody>';
        data.edges.forEach((e) => {
          html += `<tr><td>${escapeHtml(e.src)}</td><td>${escapeHtml(e.dst)}</td></tr>`;
        });
        html += "</tbody></table>";
        el.innerHTML = html;
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
        el.innerHTML =
          '<p class="hint">Dry run - see YAML in the output above. No files were written.</p>';
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
          if (value && /^-?\d+(\.\d+)?$/.test(value)) {
            value = '<span class="y-num">' + value + "</span>";
          } else if (value) {
            value = '<span class="y-str">' + value + "</span>";
          }
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
        let html = "";
        names.forEach((name) => {
          const content = data.files[name];
          if (content === undefined) return;
          html += `
            <div class="yaml-panel">
              <div class="yaml-panel-header" data-panel="${escapeHtml(name)}">
                <span>${escapeHtml(name)}</span>
                <span class="yaml-panel-toggle">&#9656;</span>
              </div>
              <div class="yaml-panel-body">${highlightYaml(content)}</div>
            </div>`;
        });
        el.innerHTML = html || '<p class="hint">No generated files found.</p>';
        el.querySelectorAll(".yaml-panel-header").forEach((header) => {
          header.addEventListener("click", () => {
            const panel = header.closest(".yaml-panel");
            panel.classList.toggle("open");
            header.querySelector(".yaml-panel-toggle").innerHTML = panel.classList.contains("open")
              ? "&#9662;"
              : "&#9656;";
          });
        });
      });
  }

  // ---------------------------------------------------------------------
  // Apply
  // ---------------------------------------------------------------------

  const applyModal = document.getElementById("apply-modal");
  document.getElementById("run-apply").addEventListener("click", () => {
    applyModal.classList.remove("hidden");
  });
  document.getElementById("apply-cancel").addEventListener("click", () => {
    applyModal.classList.add("hidden");
  });
  document.getElementById("apply-confirm").addEventListener("click", () => {
    applyModal.classList.add("hidden");
    runAction("apply", { confirm: true }, "apply-results", () => {
      document.getElementById("apply-results").innerHTML =
        '<p class="hint">Apply completed. Run Verify to check enforcement.</p>';
    });
  });

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
    const detail =
      info.total !== undefined ? `${info.ready}/${info.total}` : `${info.count} applied`;
    return (
      `<div class="badge-item">${escapeHtml(label)}<br>` +
      `<span class="badge ${cls}">${text}</span>${escapeHtml(detail)}</div>`
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
        html += badgeItem("Linkerd injection", data.pod_injection);
        html += badgeItem("NetworkPolicy", data.network_policies);
        html += badgeItem("Auth policies", data.auth_policies);
        html += "</div>";

        html += `<div class="banner">${escapeHtml(data.note)}</div>`;

        if (data.connectivity.length) {
          html +=
            '<table class="result-table"><thead><tr><th>Source</th><th>Destination</th>' +
            "<th>Port</th><th>Result</th></tr></thead><tbody>";
          data.connectivity.forEach((r) => {
            let cls = "text-yellow";
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
    const payload = { namespace: namespaceEl.value.trim() };
    runAction("report", payload, "report-results", renderReportResults);
  });

  function renderReportResults() {
    fetch("/api/report-result")
      .then((r) => r.json())
      .then((data) => {
        const el = document.getElementById("report-results");
        if (!data.available) {
          el.innerHTML = '<p class="hint">No report found.</p>';
          return;
        }
        el.innerHTML =
          `<div class="report-html">${data.html}</div>` +
          '<a class="download-btn" href="/api/report-download">Download .md</a>';
      });
  }
})();
