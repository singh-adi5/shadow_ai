(() => {
  "use strict";

  // ---------------------------------------------------------------------
  // Fixed category orders — identity follows the entity name, never its
  // rank in the current data (colors never repaint when filters change).
  // ---------------------------------------------------------------------
  const ENTITY_ORDER = [
    "CREDIT_CARD", "EMAIL_ADDRESS", "US_SSN", "GENERIC_PASSWORD",
    "API_KEY", "PHONE_NUMBER", "IBAN_CODE", "CRYPTO",
  ];
  const DEPARTMENT_ORDER = ["Engineering", "Sales", "Finance", "Marketing", "HR"];
  const STATUS_ORDER = ["NEW", "ACKNOWLEDGED", "RESOLVED"];

  const SEVERITY_CHIPS = [
    { key: "CRITICAL", label: "Critical", dbValues: ["CRITICAL", "BLOCK"] },
    { key: "WARNING",  label: "Warning",  dbValues: ["WARNING"] },
    { key: "INFO",     label: "Info",     dbValues: ["INFO"] },
  ];

  const SEVERITY_META = {
    CRITICAL: { color: "--status-critical", icon: "⛔", order: 0 },
    BLOCK:    { color: "--status-critical", icon: "⛔", order: 0 },
    WARNING:  { color: "--status-warning",  icon: "⚠",  order: 1 },
    INFO:     { color: "--status-good",     icon: "✓",  order: 2 },
  };

  const PAGE_SIZE = 25;
  const API_KEY_STORAGE = "shadow_ai_api_key";

  // ---------------------------------------------------------------------
  // Small DOM-safe helpers — build nodes via textContent, never innerHTML
  // string-concatenation, for anything that can contain data sourced from
  // a scan submission (user_id, department, destination_url, message).
  // Those fields pass through models.py's validators but are NOT HTML-
  // safe by construction (e.g. destination_url's path segment allows
  // arbitrary characters) — the dashboard is unauthenticated/public, so
  // rendering them unescaped would be a stored-XSS hole.
  // ---------------------------------------------------------------------
  function el(tag, opts = {}) {
    const node = document.createElement(tag);
    if (opts.className) node.className = opts.className;
    if (opts.text !== undefined) node.textContent = opts.text;
    if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, v);
    if (opts.style) Object.assign(node.style, opts.style);
    if (opts.onClick) node.addEventListener("click", opts.onClick);
    if (opts.children) for (const c of opts.children) node.appendChild(c);
    return node;
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function seriesColors(n) {
    const colors = [];
    for (let i = 1; i <= n; i++) colors.push(cssVar(`--series-${i}`));
    return colors;
  }

  // ---------------------------------------------------------------------
  // Filter state
  // ---------------------------------------------------------------------
  const state = {
    severity: new Set(),    // chip keys: CRITICAL / WARNING / INFO
    department: new Set(),
    entity_type: new Set(),
    status: new Set(),
    q: "",
    sort: "time_desc",
    offset: 0,
  };

  function buildParams(extra = {}) {
    const params = new URLSearchParams();
    for (const key of state.severity) {
      for (const v of SEVERITY_CHIPS.find((c) => c.key === key).dbValues) params.append("severity", v);
    }
    for (const v of state.department) params.append("department", v);
    for (const v of state.entity_type) params.append("entity_type", v);
    for (const v of state.status) params.append("status", v);
    if (state.q) params.set("q", state.q);
    for (const [k, v] of Object.entries(extra)) params.set(k, v);
    return params;
  }

  // ---------------------------------------------------------------------
  // Filter chip UI
  // ---------------------------------------------------------------------
  function renderChipGroup(container, label, chips, stateSet, onChange) {
    const group = el("div", { className: "filter-group" });
    group.appendChild(el("span", { className: "filter-group-label", text: label }));
    const row = el("div", { className: "chip-row" });
    for (const chip of chips) {
      const key = typeof chip === "string" ? chip : chip.key;
      const text = typeof chip === "string" ? chip : chip.label;
      const btn = el("button", {
        className: "chip" + (stateSet.has(key) ? " is-active" : ""),
        text,
        attrs: { type: "button", "aria-pressed": String(stateSet.has(key)) },
        onClick: () => {
          if (stateSet.has(key)) stateSet.delete(key); else stateSet.add(key);
          state.offset = 0;
          onChange();
        },
      });
      row.appendChild(btn);
    }
    group.appendChild(row);
    container.appendChild(group);
  }

  function renderFilterBar(onChange) {
    const container = document.getElementById("filter-groups");
    container.innerHTML = "";
    renderChipGroup(container, "Severity", SEVERITY_CHIPS, state.severity, onChange);
    renderChipGroup(container, "Department", DEPARTMENT_ORDER, state.department, onChange);
    renderChipGroup(container, "Entity type", ENTITY_ORDER, state.entity_type, onChange);
    renderChipGroup(container, "Status", STATUS_ORDER, state.status, onChange);
  }

  // ---------------------------------------------------------------------
  // Charts + stat tiles + severity summary
  // ---------------------------------------------------------------------
  let entityChart = null;
  let departmentChart = null;

  function orderedCounts(counts, order) {
    const labels = [...order];
    for (const key of Object.keys(counts)) if (!labels.includes(key)) labels.push(key);
    return { labels, values: labels.map((l) => counts[l] || 0) };
  }

  function renderBarChart(canvasId, existingRef, counts, colorOrder) {
    const { labels, values } = orderedCounts(counts, colorOrder);
    const palette = seriesColors(8);
    const colors = labels.map((_, i) => palette[i % palette.length]);
    const ctx = document.getElementById(canvasId).getContext("2d");
    if (existingRef) existingRef.destroy();
    return new Chart(ctx, {
      type: "bar",
      data: { labels, datasets: [{ label: "Count", data: values, backgroundColor: colors, borderRadius: 4, maxBarThickness: 28 }] },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0, color: cssVar("--text-muted") }, grid: { color: cssVar("--gridline") } },
          y: { ticks: { color: cssVar("--text-secondary") }, grid: { display: false } },
        },
      },
    });
  }

  function renderSeverityList(counts) {
    const container = document.getElementById("severity-list");
    container.innerHTML = "";
    const display = { CRITICAL: (counts.CRITICAL || 0) + (counts.BLOCK || 0), WARNING: counts.WARNING || 0, INFO: counts.INFO || 0 };
    const total = Object.values(display).reduce((a, b) => a + b, 0) || 1;
    for (const level of ["CRITICAL", "WARNING", "INFO"]) {
      const meta = SEVERITY_META[level];
      const count = display[level];
      const pct = Math.round((count / total) * 100);
      const row = el("div", { className: "severity-row", attrs: { role: "listitem" } });
      row.appendChild(el("span", { className: "severity-badge", text: `${meta.icon} ${level}`, style: { color: cssVar(meta.color) } }));
      const track = el("span", { className: "severity-bar-track" });
      track.appendChild(el("span", { className: "severity-bar-fill", style: { width: `${pct}%`, background: cssVar(meta.color) } }));
      row.appendChild(track);
      row.appendChild(el("span", { className: "severity-count", text: String(count) }));
      container.appendChild(row);
    }
  }

  function renderStatTiles(totals, bufferSize, matchedCount) {
    const container = document.getElementById("stat-tiles");
    const tiles = [
      { label: "Logs scanned (all time)", value: totals.scanned },
      { label: "Threats detected (all time)", value: totals.threats },
      { label: "Critical alerts (all time)", value: totals.critical },
      { label: "Alerts matching filters", value: matchedCount },
    ];
    container.innerHTML = "";
    for (const t of tiles) {
      container.appendChild(el("div", {
        className: "stat-tile",
        children: [
          el("div", { className: "value", text: t.value.toLocaleString() }),
          el("div", { className: "label", text: t.label }),
        ],
      }));
    }
  }

  function renderStatusPills(data) {
    const container = document.getElementById("status-pills");
    const pills = [
      { label: data.presidio_active ? "Presidio: active" : "Presidio: regex fallback", ok: data.presidio_active },
      { label: `Rate limiter: ${data.rate_limiter_backend}`, ok: data.rate_limiter_backend === "redis" },
      { label: data.auth_enabled ? "Auth: enabled" : "Auth: disabled (demo mode)", ok: data.auth_enabled },
    ];
    container.innerHTML = "";
    for (const p of pills) {
      container.appendChild(el("span", {
        className: "pill",
        children: [
          el("span", { className: "pill-dot", style: { background: p.ok ? cssVar("--status-good") : cssVar("--status-warning") } }),
          document.createTextNode(p.label),
        ],
      }));
    }
  }

  // ---------------------------------------------------------------------
  // Alerts table (safe rendering — textContent only for data fields)
  // ---------------------------------------------------------------------
  function statusBadge(status) {
    return el("span", {
      className: `status-badge status-${(status || "new").toLowerCase()}`,
      text: status || "NEW",
    });
  }

  function severityBadge(level) {
    const meta = SEVERITY_META[level] || SEVERITY_META.INFO;
    return el("span", {
      className: "badge",
      text: `${meta.icon} ${level}`,
      style: { background: cssVar(meta.color) },
    });
  }

  function renderAlertsTable(items) {
    const tbody = document.getElementById("alerts-tbody");
    const empty = document.getElementById("alerts-empty");
    tbody.innerHTML = "";

    if (!items.length) {
      empty.hidden = false;
      return;
    }
    empty.hidden = true;

    for (const a of items) {
      const ts = (a.timestamp || "").replace("T", " ").replace("Z", "");
      const tr = el("tr", {
        attrs: { tabindex: "0", role: "button", "aria-label": `Open alert ${a.alert_id}` },
        onClick: () => openDetail(a.alert_id),
      });
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter") openDetail(a.alert_id); });

      const statusTd = el("td"); statusTd.appendChild(statusBadge(a.status));
      const severityTd = el("td"); severityTd.appendChild(severityBadge(a.threat_level));
      const userTd = el("td", { text: `${a.user_id || ""} ` });
      userTd.appendChild(el("span", { text: `/ ${a.department || ""}`, style: { color: "var(--text-muted)" } }));

      tr.appendChild(statusTd);
      tr.appendChild(severityTd);
      tr.appendChild(el("td", { text: ts }));
      tr.appendChild(userTd);
      tr.appendChild(el("td", { className: "dest-cell", text: a.destination_url || "" }));
      tr.appendChild(el("td", { className: "entities-cell", text: (a.entity_types || []).join(", ") || "—" }));
      tr.appendChild(el("td", { text: a.threat_score ?? "—" }));
      tr.appendChild(el("td", { text: a.action || "" }));
      tbody.appendChild(tr);
    }
  }

  function renderPagination(total, offset, limit) {
    const container = document.getElementById("pagination");
    container.innerHTML = "";
    const from = total === 0 ? 0 : offset + 1;
    const to = Math.min(offset + limit, total);
    container.appendChild(el("span", { text: `Showing ${from}-${to} of ${total}` }));
    container.appendChild(el("button", {
      className: "btn btn-ghost btn-small", text: "‹ Prev",
      attrs: offset <= 0 ? { disabled: "disabled" } : {},
      onClick: () => { state.offset = Math.max(0, offset - limit); refreshAlertsOnly(); },
    }));
    container.appendChild(el("button", {
      className: "btn btn-ghost btn-small", text: "Next ›",
      attrs: offset + limit >= total ? { disabled: "disabled" } : {},
      onClick: () => { state.offset = offset + limit; refreshAlertsOnly(); },
    }));
  }

  // ---------------------------------------------------------------------
  // Detail panel — clickable + linkable (location.hash = alert id)
  // ---------------------------------------------------------------------
  function detailField(label, value) {
    return el("div", { className: "detail-field", children: [
      el("span", { className: "k", text: label }),
      el("span", { className: "v", text: value ?? "—" }),
    ]});
  }

  function apiKey() { return localStorage.getItem(API_KEY_STORAGE) || ""; }

  async function setAlertStatus(alertId, newStatus) {
    const key = apiKey();
    const headers = { "Content-Type": "application/json" };
    if (key) headers["X-API-Key"] = key;
    const res = await fetch(`/dashboard/alerts/${encodeURIComponent(alertId)}`, {
      method: "PATCH", headers, body: JSON.stringify({ status: newStatus }),
    });
    if (res.status === 401) throw new Error("API key required — set it via the 🔑 API key button above.");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function openDetail(alertId) {
    location.hash = `alert=${encodeURIComponent(alertId)}`;
    const panel = document.getElementById("detail-panel");
    const overlay = document.getElementById("detail-overlay");
    const body = document.getElementById("detail-body");
    const title = document.getElementById("detail-title");

    body.innerHTML = "";
    body.appendChild(el("p", { text: "Loading…" }));
    panel.hidden = false;
    overlay.hidden = false;

    try {
      const res = await fetch(`/dashboard/alerts/${encodeURIComponent(alertId)}`);
      if (!res.ok) throw new Error(res.status === 404 ? "Alert not found (it may have aged out of the retention window)." : `HTTP ${res.status}`);
      const a = await res.json();

      title.textContent = `Alert ${a.alert_id}`;
      body.innerHTML = "";
      body.appendChild(detailField("Severity", a.threat_level));
      body.appendChild(detailField("Timestamp (UTC)", a.timestamp));
      body.appendChild(detailField("User", a.user_id));
      body.appendChild(detailField("Department", a.department));
      body.appendChild(detailField("Destination", a.destination_url));
      body.appendChild(detailField("Entities", (a.entity_types || []).join(", ") || "None"));
      body.appendChild(detailField("Threat score", `${a.threat_score ?? "—"} / 100`));
      body.appendChild(detailField("Recommended action", a.action));
      body.appendChild(detailField("Message", a.message));
      body.appendChild(detailField("Remediation", a.remediation));
      body.appendChild(detailField("Log ID", a.log_id));

      const statusRow = el("div", { className: "detail-field" });
      statusRow.appendChild(el("span", { className: "k", text: "Status" }));
      const actions = el("div", { className: "status-actions" });
      for (const s of STATUS_ORDER) {
        actions.appendChild(el("button", {
          className: "btn btn-small" + (a.status === s ? " is-active" : ""),
          text: s,
          onClick: async (e) => {
            e.target.disabled = true;
            try {
              await setAlertStatus(a.alert_id, s);
              openDetail(a.alert_id);
              refreshAlertsOnly();
            } catch (err) {
              alert(err.message);
            } finally {
              e.target.disabled = false;
            }
          },
        }));
      }
      statusRow.appendChild(actions);
      body.appendChild(statusRow);

      const copyBtn = el("button", {
        className: "btn btn-ghost btn-small", text: "Copy link to this alert",
        onClick: async () => {
          const url = `${location.origin}${location.pathname}#alert=${encodeURIComponent(a.alert_id)}`;
          try { await navigator.clipboard.writeText(url); copyBtn.textContent = "Copied!"; setTimeout(() => (copyBtn.textContent = "Copy link to this alert"), 1500); }
          catch { prompt("Copy this link:", url); }
        },
      });
      body.appendChild(copyBtn);
    } catch (err) {
      body.innerHTML = "";
      body.appendChild(el("p", { text: err.message }));
    }
  }

  function closeDetail() {
    document.getElementById("detail-panel").hidden = true;
    document.getElementById("detail-overlay").hidden = true;
    history.replaceState(null, "", location.pathname + location.search);
  }

  // ---------------------------------------------------------------------
  // Data fetch + orchestration
  // ---------------------------------------------------------------------
  async function fetchStats() {
    const res = await fetch(`/dashboard/stats?${buildParams()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function fetchAlerts() {
    const params = buildParams({ sort: state.sort, limit: PAGE_SIZE, offset: state.offset });
    const res = await fetch(`/dashboard/alerts?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function refreshAlertsOnly() {
    try {
      const data = await fetchAlerts();
      renderAlertsTable(data.items);
      renderPagination(data.total, data.offset, data.limit);
      document.getElementById("table-count-label").textContent = `(${data.total} match current filters)`;
    } catch (err) {
      console.error("Alerts refresh failed:", err);
    }
  }

  async function refreshAll() {
    try {
      const [stats, alerts] = await Promise.all([fetchStats(), fetchAlerts()]);
      renderStatusPills(stats);
      renderStatTiles(stats.totals, stats.alert_buffer_size, stats.matched_count);
      renderSeverityList(stats.severity_counts || {});
      entityChart = renderBarChart("chart-entities", entityChart, stats.entity_counts || {}, ENTITY_ORDER);
      departmentChart = renderBarChart("chart-departments", departmentChart, stats.department_counts || {}, DEPARTMENT_ORDER);
      renderAlertsTable(alerts.items);
      renderPagination(alerts.total, alerts.offset, alerts.limit);
      document.getElementById("table-count-label").textContent = `(${alerts.total} match current filters)`;
    } catch (err) {
      console.error("Dashboard refresh failed:", err);
    }
  }

  function onFilterChange() {
    renderFilterBar(onFilterChange);
    refreshAll();
  }

  async function simulate() {
    const btn = document.getElementById("btn-simulate");
    const count = document.getElementById("sim-count").value;
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = "Generating…";
    try {
      const res = await fetch(`/dashboard/simulate?count=${encodeURIComponent(count)}`, { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await refreshAll();
    } catch (err) {
      alert("Failed to generate demo traffic — see console for details.");
      console.error(err);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  }

  let debounceTimer = null;
  function onSearchInput(e) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      state.q = e.target.value.trim();
      state.offset = 0;
      refreshAll();
    }, 300);
  }

  let autoRefreshTimer = null;
  function setAutoRefresh(enabled) {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = enabled ? setInterval(refreshAll, 8000) : null;
  }

  // ---------------------------------------------------------------------
  // Wire up
  // ---------------------------------------------------------------------
  document.getElementById("btn-simulate").addEventListener("click", simulate);
  document.getElementById("btn-refresh").addEventListener("click", refreshAll);
  document.getElementById("auto-refresh").addEventListener("change", (e) => setAutoRefresh(e.target.checked));
  document.getElementById("search-input").addEventListener("input", onSearchInput);
  document.getElementById("sort-select").addEventListener("change", (e) => { state.sort = e.target.value; state.offset = 0; refreshAlertsOnly(); });
  document.getElementById("btn-clear-filters").addEventListener("click", () => {
    state.severity.clear(); state.department.clear(); state.entity_type.clear(); state.status.clear();
    state.q = ""; state.offset = 0;
    document.getElementById("search-input").value = "";
    onFilterChange();
  });
  document.getElementById("detail-close").addEventListener("click", closeDetail);
  document.getElementById("detail-overlay").addEventListener("click", closeDetail);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetail(); });

  const apikeyBox = document.getElementById("apikey-box");
  document.getElementById("btn-apikey").addEventListener("click", () => {
    apikeyBox.hidden = !apikeyBox.hidden;
    if (!apikeyBox.hidden) document.getElementById("apikey-input").value = apiKey();
  });
  document.getElementById("btn-apikey-save").addEventListener("click", () => {
    const v = document.getElementById("apikey-input").value.trim();
    if (v) localStorage.setItem(API_KEY_STORAGE, v);
    apikeyBox.hidden = true;
  });
  document.getElementById("btn-apikey-clear").addEventListener("click", () => {
    localStorage.removeItem(API_KEY_STORAGE);
    document.getElementById("apikey-input").value = "";
  });

  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", refreshAll);
  }

  renderFilterBar(onFilterChange);
  refreshAll();
  setAutoRefresh(document.getElementById("auto-refresh").checked);

  const hashMatch = /alert=([^&]+)/.exec(location.hash);
  if (hashMatch) openDetail(decodeURIComponent(hashMatch[1]));
})();
