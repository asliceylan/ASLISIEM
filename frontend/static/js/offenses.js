// Page-local, multi-select tenant filter for Offenses ONLY -- unlike Log
// Activity's/Rules' single-select window.logActivityTenant/window.
// rulesTenant, this holds an ARRAY of tenant ids (empty array = "All
// Tenants", always available). No other page reads or is affected by this.
window.offensesTenantIds = [];
let offensesTenantFilterRestoredFromUrl = false;

function restoreOffensesTenantIdsFromUrl() {
  if (offensesTenantFilterRestoredFromUrl) return;
  offensesTenantFilterRestoredFromUrl = true;
  const param = new URLSearchParams(location.hash.slice(1)).get("tenant_ids");
  if (!param) return;
  window.offensesTenantIds = param.split(",").map(s => parseInt(s, 10)).filter(n => !isNaN(n));
}

function renderOffensesTenantFilter() {
  const el = document.getElementById("offenses-tenant-filter");
  if (!el) return;
  if (!window.currentSession || window.currentSession.role !== "full_admin") {
    el.innerHTML = ""; // a Tenant Admin has only one tenant -- nothing to filter
    return;
  }
  restoreOffensesTenantIdsFromUrl();
  renderTenantMultiSelect(el, {
    tenants: window.allTenants || [],
    selectedIds: window.offensesTenantIds,
    onChange: onOffensesTenantFilterChange,
  });
}

// "Add Filter" builder state -- an array of {field,operator,value} objects,
// AND'd together server-side (see filter_service.OFFENSE_FILTERABLE_FIELDS
// and offense_service.list_offenses). Independent of, and intersected
// (AND'd) with, window.offensesTenantIds above -- both are sent to the
// backend on every load.
window.offensesFilters = [];
let offensesFiltersRestoredFromUrl = false;

const OFFENSE_STATUS_OPTIONS = [
  { value: "OPEN", label: "Open" },
  { value: "CLOSED", label: "Closed" },
];
const OFFENSE_SEVERITY_OPTIONS = [
  { value: "Low", label: "Low" },
  { value: "Medium", label: "Medium" },
  { value: "High", label: "High" },
  { value: "Critical", label: "Critical" },
];

function offenseFilterFields() {
  return [
    { field: "status", label: "Status", type: "closed", options: OFFENSE_STATUS_OPTIONS },
    { field: "severity", label: "Severity", type: "closed", options: OFFENSE_SEVERITY_OPTIONS },
    { field: "source_ip", label: "Source IP", type: "free" },
    { field: "username", label: "Username", type: "free" },
    { field: "tenant_id", label: "Tenant", type: "closed", options: (window.allTenants || []).map(t => ({ value: t.id, label: t.name })) },
    { field: "created_at", label: "Created At", type: "free" },
  ];
}

function restoreOffensesFiltersFromUrl() {
  if (offensesFiltersRestoredFromUrl) return;
  offensesFiltersRestoredFromUrl = true;
  const param = new URLSearchParams(location.hash.slice(1)).get("filters");
  if (!param) return;
  try {
    window.offensesFilters = JSON.parse(param); // URLSearchParams.get() already decoded it
  } catch (err) {
    window.offensesFilters = [];
  }
}

function renderOffensesFilterBuilder() {
  const el = document.getElementById("offenses-filter-builder");
  if (!el) return;
  restoreOffensesFiltersFromUrl();
  renderFilterBuilder(el, {
    fieldConfigs: offenseFilterFields(),
    filters: window.offensesFilters,
    onChange: onOffensesFiltersChange,
  });
}

function onOffensesFiltersChange(filters) {
  window.offensesFilters = filters;
  updateOffensesHash();
  loadOffenses();
}

function onOffensesTenantFilterChange(selectedIds) {
  window.offensesTenantIds = selectedIds;
  updateOffensesHash();
  loadOffenses();
}

// Shared by both onChange handlers above -- rebuilds the full hash from
// current tenant/filter state each time so neither overwrites the other's
// param (each one only knows its own piece otherwise).
function updateOffensesHash() {
  // Built via URLSearchParams (not manual template-string concatenation)
  // so .toString() percent-encodes the JSON filters value exactly once --
  // URLSearchParams.get() on restore decodes it exactly once too.
  const params = new URLSearchParams();
  if (window.offensesTenantIds.length) params.set("tenant_ids", window.offensesTenantIds.join(","));
  if (window.offensesFilters.length) params.set("filters", JSON.stringify(window.offensesFilters));
  const qs = params.toString();
  const hash = qs ? `#page=offenses&${qs}` : "#page=offenses";
  if (location.hash !== hash) history.replaceState(null, "", hash);
}

async function loadOffenses() {
  renderOffensesTenantFilter();
  renderOffensesFilterBuilder();
  const isFullAdmin = window.currentSession?.role === "full_admin";

  const params = new URLSearchParams();
  if (window.offensesTenantIds.length) params.set("tenant_ids", window.offensesTenantIds.join(","));
  if (window.offensesFilters.length) params.set("filters", JSON.stringify(window.offensesFilters));
  const offenses = await api(`/offenses?${params.toString()}`);
  renderOffensesTable(offenses, isFullAdmin);
}

function renderOffensesTable(offenses, isFullAdmin) {
  const el = document.getElementById("offenses-table");
  if (!offenses.length) {
    el.innerHTML = `<div class="empty-state">No offenses found.</div>`;
    return;
  }
  const tenantName = (tenantId) => window.allTenants?.find(t => t.id === tenantId)?.name || `Tenant ${tenantId}`;
  el.innerHTML = `<table>
    <tr><th>ID</th><th>Name</th>${isFullAdmin ? "<th>Tenant</th>" : ""}<th>Severity</th><th>Status</th><th>Event Count</th><th>Source IP</th><th>Username</th><th>Created</th></tr>
    ${offenses.map(o => `
      <tr class="clickable" onclick="openOffenseDetail(${o.id})">
        <td>${o.id}</td>
        <td>${escapeHtml(o.title)}</td>
        ${isFullAdmin ? `<td>${escapeHtml(tenantName(o.tenant_id))}</td>` : ""}
        <td><span class="badge ${o.severity}">${o.severity}</span></td>
        <td><span class="badge ${o.status}">${o.status}</span></td>
        <td>${o.event_count}</td>
        <td>${escapeHtml(o.source_ip)}</td>
        <td>${escapeHtml(o.username)}</td>
        <td>${fmtDate(o.created_at)}</td>
      </tr>`).join("")}
  </table>`;
}

async function openOffenseDetail(offenseId) {
  const offense = await api(`/offenses/${offenseId}`);
  showPage("offense-detail");
  renderOffenseDetail(offense);
}

function renderOffenseDetail(o) {
  const mitreHtml = (o.mitre || []).map(m => mitreEntryToChipHtml(m)).join("") ||
    `<span style="color:var(--text-dim); font-size:12px;">No MITRE mapping defined for this rule.</span>`;

  const eventsHtml = o.events.length ? `
    <table>
      <tr><th>Time</th><th>Event ID</th><th>Event Name</th><th>Source IP</th><th>Username</th></tr>
      ${o.events.map(e => `
        <tr class="clickable" onclick="showRawEvent(${e.id})">
          <td>${fmtDate(e.timestamp)}</td><td>${escapeHtml(e.event_id)}</td>
          <td>${escapeHtml(e.event_name)}</td><td>${escapeHtml(e.source_ip)}</td><td>${escapeHtml(e.username)}</td>
        </tr>`).join("")}
    </table>` : `<div class="empty-state">No linked events.</div>`;

  document.getElementById("offense-detail-content").innerHTML = `
    <h2>#${o.id} ${escapeHtml(o.title)}</h2>
    <p style="color:var(--text-dim);">${escapeHtml(o.description || "")}</p>
    <div class="detail-grid">
      <div class="item"><div class="k">Severity</div><div class="v"><span class="badge ${o.severity}">${o.severity}</span></div></div>
      <div class="item"><div class="k">Status</div><div class="v"><span class="badge ${o.status}">${o.status}</span></div></div>
      <div class="item"><div class="k">Triggered Rule</div><div class="v">${escapeHtml(o.rule_name)}</div></div>
      <div class="item"><div class="k">Source IP</div><div class="v">${escapeHtml(o.source_ip)}</div></div>
      <div class="item"><div class="k">Username</div><div class="v">${escapeHtml(o.username)}</div></div>
      <div class="item"><div class="k">Event Count</div><div class="v">${o.event_count}</div></div>
      <div class="item"><div class="k">First Seen</div><div class="v">${fmtDate(o.first_seen)}</div></div>
      <div class="item"><div class="k">Last Seen</div><div class="v">${fmtDate(o.last_seen)}</div></div>
      <div class="item"><div class="k">Created</div><div class="v">${fmtDate(o.created_at)}</div></div>
    </div>
    <h3>MITRE ATT&amp;CK Mapping</h3>
    <div style="margin-bottom:16px;">${mitreHtml}</div>
    <div style="margin-bottom:12px;">
      <button onclick="toggleOffenseStatus(${o.id}, '${o.status === 'OPEN' ? 'CLOSED' : 'OPEN'}')">
        Mark as ${o.status === 'OPEN' ? 'Closed' : 'Open'}
      </button>
    </div>
    <h3>Related Events</h3>
    ${eventsHtml}
  `;
}

async function toggleOffenseStatus(offenseId, newStatus) {
  await api(`/offenses/${offenseId}/status`, { method: "PUT", body: JSON.stringify({ status: newStatus }) });
  openOffenseDetail(offenseId);
}

document.getElementById("back-to-offenses")?.addEventListener("click", () => showPage("offenses"));

window.loadOffenses = loadOffenses;
window.openOffenseDetail = openOffenseDetail;
window.toggleOffenseStatus = toggleOffenseStatus;
