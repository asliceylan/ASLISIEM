// Page-local tenant context for Log Activity ONLY -- {id, name} for a
// specific tenant, or null for "All Tenants" (unscoped). No other page
// reads or is affected by this; see app.js for why there is deliberately
// no app-wide equivalent. imports.js reads this too, to default the
// "Import into Tenant" picker to whatever tenant is active here.
window.logActivityTenant = null;
let logActivityTenantRestoredFromUrl = false;

function restoreLogActivityTenantFromUrl() {
  if (logActivityTenantRestoredFromUrl) return;
  logActivityTenantRestoredFromUrl = true;
  const tenantParam = new URLSearchParams(location.hash.slice(1)).get("tenant");
  if (!tenantParam || !window.allTenants?.length) return;
  const id = parseInt(tenantParam, 10);
  const known = window.allTenants.find(t => t.id === id);
  if (known) window.logActivityTenant = { id: known.id, name: known.name };
}

function renderLogActivityTenantCards() {
  const el = document.getElementById("log-activity-tenant-cards");
  if (!el) return;
  if (!window.currentSession || window.currentSession.role !== "full_admin") {
    el.innerHTML = ""; // a Tenant Admin has only one tenant -- nothing to pick
    return;
  }
  restoreLogActivityTenantFromUrl();
  renderTenantSingleSelect(el, {
    tenants: window.allTenants || [],
    selectedId: window.logActivityTenant?.id ?? null,
    onSelect: selectLogActivityTenant,
  });
}

// "Add Filter" builder state -- an array of {field,operator,value} objects,
// AND'd together server-side (see filter_service.EVENT_FILTERABLE_FIELDS
// and event_service.query_events). Independent of, and intersected (AND'd)
// with, window.logActivityTenant above. filter-search/filter-source (a
// multi-field OR quick-search, and the import/simulator source toggle) are
// separate, pre-existing concepts and are NOT folded into this builder.
window.eventsFilters = [];
let eventsFiltersRestoredFromUrl = false;

const EVENT_DEVICE_TYPE_OPTIONS = ["firewall", "router", "switch", "dmz_web", "waf", "dmz_db", "dmz_mail", "internal_host"]
  .map(v => ({ value: v, label: v }));
const EVENT_LOG_FORMAT_OPTIONS = ["cef", "syslog", "access_log", "winevent", "unknown"]
  .map(v => ({ value: v, label: v }));

function eventFilterFields() {
  return [
    { field: "event_id", label: "Event ID", type: "free" },
    { field: "event_name", label: "Event Name", type: "free" },
    { field: "source_ip", label: "Source IP", type: "free" },
    { field: "source_port", label: "Source Port", type: "free" },
    { field: "destination_ip", label: "Destination IP", type: "free" },
    { field: "destination_port", label: "Destination Port", type: "free" },
    { field: "username", label: "Username", type: "free" },
    { field: "process_name", label: "Process Name", type: "free" },
    { field: "timestamp", label: "Timestamp", type: "free" },
    { field: "device_type", label: "Device Type", type: "closed", options: EVENT_DEVICE_TYPE_OPTIONS },
    { field: "log_format", label: "Log Format", type: "closed", options: EVENT_LOG_FORMAT_OPTIONS },
    { field: "tenant_id", label: "Tenant", type: "closed", options: (window.allTenants || []).map(t => ({ value: t.id, label: t.name })) },
    { field: "Path", label: "Path", type: "free" },
  ];
}

function restoreEventsFiltersFromUrl() {
  if (eventsFiltersRestoredFromUrl) return;
  eventsFiltersRestoredFromUrl = true;
  const param = new URLSearchParams(location.hash.slice(1)).get("filters");
  if (!param) return;
  try {
    window.eventsFilters = JSON.parse(param); // URLSearchParams.get() already decoded it
  } catch (err) {
    window.eventsFilters = [];
  }
}

function renderEventsFilterBuilder() {
  const el = document.getElementById("events-filter-builder");
  if (!el) return;
  restoreEventsFiltersFromUrl();
  renderFilterBuilder(el, {
    fieldConfigs: eventFilterFields(),
    filters: window.eventsFilters,
    onChange: onEventsFiltersChange,
  });
}

function onEventsFiltersChange(filters) {
  window.eventsFilters = filters;
  updateLogActivityHash();
  loadEvents();
}

function selectLogActivityTenant(tenantId) {
  const known = tenantId === null ? null : window.allTenants.find(t => t.id === tenantId);
  window.logActivityTenant = known ? { id: known.id, name: known.name } : null;
  updateLogActivityHash();
  renderLogActivityTenantCards();
  loadEvents();
}

// Shared by selectLogActivityTenant and onEventsFiltersChange above --
// rebuilds the full hash from current tenant/filter state each time so
// neither overwrites the other's param. Built via URLSearchParams (not
// manual template-string concatenation) so .toString() percent-encodes the
// JSON filters value exactly once -- URLSearchParams.get() on restore
// decodes it exactly once too.
function updateLogActivityHash() {
  const params = new URLSearchParams();
  if (window.logActivityTenant?.id) params.set("tenant", window.logActivityTenant.id);
  if (window.eventsFilters.length) params.set("filters", JSON.stringify(window.eventsFilters));
  const qs = params.toString();
  const hash = qs ? `#page=log-activity&${qs}` : "#page=log-activity";
  if (location.hash !== hash) history.replaceState(null, "", hash);
}

async function loadEvents() {
  renderLogActivityTenantCards();
  renderEventsFilterBuilder();

  const params = new URLSearchParams();
  const search = document.getElementById("filter-search").value.trim();
  const source = document.getElementById("filter-source")?.value || "";
  if (search) params.set("search", search);
  if (source) params.set("source", source);
  if (window.logActivityTenant?.id) params.set("tenant_id", window.logActivityTenant.id);
  if (window.eventsFilters.length) params.set("filters", JSON.stringify(window.eventsFilters));
  params.set("per_page", "100");

  const data = await api(`/events?${params.toString()}`);
  renderEventsTable(data.items, data.total, data.truncated);
}

function renderEventsTable(events, total, truncated) {
  const el = document.getElementById("events-table");
  if (!events.length) {
    el.innerHTML = `<div class="empty-state">No events imported.</div>`;
    return;
  }
  const truncatedNote = truncated
    ? `<div style="color:var(--high); font-size:12px; margin-bottom:8px;">
        ⚠ Results may be incomplete -- a filter on a derived field (e.g. Path) is applied
        after a 5000-row scan cap. Narrow your other filters for exact results.
       </div>`
    : "";
  el.innerHTML = `
    <div style="color:var(--text-dim); font-size:12px; margin-bottom:8px;">${total} event(s)</div>
    ${truncatedNote}
    <table>
      <tr><th>Timestamp</th><th>Event ID</th><th>Event Name</th><th>Source IP</th><th>Destination IP</th><th>Username</th><th>Source</th><th>Format</th></tr>
      ${events.map(e => `
        <tr class="clickable" onclick="showRawEvent(${e.id})">
          <td>${fmtDate(e.timestamp)}</td>
          <td>${escapeHtml(e.event_id)}</td>
          <td>${escapeHtml(e.event_name)}</td>
          <td>${escapeHtml(e.source_ip)}</td>
          <td>${escapeHtml(e.destination_ip)}</td>
          <td>${escapeHtml(e.username)}</td>
          <td>${escapeHtml(e.source)}${e.device_type ? ` (${escapeHtml(e.device_type)})` : ""}</td>
          <td>${escapeHtml(e.log_format)}</td>
        </tr>`).join("")}
    </table>`;
}

async function showRawEvent(eventId) {
  const event = await api(`/events/${eventId}`);
  const mitreGuesses = event.mitre_guess || [];
  const mitreSection = mitreGuesses.length ? `
    <div style="margin-bottom:10px;">
      <div style="color:var(--text-dim); font-size:11px; margin-bottom:4px;">💡 Possible MITRE match (heuristic)</div>
      ${mitreGuesses.map(mitreEntryToChipHtml).join("")}
    </div>` : "";
  openModal(`
    <h2>Event #${event.id} Raw Data</h2>
    ${mitreSection}
    <div class="raw-json">${escapeHtml(JSON.stringify(event.raw_data, null, 2))}</div>
    <div class="modal-actions"><button class="secondary" onclick="closeModal()">Close</button></div>
  `);
}

document.getElementById("apply-event-filters")?.addEventListener("click", loadEvents);

window.loadEvents = loadEvents;
window.selectLogActivityTenant = selectLogActivityTenant;
