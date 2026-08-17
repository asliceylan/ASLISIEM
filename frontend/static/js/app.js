const PAGE_TITLES = {
  "dashboard": "Dashboard",
  "offenses": "Offenses",
  "offense-detail": "Offense Detail",
  "log-activity": "Log Activity",
  "network-activity": "Network Activity",
  "assets": "Assets",
  "rules": "Rules",
  "log-sources": "Log Sources",
  "admin": "Admin",
  "tenants": "Tenants",
  "simulators": "Simulators",
};

// Populated once at load by loadSession() below: {id, username, role,
// tenant_id, tenant_name}. Other modules (simulator.js, rules.js,
// tenants.js) read window.currentSession instead of each re-fetching it.
window.currentSession = null;

// Full list of tenants, fetched once for a full_admin session -- backs the
// tenant cards inside Log Activity (see events.js) and the tenant pickers
// in rules.js/imports.js. A tenant_admin has only one tenant (their own,
// from currentSession) so never needs this. NOTE: there is no app-wide
// "active tenant" here -- Dashboard/Offenses/Rules/Assets/Log Sources are
// always unscoped/aggregate. Only Log Activity has its own, page-local
// tenant context (window.logActivityTenant, owned entirely by events.js).
window.allTenants = [];

async function loadSession() {
  try {
    window.currentSession = await api("/session");
  } catch (err) {
    return; // 401 already redirects to /login inside api()
  }
  const isFullAdmin = window.currentSession.role === "full_admin";
  // Admin (MITRE sync) and Tenants (tenant/user management) are full_admin
  // only. Simulators has no nav entry at all (reachable only via a direct
  // /simulators URL) -- simulator.js already shows a Tenant Admin only
  // their own tenant's card, so no role-based hiding is needed for it here.
  ["nav-admin", "nav-tenants"].forEach(id => {
    const item = document.getElementById(id);
    if (item) item.style.display = isFullAdmin ? "" : "none";
  });
  if (isFullAdmin) {
    try {
      window.allTenants = await api("/tenants");
    } catch (err) {
      window.allTenants = [];
    }
  }
}

async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: options.body && !(options.body instanceof FormData) ? { "Content-Type": "application/json" } : {},
    ...options,
  });
  if (res.status === 401) {
    // Session expired (or never existed) while the SPA was open -- send the
    // user back to a real page load of /login rather than surfacing a raw
    // fetch-error toast for every in-flight API call.
    window.location.href = "/login";
    throw new Error("Authentication required");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Request failed");
  }
  return res.json();
}

function showPage(pageId) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  const target = document.getElementById(`page-${pageId}`);
  if (target) target.classList.add("active");
  document.getElementById("page-title").textContent = PAGE_TITLES[pageId] || pageId;

  document.querySelectorAll("#nav-list li").forEach(li => {
    li.classList.toggle("active", li.dataset.page === pageId);
  });

  if (pageId === "dashboard" && window.loadDashboard) window.loadDashboard();
  if (pageId === "offenses" && window.loadOffenses) window.loadOffenses();
  if (pageId === "log-activity" && window.loadEvents) window.loadEvents();
  if (pageId === "rules" && window.loadRules) window.loadRules();
  if (pageId === "assets" && window.loadAssets) window.loadAssets();
  if (pageId === "log-sources" && window.loadLogSources) window.loadLogSources();
  if (pageId === "tenants" && window.loadTenantsPage) window.loadTenantsPage();
  if (pageId === "admin" && window.loadMitreAdminPanel) window.loadMitreAdminPanel();
  if (pageId === "simulators" && window.loadSimulatorAdminPanel) window.loadSimulatorAdminPanel();
  if (pageId !== "simulators" && window.stopSimulatorAdminPolling) window.stopSimulatorAdminPolling();
}

// ---- Hash-based URL routing (page only -- no tenant concept here) --------
// URL shape: #page=<pageId>. Makes reload/back/forward/deep-links to a
// specific page work. Log Activity's own tenant selection is a SEPARATE,
// page-local concern (see events.js) and is intentionally not handled here.

function navigateTo(pageId) {
  const newHash = `#page=${pageId}`;
  if (location.hash === newHash) {
    applyStateFromUrl(); // same hash -> no hashchange event fires, apply directly
  } else {
    location.hash = newHash;
  }
}

function applyStateFromUrl() {
  const params = new URLSearchParams(location.hash.slice(1));
  const pageId = params.get("page") || "dashboard";
  showPage(pageId);
}

window.addEventListener("hashchange", applyStateFromUrl);

document.addEventListener("DOMContentLoaded", async () => {
  document.querySelectorAll("#nav-list li").forEach(li => {
    li.addEventListener("click", () => navigateTo(li.dataset.page));
  });

  document.querySelectorAll(".log-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".log-tab").forEach(t => t.classList.remove("current"));
      tab.classList.add("current");
      document.querySelectorAll(".log-tab-content").forEach(c => c.style.display = "none");
      document.getElementById(`log-tab-${tab.dataset.tab}`).style.display = "block";
      if (tab.dataset.tab === "history" && window.loadImportHistory) window.loadImportHistory();
    });
  });

  await loadSession();
  // /simulators has no nav entry and therefore no #page=... hash to route
  // through -- reaching it is purely a function of the URL path the user
  // typed. This is only checked once, on initial load: once the SPA is
  // open, ordinary nav clicks (which only ever change location.hash, never
  // location.pathname) must behave normally even if the address bar still
  // shows /simulators from the original page load.
  if (location.pathname === "/simulators") {
    showPage("simulators");
  } else {
    applyStateFromUrl(); // location.hash is empty on first load -> defaults to dashboard
  }
});

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function fmtDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

// Minimal 2-level modal stack -- NOT a general nested-modal system. Only
// snapshots/restores raw innerHTML, so any listeners the underlying modal
// bound via addEventListener() (not inline onclick=) are lost on restore.
// Every modal in this app today only uses inline onclick=, so this is safe;
// a future modal relying on addEventListener-bound handlers would need its
// own re-render on restore instead of reusing this stack as-is.
let modalStack = [];

function _bindModalOverlayClose() {
  document.getElementById("modal-overlay")?.addEventListener("click", (e) => {
    if (e.target.id === "modal-overlay") closeModal();
  });
}

function openModal(innerHtml) {
  const root = document.getElementById("modal-root");
  if (root.innerHTML.trim()) {
    modalStack.push(root.innerHTML);
  }
  root.innerHTML = `<div class="modal-overlay" id="modal-overlay"><div class="modal-box">${innerHtml}</div></div>`;
  _bindModalOverlayClose();
}

function closeModal() {
  const root = document.getElementById("modal-root");
  if (modalStack.length) {
    root.innerHTML = modalStack.pop();
    _bindModalOverlayClose();
  } else {
    root.innerHTML = "";
  }
}

