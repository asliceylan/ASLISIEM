const MITRE_DOMAIN_LABELS = { enterprise: "Enterprise", mobile: "Mobile", ics: "ICS" };

function mitreEntryIsLegacy(entry) {
  return !entry || !Array.isArray(entry.tactics);
}

function mitreChipDataAttrs(entry) {
  // Legacy saved entries (old rule.mitre_json rows) never carried a domain
  // field -- default to "enterprise" (see decision: acceptable limitation,
  // matches this app's only-ever-enterprise-domain data everywhere else).
  if (!entry.technique_id) return "";
  const domain = entry.domain || "enterprise";
  return ` data-domain="${escapeHtml(domain)}" data-technique-id="${escapeHtml(entry.technique_id)}"`;
}

function mitreEntryToChipHtml(entry) {
  if (!entry) return "";
  if (mitreEntryIsLegacy(entry)) {
    const sub = entry.subtechnique_id
      ? ` / ${escapeHtml(entry.subtechnique_id)} ${escapeHtml(entry.subtechnique_name || "")}`
      : "";
    return `<span class="mitre-chip"${mitreChipDataAttrs(entry)}>${escapeHtml(entry.technique_id || "")} ${escapeHtml(entry.technique_name || "")}${sub}</span>`;
  }
  const subNote = entry.is_subtechnique && entry.parent_technique_id
    ? ` (sub-technique of ${escapeHtml(entry.parent_technique_id)})`
    : "";
  const tactics = (entry.tactics || []).map(t => escapeHtml(t.tactic_name)).join(", ");
  return `<span class="mitre-chip"${mitreChipDataAttrs(entry)}>${escapeHtml(entry.technique_id)} ${escapeHtml(entry.technique_name)}${subNote}${tactics ? " — " + tactics : ""}</span>`;
}

async function showTechniqueDescription(domain, techniqueId) {
  let technique = null;
  try {
    technique = await api(`/mitre/techniques/${encodeURIComponent(techniqueId)}?domain=${encodeURIComponent(domain)}`);
  } catch (err) {
    technique = null;
  }
  const description = technique?.description
    ? technique.description.split(/\n{2,}/).map(p => `<p>${escapeHtml(p.trim())}</p>`).join("")
    : `<p style="color:var(--text-dim);">No description available — try Admin &gt; Sync.</p>`;
  openModal(`
    <h2>${escapeHtml(techniqueId)}${technique?.technique_name ? ` — ${escapeHtml(technique.technique_name)}` : ""}</h2>
    <div class="mitre-description">${description}</div>
    <div class="modal-actions"><button class="secondary" onclick="closeModal()">Close</button></div>
  `);
}

document.addEventListener("click", (e) => {
  const chip = e.target.closest(".mitre-chip[data-technique-id]");
  if (chip) showTechniqueDescription(chip.dataset.domain, chip.dataset.techniqueId);
});

/* ---------------- Admin sync panel ---------------- */

async function loadMitreAdminPanel() {
  const el = document.getElementById("mitre-admin-panel");
  if (!el) return;
  el.innerHTML = `<div class="panel"><div class="empty-state">Loading MITRE catalog status...</div></div>`;
  let statuses;
  try {
    statuses = await api("/mitre/status");
  } catch (err) {
    el.innerHTML = `<div class="panel"><div class="empty-state">Failed to load MITRE status: ${escapeHtml(err.message)}</div></div>`;
    return;
  }
  renderMitreAdminPanel(el, statuses);
}

function renderMitreAdminPanel(el, statuses) {
  el.innerHTML = `
    <div class="panel">
      <h3>MITRE ATT&amp;CK Catalog</h3>
      <p style="color:var(--text-dim); font-size:12px; margin:0 0 12px;">
        Fetched at runtime from the official MITRE STIX data repository (attack-stix-data, ${escapeHtml(statuses[0]?.attack_version || "")}).
        This requires internet access.
      </p>
      <div class="toolbar" style="margin-bottom:14px;">
        <button id="mitre-sync-all-btn">Sync All Domains</button>
      </div>
      <table>
        <tr><th>Domain</th><th>Status</th><th>Tactics</th><th>Techniques</th><th>Last Success</th><th></th></tr>
        ${statuses.map(s => `
          <tr>
            <td>${MITRE_DOMAIN_LABELS[s.domain] || s.domain}</td>
            <td>
              <span class="badge ${s.status}">${s.status.replace("_", " ")}</span>
              ${s.status === "FAILED" && s.error_message ? `<div style="color:var(--critical); font-size:11px; margin-top:4px;">${escapeHtml(s.error_message)}</div>` : ""}
            </td>
            <td>${s.tactic_count}</td>
            <td>${s.technique_count}</td>
            <td>${fmtDate(s.last_success_at)}</td>
            <td><button class="secondary mitre-sync-domain-btn" data-domain="${s.domain}">Sync</button></td>
          </tr>`).join("")}
      </table>
    </div>`;

  document.getElementById("mitre-sync-all-btn").addEventListener("click", () => triggerMitreSync(null));
  el.querySelectorAll(".mitre-sync-domain-btn").forEach(btn => {
    btn.addEventListener("click", () => triggerMitreSync(btn.dataset.domain));
  });
}

async function triggerMitreSync(domain) {
  const el = document.getElementById("mitre-admin-panel");
  el.querySelectorAll("button").forEach(b => b.disabled = true);
  const busyBtn = domain
    ? el.querySelector(`.mitre-sync-domain-btn[data-domain="${domain}"]`)
    : document.getElementById("mitre-sync-all-btn");
  if (busyBtn) busyBtn.textContent = "Syncing...";
  try {
    await api("/mitre/sync", { method: "POST", body: JSON.stringify(domain ? { domain } : {}) });
  } catch (err) {
    alert(`Sync failed: ${err.message}`);
  }
  loadMitreAdminPanel();
}

/* ---------------- Rule builder technique picker ---------------- */

let mitrePickerContainer = null;
let mitrePickerDomain = "enterprise";
let mitrePickerSelection = [];
let mitreSearchDebounce = null;

function renderMitrePicker(container, initialEntries) {
  mitrePickerContainer = container;
  mitrePickerDomain = "enterprise";
  mitrePickerSelection = (initialEntries || []).map(e => ({ ...e, _legacy: mitreEntryIsLegacy(e) }));

  container.innerHTML = `
    <div class="mitre-domain-tabs" id="mitre-domain-tabs">
      ${Object.entries(MITRE_DOMAIN_LABELS).map(([d, label]) =>
        `<span data-domain="${d}" class="${d === mitrePickerDomain ? "current" : ""}">${label}</span>`).join("")}
    </div>
    <input type="text" id="mitre-search-input" placeholder="Search techniques by name or ID (e.g. T1110, Brute Force)">
    <div class="mitre-search-results" id="mitre-search-results" style="display:none;"></div>
    <div id="mitre-selected-cards"></div>
  `;

  container.querySelectorAll("#mitre-domain-tabs span").forEach(tab => {
    tab.addEventListener("click", () => {
      mitrePickerDomain = tab.dataset.domain;
      container.querySelectorAll("#mitre-domain-tabs span").forEach(t => t.classList.toggle("current", t === tab));
      document.getElementById("mitre-search-input").value = "";
      document.getElementById("mitre-search-results").style.display = "none";
    });
  });

  document.getElementById("mitre-search-input").addEventListener("input", (e) => {
    clearTimeout(mitreSearchDebounce);
    const q = e.target.value.trim();
    mitreSearchDebounce = setTimeout(() => runMitreSearch(q), 250);
  });

  hydrateMitreSelection();
}

async function runMitreSearch(query) {
  const resultsEl = document.getElementById("mitre-search-results");
  if (!query) { resultsEl.style.display = "none"; resultsEl.innerHTML = ""; return; }
  let results;
  try {
    results = await api(`/mitre/techniques?domain=${mitrePickerDomain}&q=${encodeURIComponent(query)}&limit=20`);
  } catch (err) {
    resultsEl.style.display = "block";
    resultsEl.innerHTML = `<div class="result-row">Search failed: ${escapeHtml(err.message)}</div>`;
    return;
  }
  if (!results.length) {
    resultsEl.style.display = "block";
    resultsEl.innerHTML = `<div class="result-row">No results. Run a sync from the Admin page if the catalog looks empty.</div>`;
    return;
  }
  resultsEl.style.display = "block";
  resultsEl.innerHTML = results.map(r => `
    <div class="result-row" data-technique-id="${escapeHtml(r.technique_id)}">
      <span class="tid">${escapeHtml(r.technique_id)}</span>${escapeHtml(r.technique_name)}
      ${r.is_subtechnique ? ` <span style="color:var(--text-dim);">(sub-technique of ${escapeHtml(r.parent_technique_id || "")})</span>` : ""}
    </div>`).join("");
  resultsEl.querySelectorAll(".result-row[data-technique-id]").forEach(row => {
    const match = results.find(r => r.technique_id === row.dataset.techniqueId);
    row.addEventListener("click", () => addMitreTechniqueToSelection(match));
  });
}

function addMitreTechniqueToSelection(technique) {
  const already = mitrePickerSelection.some(
    e => !e._legacy && e.domain === technique.domain && e.technique_id === technique.technique_id
  );
  if (!already) {
    mitrePickerSelection.push({
      domain: technique.domain,
      technique_id: technique.technique_id,
      technique_name: technique.technique_name,
      is_subtechnique: technique.is_subtechnique,
      parent_technique_id: technique.parent_technique_id,
      tactics: technique.tactics.map(t => ({ ...t, checked: true })),
      _legacy: false,
    });
  }
  document.getElementById("mitre-search-input").value = "";
  document.getElementById("mitre-search-results").style.display = "none";
  renderMitreSelectedCards();
}

async function hydrateMitreSelection() {
  // For entries loaded from an existing rule, refresh the full tactic list
  // from the catalog so the user can re-check tactics they'd previously
  // unchecked, not just see the subset that was saved.
  for (const entry of mitrePickerSelection) {
    if (entry._legacy) continue;
    try {
      const fresh = await api(`/mitre/techniques/${encodeURIComponent(entry.technique_id)}?domain=${entry.domain}`);
      const savedIds = new Set((entry.tactics || []).map(t => t.tactic_id));
      entry.tactics = fresh.tactics.map(t => ({ ...t, checked: savedIds.has(t.tactic_id) }));
    } catch (err) {
      entry.tactics = (entry.tactics || []).map(t => ({ ...t, checked: true }));
    }
  }
  renderMitreSelectedCards();
}

function renderMitreSelectedCards() {
  const el = document.getElementById("mitre-selected-cards");
  if (!el) return;
  if (!mitrePickerSelection.length) {
    el.innerHTML = `<p style="color:var(--text-dim); font-size:12px; margin-top:10px;">No MITRE techniques mapped yet. Search above to add one.</p>`;
    return;
  }
  el.innerHTML = mitrePickerSelection.map((entry, idx) => {
    if (entry._legacy) {
      return `
        <div class="mitre-technique-card legacy">
          <div class="card-head">
            <div>
              <div class="card-title">${mitreEntryToChipHtml(entry)}</div>
              <div class="card-sub">Legacy manual entry — read-only, kept as-is.</div>
            </div>
            <button class="remove-btn" data-remove-idx="${idx}">&times;</button>
          </div>
        </div>`;
    }
    const subNote = entry.is_subtechnique && entry.parent_technique_id ? ` (sub-technique of ${escapeHtml(entry.parent_technique_id)})` : "";
    return `
      <div class="mitre-technique-card">
        <div class="card-head">
          <div>
            <div class="card-title">${escapeHtml(entry.technique_id)} ${escapeHtml(entry.technique_name)}${subNote}</div>
            <div class="card-sub">${MITRE_DOMAIN_LABELS[entry.domain] || entry.domain}</div>
          </div>
          <button class="remove-btn" data-remove-idx="${idx}">&times;</button>
        </div>
        <div class="mitre-tactic-checks">
          ${entry.tactics.map((t, tIdx) => `
            <label>
              <input type="checkbox" data-entry-idx="${idx}" data-tactic-idx="${tIdx}" ${t.checked ? "checked" : ""}>
              ${escapeHtml(t.tactic_name)}
            </label>`).join("")}
        </div>
      </div>`;
  }).join("");

  el.querySelectorAll("button[data-remove-idx]").forEach(btn => {
    btn.addEventListener("click", () => {
      mitrePickerSelection.splice(parseInt(btn.dataset.removeIdx, 10), 1);
      renderMitreSelectedCards();
    });
  });
  el.querySelectorAll("input[data-entry-idx]").forEach(cb => {
    cb.addEventListener("change", () => {
      const entry = mitrePickerSelection[parseInt(cb.dataset.entryIdx, 10)];
      entry.tactics[parseInt(cb.dataset.tacticIdx, 10)].checked = cb.checked;
    });
  });
}

function collectMitrePayload() {
  return mitrePickerSelection
    .filter(e => e._legacy || e.tactics.some(t => t.checked))
    .map(e => {
      if (e._legacy) {
        const { _legacy, ...rest } = e;
        return rest;
      }
      return {
        domain: e.domain,
        technique_id: e.technique_id,
        technique_name: e.technique_name,
        is_subtechnique: e.is_subtechnique,
        parent_technique_id: e.parent_technique_id,
        tactics: e.tactics.filter(t => t.checked).map(t => ({ tactic_id: t.tactic_id, tactic_name: t.tactic_name })),
      };
    });
}

window.loadMitreAdminPanel = loadMitreAdminPanel;
window.renderMitrePicker = renderMitrePicker;
window.collectMitrePayload = collectMitrePayload;
window.mitreEntryToChipHtml = mitreEntryToChipHtml;
window.mitreEntryIsLegacy = mitreEntryIsLegacy;
