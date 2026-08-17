let currentPreview = null;

document.getElementById("import-file-input")?.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append("file", file);

  const area = document.getElementById("import-preview-area");
  area.innerHTML = `<div class="empty-state">Uploading and parsing...</div>`;

  try {
    const preview = await api("/import/upload", { method: "POST", body: formData });
    currentPreview = preview;
    await renderImportPreview(preview);
  } catch (err) {
    area.innerHTML = `<div class="empty-state">${escapeHtml(err.message)}</div>`;
  }
});

function mappingOptionFields(target, spec, fields) {
  const source = spec?.source_field || "";
  const mode = spec?.mode || "direct";
  const key = spec?.key || "";
  const options = ["<option value=''>-- Not mapped --</option>"]
    .concat(fields.map(f => `<option value="${escapeHtml(f)}" ${f === source ? "selected" : ""}>${escapeHtml(f)}</option>`));

  return `
    <div class="condition-row import-mapping-row">
      <label style="min-width:160px; margin:0;">${escapeHtml(target)}</label>
      <select data-target="${escapeHtml(target)}" class="mapping-source">${options.join("")}</select>
      <select data-target="${escapeHtml(target)}" class="mapping-mode">
        <option value="direct" ${mode === "direct" ? "selected" : ""}>Direct value</option>
        <option value="key_value" ${mode === "key_value" ? "selected" : ""}>Extract key=value</option>
      </select>
      <input data-target="${escapeHtml(target)}" class="mapping-key" placeholder="Key, e.g. EventID" value="${escapeHtml(key)}">
    </div>`;
}

async function importTenantFieldHtml() {
  // A Tenant Admin's imports always land in their own tenant automatically
  // (the backend forces it regardless of what this form sends); a Full
  // Admin must pick one explicitly -- same "every write belongs to exactly
  // one tenant" rule used by the Rules form (see rules.js tenantFieldHtml).
  const session = window.currentSession;
  if (!session) return "";
  if (session.role !== "full_admin") {
    return `<p style="color:var(--text-dim); font-size:12px;">Importing into tenant: <strong>${escapeHtml(session.tenant_name || "")}</strong></p>`;
  }
  const tenants = window.allTenants?.length ? window.allTenants : await api("/tenants");
  // Defaults to whichever tenant is currently active on the Events tab of
  // this same Log Activity page (window.logActivityTenant, see events.js)
  // -- still changeable, and still required before importing.
  const preselected = window.logActivityTenant?.id;
  return `
    <label>Import into Tenant</label>
    <select id="import-tenant">
      <option value="">-- select tenant --</option>
      ${tenants.map(t => `<option value="${t.id}" ${preselected === t.id ? "selected" : ""}>${escapeHtml(t.name)}</option>`).join("")}
    </select>`;
}

async function renderImportPreview(preview) {
  const area = document.getElementById("import-preview-area");
  const fields = preview.detected_fields || [];
  const previewRows = (preview.preview_rows || []).slice(0, 5);
  const sourceHeaders = preview.source_headers || [];
  const previewHeaders = fields;
  const displayLabel = (field) => {
    const idx = Number(String(field).replace("column_", ""));
    const original = sourceHeaders[idx] ?? "";
    return `${field} [source column ${idx + 1}]${original ? ` — ${original}` : ""}`;
  };

  area.innerHTML = `
    <div class="detail-grid">
      <div class="item"><div class="k">Filename</div><div class="v">${escapeHtml(preview.original_filename)}</div></div>
      <div class="item"><div class="k">Format</div><div class="v">${preview.file_type.toUpperCase()}</div></div>
      <div class="item"><div class="k">Detected Records</div><div class="v">${preview.record_count}</div></div>
      <div class="item"><div class="k">Detected Columns</div><div class="v">${previewHeaders.length}</div></div>
    </div>

    <h3>Original QRadar Data Preview (first 5 rows)</h3>
    <p style="color:var(--text-dim); font-size:12px;">
      All source rows will be imported automatically. No manual field mapping is required.
      Every original column and value is preserved in the event's raw data for future rule evaluation.
    </p>
    <div style="overflow-x:auto; margin-bottom:16px;">
      <table>
        <tr>${Object.keys((preview.qradar_preview_rows || [])[0] || {}).map(h => `<th>${escapeHtml(h)}</th>`).join("")}</tr>
        ${(preview.qradar_preview_rows || []).map(r => `<tr>${Object.keys(r).map(h => `<td>${escapeHtml(r[h] ?? "")}</td>`).join("")}</tr>`).join("")}
      </table>
    </div>
    <details style="margin-bottom:16px;">
      <summary>Show raw ${previewHeaders.length}-column source preview</summary>
      <div style="overflow-x:auto; margin-top:10px;">
        <table>
          <tr>${previewHeaders.map(h => `<th>${escapeHtml(displayLabel(h))}</th>`).join("")}</tr>
          ${previewRows.map(r => `<tr>${previewHeaders.map(h => `<td>${escapeHtml(r[h] ?? "")}</td>`).join("")}</tr>`).join("")}
        </table>
      </div>
    </details>

    <div class="empty-state" style="margin-top:16px;">
      <strong>Automatic import enabled</strong><br>
      ${preview.record_count} source records will be imported as ${preview.record_count} events.<br>
      The complete original source row is preserved. Normalized fields are auto-detected when possible; no event is discarded because a field cannot be normalized.
    </div>

    ${await importTenantFieldHtml()}

    <div class="modal-actions">
      <button class="secondary" onclick="cancelImportPreview()">Cancel</button>
      <button id="confirm-import-btn">Import ${preview.record_count} Events</button>
    </div>
  `;

  document.getElementById("confirm-import-btn").addEventListener("click", confirmImport);
}

function cancelImportPreview() {
  currentPreview = null;
  document.getElementById("import-preview-area").innerHTML = "";
  document.getElementById("import-file-input").value = "";
}

async function confirmImport() {
  if (!currentPreview) return;
  // The importer is intentionally automatic. The backend detects reliable
  // normalized fields, while preserving every source column/value in raw_data.
  // No manual mapping is required for an import.
  const mapping = {};

  const tenantSelect = document.getElementById("import-tenant");
  if (tenantSelect && !tenantSelect.value) {
    alert("Please select a tenant to import into.");
    return;
  }
  const tenant_id = tenantSelect ? parseInt(tenantSelect.value, 10) : null;

  const btn = document.getElementById("confirm-import-btn");
  btn.disabled = true;
  btn.textContent = "Importing...";

  try {
    const result = await api("/import/confirm", {
      method: "POST",
      body: JSON.stringify({
        temp_name: currentPreview.temp_name,
        original_filename: currentPreview.original_filename,
        file_type: currentPreview.file_type,
        mapping,
        tenant_id,
      }),
    });

    document.getElementById("import-preview-area").innerHTML = `
      <div class="empty-state">
        <strong>Import completed</strong><br>
        Imported: ${result.imported_count}<br>
        Skipped: ${result.skipped_count}<br>
        Failed: ${result.failed_count}<br>
        <strong>Total events stored in database: ${result.database_event_count}</strong><br>
        Total imported files stored: ${result.database_import_count}<br>
        Rules were evaluated against all persisted database events.
      </div>`;

    document.getElementById("import-file-input").value = "";
    currentPreview = null;

    // Refresh visible event data and dashboard if those views are active.
    if (typeof loadEvents === "function") loadEvents();
    if (typeof loadDashboard === "function") loadDashboard();
    if (typeof loadImportHistory === "function") loadImportHistory();
  } catch (err) {
    alert(err.message);
    btn.disabled = false;
    btn.textContent = "Import";
  }
}

async function loadImportHistory() {
  const imports = await api("/import");
  const el = document.getElementById("import-history-table");
  if (!imports.length) {
    el.innerHTML = `<div class="empty-state">No events imported.</div>`;
    return;
  }
  el.innerHTML = `<table>
    <tr><th>Filename</th><th>Type</th><th>Size</th><th>Event Count</th><th>Imported At</th><th>Status</th></tr>
    ${imports.map(i => `
      <tr>
        <td>${escapeHtml(i.filename)}</td>
        <td>${i.file_type.toUpperCase()}</td>
        <td>${i.file_size} bytes</td>
        <td>${i.event_count}</td>
        <td>${fmtDate(i.imported_at)}</td>
        <td>${escapeHtml(i.status)}</td>
      </tr>`).join("")}
  </table>`;
}

window.loadImportHistory = loadImportHistory;
