const OPERATORS = [
  ["equals", "Equals"], ["not_equals", "Not Equals"],
  ["contains", "Contains"], ["not_contains", "Not Contains"],
  ["in", "In (comma list)"], ["not_in", "Not In (comma list)"],
  ["greater_than", "Greater Than"], ["less_than", "Less Than"],
  ["exists", "Exists"], ["not_exists", "Does Not Exist"],
];
const COMMON_FIELDS = ["event_id", "event_name", "source_ip", "source_port", "destination_ip", "destination_port", "username", "process_name", "timestamp"];
const GROUPING_FIELDS = ["source_ip", "username", "destination_ip", "destination_port", "event_id", "process_name"];

let groupCounter = 0;
let editingRuleId = null;

// Page-local tenant context for Rules ONLY -- {id, name} for a specific
// tenant, or null for "All Tenants" (unscoped). Mirrors events.js's
// window.logActivityTenant exactly (same pattern, independent state): no
// other page reads or is affected by this.
window.rulesTenant = null;
let rulesTenantRestoredFromUrl = false;

function restoreRulesTenantFromUrl() {
  if (rulesTenantRestoredFromUrl) return;
  rulesTenantRestoredFromUrl = true;
  const tenantParam = new URLSearchParams(location.hash.slice(1)).get("tenant");
  if (!tenantParam || !window.allTenants?.length) return;
  const id = parseInt(tenantParam, 10);
  const known = window.allTenants.find(t => t.id === id);
  if (known) window.rulesTenant = { id: known.id, name: known.name };
}

function renderRulesTenantCards() {
  const el = document.getElementById("rules-tenant-cards");
  if (!el) return;
  if (!window.currentSession || window.currentSession.role !== "full_admin") {
    el.innerHTML = ""; // a Tenant Admin has only one tenant -- nothing to pick
    return;
  }
  restoreRulesTenantFromUrl();
  renderTenantSingleSelect(el, {
    tenants: window.allTenants || [],
    selectedId: window.rulesTenant?.id ?? null,
    onSelect: selectRulesTenant,
  });
}

function selectRulesTenant(tenantId) {
  const known = tenantId === null ? null : window.allTenants.find(t => t.id === tenantId);
  window.rulesTenant = known ? { id: known.id, name: known.name } : null;
  const hash = window.rulesTenant ? `#page=rules&tenant=${window.rulesTenant.id}` : "#page=rules";
  if (location.hash !== hash) history.replaceState(null, "", hash);
  renderRulesTenantCards();
  loadRules();
}

async function loadRules() {
  renderRulesTenantCards();
  const isFullAdmin = window.currentSession?.role === "full_admin";

  const params = new URLSearchParams();
  if (window.rulesTenant?.id) params.set("tenant_id", window.rulesTenant.id);
  const rules = await api(`/rules?${params.toString()}`);
  const el = document.getElementById("rules-table");
  if (!rules.length) {
    el.innerHTML = `<div class="empty-state">No detection rules created.</div>`;
    return;
  }
  const tenantName = (tenantId) => window.allTenants?.find(t => t.id === tenantId)?.name || `Tenant ${tenantId}`;
  el.innerHTML = `<table>
    <tr><th>Name</th>${isFullAdmin ? "<th>Tenant</th>" : ""}<th>Severity</th><th>Enabled</th><th>Threshold</th><th>Window</th><th>Matches</th><th>Created</th><th></th></tr>
    ${rules.map(r => `
      <tr>
        <td>${escapeHtml(r.name)}${r.auto_pattern_type ? ` <span class="badge" style="background:var(--accent-dim); color:var(--accent);" title="Automatically created from a detected ${escapeHtml(r.auto_pattern_type)} pattern">🤖 Auto-generated</span>` : ""}</td>
        ${isFullAdmin ? `<td>${escapeHtml(tenantName(r.tenant_id))}</td>` : ""}
        <td><span class="badge ${r.severity}">${r.severity}</span></td>
        <td>${r.enabled ? "Yes" : "No"}</td>
        <td>${r.threshold_count}</td>
        <td>${r.time_window_value} ${r.time_window_unit}</td>
        <td>${r.match_count}</td>
        <td>${fmtDate(r.created_at)}</td>
        <td style="white-space:nowrap;">
          <button class="secondary" onclick="editRule(${r.id})">Edit</button>
          <button class="secondary" onclick="evaluateRule(${r.id})">Evaluate</button>
          ${isFullAdmin ? `<button class="secondary" onclick="openCopyRuleModal(${r.id})">📋 Copy</button>` : ""}
          <button class="danger" onclick="deleteRule(${r.id})">Delete</button>
        </td>
      </tr>`).join("")}
  </table>`;
}

async function evaluateRule(ruleId) {
  const result = await api(`/rules/${ruleId}/evaluate`, { method: "POST" });
  alert(`Rule evaluated: ${result.offenses_created_or_updated} offense(s) created or updated.`);
  loadRules();
}

async function deleteRule(ruleId) {
  if (!confirm("Delete this rule? This cannot be undone.")) return;
  await api(`/rules/${ruleId}`, { method: "DELETE" });
  loadRules();
}

async function openCopyRuleModal(ruleId) {
  const rule = await api(`/rules/${ruleId}`);
  const tenants = window.allTenants?.length ? window.allTenants : await api("/tenants");

  openModal(`
    <h2>Copy "${escapeHtml(rule.name)}" to other tenants</h2>
    <p style="color:var(--text-dim); font-size:12px;">
      Creates an independent copy of this rule (same conditions, threshold, MITRE mapping) in each
      tenant you select. Copies are not linked to each other or to this rule -- editing one afterward
      never affects the others.
    </p>
    <div id="copy-rule-tenant-container" style="margin:12px 0;"></div>
    <div class="modal-actions">
      <button class="secondary" onclick="closeModal()">Cancel</button>
      <button id="confirm-copy-rule-btn">Copy</button>
    </div>
  `);

  renderTenantMultiSelect(document.getElementById("copy-rule-tenant-container"), {
    tenants,
    excludeIds: [rule.tenant_id], // can't "copy" a rule into its own tenant
  });

  document.getElementById("confirm-copy-rule-btn")?.addEventListener("click", () => submitCopyRule(ruleId));
}

async function submitCopyRule(ruleId) {
  const tenantIds = getTenantMultiSelectSelection(document.getElementById("copy-rule-tenant-container"));
  if (!tenantIds.length) { alert("Select at least one tenant to copy to."); return; }
  try {
    const copies = await api(`/rules/${ruleId}/copy`, { method: "POST", body: JSON.stringify({ tenant_ids: tenantIds }) });
    const names = copies.map(c => window.allTenants.find(t => t.id === c.tenant_id)?.name || `Tenant ${c.tenant_id}`);
    alert(`Copied to ${copies.length} tenant(s): ${names.join(", ")}`);
    closeModal();
    loadRules();
  } catch (err) {
    alert(err.message);
  }
}

document.getElementById("new-rule-btn")?.addEventListener("click", () => openRuleBuilder(null));

async function editRule(ruleId) {
  const rule = await api(`/rules/${ruleId}`);
  openRuleBuilder(rule);
}

async function tenantFieldHtml(rule) {
  // A rule always belongs to exactly one tenant (no "global rule" concept).
  // A Full Admin picks it at creation time and can't change it afterward
  // (tenant reassignment isn't supported -- see rule_service.update_rule);
  // a Tenant Admin never sees a picker, their rules are always forced onto
  // their own tenant server-side regardless of what this form sends.
  const session = window.currentSession;
  if (!session) return "";
  if (session.role !== "full_admin") {
    return `
    <label style="margin-top:18px;">Tenant</label>
    <input type="text" value="${escapeHtml(session.tenant_name || "")}" disabled>`;
  }
  const tenants = window.allTenants?.length ? window.allTenants : await api("/tenants");
  // Editing an existing rule shows/locks its real tenant; creating a new
  // one pre-selects whichever tenant is active on this page's own card
  // strip (window.rulesTenant, see renderRulesTenantCards above) --
  // still changeable, and still required before saving.
  const preselected = rule ? rule.tenant_id : window.rulesTenant?.id;
  return `
    <label style="margin-top:18px;">Tenant</label>
    <select id="rule-tenant" ${rule ? "disabled" : ""}>
      <option value="">-- select tenant --</option>
      ${tenants.map(t => `<option value="${t.id}" ${preselected === t.id ? "selected" : ""}>${escapeHtml(t.name)}</option>`).join("")}
    </select>`;
}

function conditionGroupHtml(group = { logic: "AND", conditions: [{}] }) {
  const gid = `g${groupCounter++}`;
  const conditionsHtml = (group.conditions.length ? group.conditions : [{}]).map(c => conditionRowHtml(c)).join("");
  return `
    <div class="group-box" data-group-id="${gid}">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <strong style="font-size:12px; color:var(--text-dim);">Condition Group (AND)</strong>
        <button class="remove-btn" onclick="this.closest('.group-box').remove()">&times;</button>
      </div>
      <div class="conditions-list">${conditionsHtml}</div>
      <button class="secondary" style="margin-top:6px;" onclick="addConditionRow(this)">+ Condition</button>
    </div>`;
}

function conditionRowHtml(c = {}) {
  // A saved/suggested condition can reference a field outside COMMON_FIELDS
  // (e.g. a CEF/access_log derived field like "Path"). Losing track of it
  // and silently falling back to the <select>'s first option would save a
  // corrupted rule with no warning -- prepend it as its own option instead
  // so the real field name stays visible and selected.
  const fieldOptions = (c.field && !COMMON_FIELDS.includes(c.field)) ? [c.field, ...COMMON_FIELDS] : COMMON_FIELDS;
  return `
    <div class="condition-row">
      <select class="cond-field">${fieldOptions.map(f => `<option value="${f}" ${c.field === f ? "selected" : ""}>${f}</option>`).join("")}</select>
      <select class="cond-op">${OPERATORS.map(([v, l]) => `<option value="${v}" ${c.operator === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <input type="text" class="cond-value" placeholder="Value" value="${escapeHtml(c.value ?? "")}">
      <button class="remove-btn" onclick="this.closest('.condition-row').remove()">&times;</button>
    </div>`;
}

function addConditionRow(btn) {
  btn.insertAdjacentHTML("beforebegin", conditionRowHtml());
  refreshRuleSentence();
}

function addConditionGroup() {
  document.getElementById("condition-groups").insertAdjacentHTML("beforeend", conditionGroupHtml());
  refreshRuleSentence();
}

function ruleSentenceFromForm() {
  const name = document.getElementById("rule-name")?.value.trim() || "[Rule Name]";
  const scope = document.getElementById("rule-scope")?.value || "Local system";
  const logSource = document.getElementById("rule-log-source")?.value || "one or more of [Log Source]";
  const parts = [];
  document.querySelectorAll("#condition-groups .condition-row").forEach(row => {
    const field = row.querySelector(".cond-field")?.value || "Field";
    const op = row.querySelector(".cond-op")?.selectedOptions?.[0]?.textContent || "Equals";
    const value = row.querySelector(".cond-value")?.value.trim() || "[value]";
    parts.push(`when the event matches ${field} ${op.toLowerCase()} ${value}`);
  });
  const conditions = parts.length ? parts.map(x => `and ${x}`).join("<br>") : "and when the event matches [conditions]";
  return `Apply <strong>${escapeHtml(name)}</strong> to events which are detected by the ${escapeHtml(scope)}<br>and when the event(s) were detected by ${escapeHtml(logSource)}<br>${conditions}`;
}

function refreshRuleSentence() {
  const el = document.getElementById("rule-sentence-preview");
  if (el) el.innerHTML = ruleSentenceFromForm();
}

async function openRuleBuilder(rule) {
  editingRuleId = rule ? rule.id : null;
  const conditions = rule ? rule.conditions : { scope: "Local system", log_source: "", logic: "OR", groups: [{ logic: "AND", conditions: [{}] }] };
  const groups = (conditions.groups && conditions.groups.length) ? conditions.groups : [{ logic: "AND", conditions: [{}] }];
  const grouping = rule ? rule.grouping : [];
  const mitre = (rule && rule.mitre) ? rule.mitre : [];
  const tenantField = await tenantFieldHtml(rule);

  const groupingCheckboxes = GROUPING_FIELDS.map(f => `
    <label style="display:inline-flex; align-items:center; gap:4px; margin-right:14px; font-size:12px; color:var(--text);">
      <input type="checkbox" class="grouping-check" value="${f}" ${grouping.includes(f) ? "checked" : ""}> ${f}
    </label>`).join("");

  openModal(`
    <h2>${rule ? "Edit" : "Create"} Detection Rule</h2>
    <div class="wizard-steps">
      <span>1. Rule Info</span><span>2. Conditions</span><span>3. Correlation</span>
      <span>4. Threshold</span><span>5. Time Window</span><span>6. MITRE</span><span>7. Response</span>
    </div>

    <label>Rule Name</label>
    <input type="text" id="rule-name" value="${escapeHtml(rule?.name ?? "")}" placeholder="e.g. Brute Force Detection">

    <label>Description</label>
    <textarea id="rule-description" rows="2" placeholder="Detect repeated failed authentication attempts from the same source.">${escapeHtml(rule?.description ?? "")}</textarea>

    ${tenantField}

    <div style="display:flex; gap:16px;">
      <div style="flex:1;">
        <label>Severity</label>
        <select id="rule-severity">
          ${["Low","Medium","High","Critical"].map(s => `<option value="${s}" ${rule?.severity === s ? "selected" : ""}>${s}</option>`).join("")}
        </select>
      </div>
      <div style="flex:1;">
        <label>Enabled</label>
        <select id="rule-enabled">
          <option value="true" ${rule?.enabled !== false ? "selected" : ""}>Enabled</option>
          <option value="false" ${rule?.enabled === false ? "selected" : ""}>Disabled</option>
        </select>
      </div>
    </div>

    <label style="margin-top:18px;">Rule Scope</label>
    <select id="rule-scope">
      ${["Local system", "One or more systems", "Any system"].map(s => `<option value="${s}" ${conditions.scope === s ? "selected" : ""}>${s}</option>`).join("")}
    </select>

    <label style="margin-top:12px;">Log Source</label>
    <input type="text" id="rule-log-source" value="${escapeHtml(conditions.log_source ?? "")}" placeholder="e.g. Microsoft Windows Security Event Log">

    <label style="margin-top:18px;">Event Conditions</label>
    <p style="color:var(--text-dim); font-size:12px; margin:2px 0 8px;">Use selectable fields, operators, and values. The QRadar-style rule sentence below is generated from these selections and is saved with the rule.</p>
    <div id="condition-groups">${groups.map(g => conditionGroupHtml(g)).join("")}</div>
    <button class="secondary" onclick="addConditionGroup()">+ Condition Group (OR)</button>

    <div class="panel" style="margin-top:14px; padding:12px;">
      <div style="font-size:11px; color:var(--text-dim); margin-bottom:6px;">QRadar-style rule preview</div>
      <div id="rule-sentence-preview" style="line-height:1.8; font-size:13px;"></div>
    </div>

    <label style="margin-top:18px;">Event Correlation / Group By</label>
    <div>${groupingCheckboxes}</div>
    <label style="margin-top:6px;">Additional custom grouping field (optional)</label>
    <input type="text" id="rule-custom-grouping" placeholder="e.g. process_name">

    <label style="margin-top:18px;">Threshold</label>
    <div style="display:flex; gap:8px; align-items:center;">
      <span id="rule-threshold-label">${rule?.distinct_field ? "Distinct values &ge;" : "Count &ge;"}</span>
      <input type="number" id="rule-threshold" min="1" value="${rule?.threshold_count ?? 1}" style="max-width:100px;">
    </div>
    <label style="margin-top:6px;">Count distinct values of (optional)</label>
    <select id="rule-distinct-field" style="max-width:220px;">
      <option value="">None (count every matching event)</option>
      ${GROUPING_FIELDS.map(f => `<option value="${f}" ${rule?.distinct_field === f ? "selected" : ""}>${f}</option>`).join("")}
    </select>

    <label style="margin-top:18px;">Time Window</label>
    <div style="display:flex; gap:8px; align-items:center;">
      <span>Within</span>
      <input type="number" id="rule-window-value" min="0" value="${rule?.time_window_value ?? 10}" style="max-width:100px;">
      <select id="rule-window-unit" style="max-width:140px;">
        ${["seconds","minutes","hours"].map(u => `<option value="${u}" ${rule?.time_window_unit === u ? "selected" : ""}>${u}</option>`).join("")}
      </select>
    </div>

    <label style="margin-top:18px;">MITRE ATT&amp;CK Mapping</label>
    <div id="mitre-picker-container"></div>

    <label style="margin-top:18px;">Rule Response</label>
    <select id="rule-response">
      <option value="CREATE_OFFENSE" selected>Create Offense</option>
    </select>

    <div class="modal-actions">
      <button class="secondary" onclick="closeModal()">Cancel</button>
      <button id="save-rule-btn">Save Rule</button>
    </div>
  `);

  document.getElementById("save-rule-btn").addEventListener("click", saveRuleFromForm);
  document.getElementById("rule-distinct-field")?.addEventListener("change", (e) => {
    const label = document.getElementById("rule-threshold-label");
    if (label) label.innerHTML = e.target.value ? "Distinct values &ge;" : "Count &ge;";
  });
  ["rule-name", "rule-scope", "rule-log-source"].forEach(id => document.getElementById(id)?.addEventListener("input", refreshRuleSentence));
  document.getElementById("condition-groups")?.addEventListener("input", refreshRuleSentence);
  document.getElementById("condition-groups")?.addEventListener("change", refreshRuleSentence);
  refreshRuleSentence();
  renderMitrePicker(document.getElementById("mitre-picker-container"), mitre);
}

function collectConditionsFromForm() {
  const groupBoxes = document.querySelectorAll("#condition-groups .group-box");
  const groups = [];
  groupBoxes.forEach(box => {
    const conditions = [];
    box.querySelectorAll(".condition-row").forEach(row => {
      const field = row.querySelector(".cond-field").value;
      const operator = row.querySelector(".cond-op").value;
      const value = row.querySelector(".cond-value").value;
      conditions.push({ field, operator, value });
    });
    if (conditions.length) groups.push({ logic: "AND", conditions });
  });
  return { logic: "OR", groups };
}

function collectGroupingFromForm() {
  const grouping = [];
  document.querySelectorAll(".grouping-check:checked").forEach(cb => grouping.push(cb.value));
  const custom = document.getElementById("rule-custom-grouping").value.trim();
  if (custom) grouping.push(custom);
  return grouping;
}

async function saveRuleFromForm() {
  const payload = {
    name: document.getElementById("rule-name").value.trim(),
    description: document.getElementById("rule-description").value.trim(),
    severity: document.getElementById("rule-severity").value,
    enabled: document.getElementById("rule-enabled").value === "true",
    conditions: {
      ...collectConditionsFromForm(),
      scope: document.getElementById("rule-scope")?.value || "Local system",
      log_source: document.getElementById("rule-log-source")?.value.trim() || ""
    },
    grouping: collectGroupingFromForm(),
    threshold_count: parseInt(document.getElementById("rule-threshold").value || "1", 10),
    distinct_field: document.getElementById("rule-distinct-field")?.value || null,
    time_window_value: parseInt(document.getElementById("rule-window-value").value || "0", 10),
    time_window_unit: document.getElementById("rule-window-unit").value,
    mitre: collectMitrePayload(),
    response: document.getElementById("rule-response").value,
  };
  const tenantSelect = document.getElementById("rule-tenant");
  if (tenantSelect) {
    payload.tenant_id = tenantSelect.value ? parseInt(tenantSelect.value, 10) : null;
  }

  if (!payload.name) { alert("Rule name is required."); return; }
  if (!editingRuleId && document.getElementById("rule-tenant") && !payload.tenant_id) {
    alert("Please select a tenant.");
    return;
  }

  try {
    if (editingRuleId) {
      await api(`/rules/${editingRuleId}`, { method: "PUT", body: JSON.stringify(payload) });
    } else {
      await api("/rules", { method: "POST", body: JSON.stringify(payload) });
    }
    closeModal();
    loadRules();
  } catch (err) {
    alert(err.message);
  }
}

window.loadRules = loadRules;
window.addConditionGroup = addConditionGroup;
window.addConditionRow = addConditionRow;
window.editRule = editRule;
window.evaluateRule = evaluateRule;
window.deleteRule = deleteRule;
window.selectRulesTenant = selectRulesTenant;
window.openCopyRuleModal = openCopyRuleModal;
