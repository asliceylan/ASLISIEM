// Framework-free searchable multi-select for tenant lists -- built for
// scenarios (Offenses filter, Rules "Copy to other tenants" modal) where a
// flat checkbox list of every tenant stops being usable once the tenant
// count grows large (e.g. 100 tenants). Mirrors the search-input +
// dropdown-of-matches + removable-chips pattern already used by mitre.js's
// renderMitrePicker (see mitrePickerSelection there) rather than
// introducing a new UI idiom or an external dependency.
//
// Deliberately has NO "select all" shortcut -- every tenant must be picked
// one at a time.
//
// Usage: renderTenantMultiSelect(container, { tenants, selectedIds,
// excludeIds, onChange }). The component owns its own selection state
// (stashed on the container element); callers that need to read it back
// synchronously (e.g. on a modal's confirm button) can use
// getTenantMultiSelectSelection(container) instead of wiring onChange.

function renderTenantMultiSelect(container, { tenants, selectedIds = [], excludeIds = [], onChange } = {}) {
  const state = {
    tenants: (tenants || []).filter(t => !excludeIds.includes(t.id)),
    selectedIds: [...selectedIds],
    onChange: onChange || (() => {}),
  };
  container._tenantMultiSelectState = state;

  if (!state.tenants.length) {
    container.innerHTML = `<div class="empty-state">No other tenants available.</div>`;
    return;
  }

  container.innerHTML = `
    <input type="text" class="tenant-ms-search" placeholder="Search tenants...">
    <div class="tenant-ms-results" style="display:none;"></div>
    <div class="tenant-ms-chips"></div>
  `;

  const searchInput = container.querySelector(".tenant-ms-search");
  const resultsEl = container.querySelector(".tenant-ms-results");
  const chipsEl = container.querySelector(".tenant-ms-chips");

  function renderChips() {
    if (!state.selectedIds.length) {
      chipsEl.innerHTML = `<span class="tenant-ms-empty-hint">No tenants selected yet -- search above to add one.</span>`;
      return;
    }
    chipsEl.innerHTML = state.selectedIds.map(id => {
      const t = state.tenants.find(t => t.id === id);
      return `<span class="tenant-ms-chip">${escapeHtml(t ? t.name : `Tenant ${id}`)}
        <button type="button" class="tenant-ms-chip-remove" data-tenant-id="${id}">&times;</button></span>`;
    }).join("");
    chipsEl.querySelectorAll(".tenant-ms-chip-remove").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = parseInt(btn.dataset.tenantId, 10);
        state.selectedIds = state.selectedIds.filter(x => x !== id);
        renderChips();
        state.onChange([...state.selectedIds]);
      });
    });
  }

  function runSearch() {
    const q = searchInput.value.trim().toLowerCase();
    const matches = state.tenants.filter(t =>
      !state.selectedIds.includes(t.id) && (!q || t.name.toLowerCase().includes(q))
    );
    resultsEl.style.display = "block";
    if (!matches.length) {
      resultsEl.innerHTML = `<div class="tenant-ms-result-row tenant-ms-empty">No matching tenants.</div>`;
      return;
    }
    resultsEl.innerHTML = matches.map(t =>
      `<div class="tenant-ms-result-row" data-tenant-id="${t.id}">${escapeHtml(t.name)}</div>`).join("");
    resultsEl.querySelectorAll(".tenant-ms-result-row[data-tenant-id]").forEach(row => {
      row.addEventListener("click", () => {
        const id = parseInt(row.dataset.tenantId, 10);
        if (!state.selectedIds.includes(id)) state.selectedIds.push(id);
        searchInput.value = "";
        resultsEl.style.display = "none";
        resultsEl.innerHTML = "";
        renderChips();
        state.onChange([...state.selectedIds]);
      });
    });
  }

  searchInput.addEventListener("input", runSearch);
  // Showing the full list on focus (before any typing) lets the user click
  // straight into a match instead of having to type first to reveal it.
  searchInput.addEventListener("focus", runSearch);
  // Closing the dropdown on blur (with a short delay so a click on a result
  // row still registers -- blur fires before click otherwise) keeps stale
  // matches from lingering once the user clicks elsewhere on the page.
  searchInput.addEventListener("blur", () => {
    setTimeout(() => { resultsEl.style.display = "none"; }, 150);
  });

  renderChips();
}

function getTenantMultiSelectSelection(container) {
  return container?._tenantMultiSelectState ? [...container._tenantMultiSelectState.selectedIds] : [];
}

// Single-select variant of the above, for "enter this tenant's context"
// pickers (Log Activity, Rules) that used to render one card per tenant --
// a fixed-size card grid stops being usable once the tenant count grows
// large (e.g. 100 tenants). Selecting a match fires onSelect(id) IMMEDIATELY
// (no separate confirm step, matching the old cards' click-to-enter
// behavior); the caller owns re-rendering after that (same pattern as
// selectLogActivityTenant/selectRulesTenant already use). selectedId=null
// means "All Tenants", which is always reachable via the fixed shortcut
// button next to the current-selection line, without having to search for it.
function renderTenantSingleSelect(container, { tenants = [], selectedId = null, onSelect } = {}) {
  const onSelectFn = onSelect || (() => {});
  const selectedTenant = selectedId !== null ? (tenants || []).find(t => t.id === selectedId) : null;

  container.innerHTML = `
    <div class="tenant-ss-current">
      Viewing: <strong>${selectedTenant ? escapeHtml(selectedTenant.name) : "All Tenants"}</strong>
      ${selectedTenant ? `<button type="button" class="secondary tenant-ss-all-btn">All Tenants</button>` : ""}
    </div>
    <input type="text" class="tenant-ms-search" placeholder="Search tenants to switch context...">
    <div class="tenant-ms-results" style="display:none;"></div>
  `;

  const searchInput = container.querySelector(".tenant-ms-search");
  const resultsEl = container.querySelector(".tenant-ms-results");
  const allBtn = container.querySelector(".tenant-ss-all-btn");

  if (allBtn) allBtn.addEventListener("click", () => onSelectFn(null));

  function runSearch() {
    const q = searchInput.value.trim().toLowerCase();
    const matches = (tenants || []).filter(t => t.id !== selectedId && (!q || t.name.toLowerCase().includes(q)));
    resultsEl.style.display = "block";
    if (!matches.length) {
      resultsEl.innerHTML = `<div class="tenant-ms-result-row tenant-ms-empty">No matching tenants.</div>`;
      return;
    }
    resultsEl.innerHTML = matches.map(t =>
      `<div class="tenant-ms-result-row" data-tenant-id="${t.id}">${escapeHtml(t.name)}${t.enabled ? "" : " (Disabled)"}</div>`).join("");
    resultsEl.querySelectorAll(".tenant-ms-result-row[data-tenant-id]").forEach(row => {
      row.addEventListener("click", () => onSelectFn(parseInt(row.dataset.tenantId, 10)));
    });
  }

  searchInput.addEventListener("input", runSearch);
  searchInput.addEventListener("focus", runSearch);
  searchInput.addEventListener("blur", () => {
    setTimeout(() => { resultsEl.style.display = "none"; }, 150);
  });
}

// Generic, {value,label}-based sibling of renderTenantMultiSelect/
// renderTenantSingleSelect above, for the "Add Filter" builder's Value
// field (filter_builder.js) when a field has a known/closed set of values
// (e.g. device_type, log_format, status, severity, or the tenant list
// itself). Same search-input + dropdown-of-matches + chip pattern, just
// generalized past tenants' hardcoded {id,name} shape. multi=true builds a
// chip list (for the "in"/"Equals Any Of" operator); multi=false keeps at
// most one chip, replaced on each new pick (no separate "clear" concept --
// unlike renderTenantSingleSelect there is no "All" equivalent here).
function renderValuePicker(container, { options = [], selectedValue = null, selectedValues = [], multi = false, onChange } = {}) {
  const state = {
    options: options || [],
    selectedValues: multi ? [...selectedValues] : (selectedValue !== null && selectedValue !== undefined ? [selectedValue] : []),
    multi,
    onChange: onChange || (() => {}),
  };
  container._valuePickerState = state;

  container.innerHTML = `
    <input type="text" class="tenant-ms-search" placeholder="${multi ? "Search values..." : "Search value..."}">
    <div class="tenant-ms-results" style="display:none;"></div>
    <div class="tenant-ms-chips"></div>
  `;

  const searchInput = container.querySelector(".tenant-ms-search");
  const resultsEl = container.querySelector(".tenant-ms-results");
  const chipsEl = container.querySelector(".tenant-ms-chips");

  function currentSelectionPayload() {
    return state.multi ? [...state.selectedValues] : (state.selectedValues[0] ?? null);
  }

  function renderChips() {
    if (!state.selectedValues.length) {
      chipsEl.innerHTML = `<span class="tenant-ms-empty-hint">${state.multi ? "No values selected yet -- search above to add one." : "No value selected -- search above."}</span>`;
      return;
    }
    chipsEl.innerHTML = state.selectedValues.map(v => {
      const opt = state.options.find(o => o.value === v);
      return `<span class="tenant-ms-chip">${escapeHtml(opt ? opt.label : String(v))}
        <button type="button" class="tenant-ms-chip-remove" data-value="${escapeHtml(String(v))}">&times;</button></span>`;
    }).join("");
    chipsEl.querySelectorAll(".tenant-ms-chip-remove").forEach(btn => {
      btn.addEventListener("click", () => {
        state.selectedValues = state.selectedValues.filter(v => String(v) !== btn.dataset.value);
        renderChips();
        state.onChange(currentSelectionPayload());
      });
    });
  }

  function runSearch() {
    const q = searchInput.value.trim().toLowerCase();
    const matches = state.options.filter(o =>
      !state.selectedValues.includes(o.value) && (!q || o.label.toLowerCase().includes(q))
    );
    resultsEl.style.display = "block";
    if (!matches.length) {
      resultsEl.innerHTML = `<div class="tenant-ms-result-row tenant-ms-empty">No matching values.</div>`;
      return;
    }
    resultsEl.innerHTML = matches.map(o =>
      `<div class="tenant-ms-result-row" data-value="${escapeHtml(String(o.value))}">${escapeHtml(o.label)}</div>`).join("");
    resultsEl.querySelectorAll(".tenant-ms-result-row[data-value]").forEach(row => {
      row.addEventListener("click", () => {
        const opt = matches.find(o => String(o.value) === row.dataset.value);
        if (!opt) return;
        state.selectedValues = state.multi ? [...state.selectedValues, opt.value] : [opt.value];
        searchInput.value = "";
        resultsEl.style.display = "none";
        resultsEl.innerHTML = "";
        renderChips();
        state.onChange(currentSelectionPayload());
      });
    });
  }

  searchInput.addEventListener("input", runSearch);
  searchInput.addEventListener("focus", runSearch);
  searchInput.addEventListener("blur", () => {
    setTimeout(() => { resultsEl.style.display = "none"; }, 150);
  });

  renderChips();
}

function getValuePickerSelection(container) {
  if (!container?._valuePickerState) return null;
  const state = container._valuePickerState;
  return state.multi ? [...state.selectedValues] : (state.selectedValues[0] ?? null);
}

window.renderTenantMultiSelect = renderTenantMultiSelect;
window.getTenantMultiSelectSelection = getTenantMultiSelectSelection;
window.renderTenantSingleSelect = renderTenantSingleSelect;
window.renderValuePicker = renderValuePicker;
window.getValuePickerSelection = getValuePickerSelection;
