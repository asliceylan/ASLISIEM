// Shared, page-agnostic "Add Filter" builder (QRadar-style Parameter +
// Operator + Value rows, all AND'd together, listed as removable chips).
// Mounted independently into Log Activity (events.js) and Offenses
// (offenses.js), each supplying its own field config and current filter
// list -- this file has no page-specific knowledge.
//
// A field config entry looks like:
//   { field: "device_type", label: "Device Type", type: "closed",
//     options: [{value:"firewall", label:"firewall"}, ...] }
//   { field: "source_ip", label: "Source IP", type: "free" }
// "closed" fields render their Value as renderValuePicker (tenant_
// multiselect.js); "free" fields render a plain text input. The 9
// operators mirror backend/services/filter_service.py's OPERATORS exactly
// (see that module's docstring for why "not_in" is deliberately excluded).

const FILTER_OPERATORS = [
  ["equals", "Equals"],
  ["not_equals", "Does Not Equal"],
  ["contains", "Contains"],
  ["not_contains", "Does Not Contain"],
  ["in", "Equals Any Of"],
  ["exists", "Exists"],
  ["not_exists", "Does Not Exist"],
  ["greater_than", "Greater Than"],
  ["less_than", "Less Than"],
];

function filterOperatorLabel(op) {
  const found = FILTER_OPERATORS.find(([v]) => v === op);
  return found ? found[1] : op;
}

function filterValueDisplay(cfg, f) {
  if (f.operator === "exists" || f.operator === "not_exists") return "";
  const labelFor = (v) => {
    if (cfg && cfg.type === "closed") {
      const opt = (cfg.options || []).find(o => o.value === v);
      return opt ? opt.label : String(v);
    }
    return String(v);
  };
  return Array.isArray(f.value) ? f.value.map(labelFor).join(", ") : labelFor(f.value);
}

// container: mount point. options.fieldConfigs: array as described above.
// options.filters: the page's current filter list (source of truth lives
// on the caller, e.g. window.eventsFilters -- same pattern as
// window.offensesTenantIds). options.onChange(filters) fires with the
// full, updated array on every add/remove.
function renderFilterBuilder(container, { fieldConfigs, filters, onChange }) {
  const state = { filters: [...(filters || [])], onChange: onChange || (() => {}) };

  container.innerHTML = `
    <div class="qf-add-row">
      <select class="qf-field"></select>
      <select class="qf-op"></select>
      <div class="qf-value-container"></div>
      <button type="button" class="secondary qf-add-btn">+ Add Filter</button>
    </div>
    <div class="tenant-ms-chips" style="margin-top:8px;"></div>
  `;

  const fieldSelect = container.querySelector(".qf-field");
  const opSelect = container.querySelector(".qf-op");
  const valueContainer = container.querySelector(".qf-value-container");
  const addBtn = container.querySelector(".qf-add-btn");
  const chipsEl = container.querySelector(".tenant-ms-chips");

  fieldSelect.innerHTML = fieldConfigs.map(f => `<option value="${f.field}">${escapeHtml(f.label || f.field)}</option>`).join("");
  opSelect.innerHTML = FILTER_OPERATORS.map(([v, l]) => `<option value="${v}">${l}</option>`).join("");

  function currentFieldConfig() {
    return fieldConfigs.find(f => f.field === fieldSelect.value) || fieldConfigs[0];
  }

  function renderValueInput() {
    const cfg = currentFieldConfig();
    const op = opSelect.value;
    if (op === "exists" || op === "not_exists") {
      valueContainer.innerHTML = `<span class="qf-no-value">(no value needed)</span>`;
      return;
    }
    if (cfg.type === "closed") {
      valueContainer.innerHTML = `<div class="qf-value-picker"></div>`;
      renderValuePicker(valueContainer.querySelector(".qf-value-picker"), {
        options: cfg.options,
        multi: op === "in",
      });
    } else {
      valueContainer.innerHTML = `<input type="text" class="qf-value-text" placeholder="Value">`;
    }
  }

  fieldSelect.addEventListener("change", renderValueInput);
  opSelect.addEventListener("change", renderValueInput);
  renderValueInput();

  function renderChips() {
    if (!state.filters.length) {
      chipsEl.innerHTML = `<span class="tenant-ms-empty-hint">No filters added yet.</span>`;
      return;
    }
    chipsEl.innerHTML = state.filters.map((f, idx) => {
      const cfg = fieldConfigs.find(fc => fc.field === f.field);
      const fieldLabel = cfg ? (cfg.label || cfg.field) : f.field;
      const valueLabel = filterValueDisplay(cfg, f);
      return `<span class="tenant-ms-chip">${escapeHtml(fieldLabel)} ${escapeHtml(filterOperatorLabel(f.operator).toLowerCase())}${valueLabel ? " " + escapeHtml(valueLabel) : ""}
        <button type="button" class="tenant-ms-chip-remove" data-idx="${idx}">&times;</button></span>`;
    }).join("");
    chipsEl.querySelectorAll(".tenant-ms-chip-remove").forEach(btn => {
      btn.addEventListener("click", () => {
        state.filters.splice(parseInt(btn.dataset.idx, 10), 1);
        renderChips();
        state.onChange([...state.filters]);
      });
    });
  }

  addBtn.addEventListener("click", () => {
    const cfg = currentFieldConfig();
    const op = opSelect.value;
    let value = null;
    if (op !== "exists" && op !== "not_exists") {
      if (cfg.type === "closed") {
        value = getValuePickerSelection(valueContainer.querySelector(".qf-value-picker"));
        const empty = op === "in" ? !(Array.isArray(value) && value.length) : (value === null || value === undefined);
        if (empty) { alert("Please select a value."); return; }
      } else {
        value = valueContainer.querySelector(".qf-value-text")?.value.trim() || "";
        if (!value) { alert("Please enter a value."); return; }
      }
    }
    state.filters.push({ field: cfg.field, operator: op, value });
    renderChips();
    state.onChange([...state.filters]);
    renderValueInput(); // reset the Value picker/input for the next filter
  });

  renderChips();
}

window.renderFilterBuilder = renderFilterBuilder;
