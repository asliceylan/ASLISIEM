let simulatorPollInterval = null;
let simulatorTenants = [];

async function loadSimulatorAdminPanel() {
  const el = document.getElementById("simulator-admin-panel");
  if (!el) return;

  const session = window.currentSession;
  if (!session) {
    el.innerHTML = `<div class="panel empty-state">Loading...</div>`;
    return;
  }

  // Full Admin sees a Start/Stop card per tenant; a Tenant Admin only ever
  // sees their own single tenant's card -- this is the log-GENERATION
  // surface, kept physically separate from the Tenants management page.
  simulatorTenants = session.role === "full_admin"
    ? await api("/tenants")
    : (session.tenant_id ? [{ id: session.tenant_id, name: session.tenant_name }] : []);

  if (!simulatorTenants.length) {
    el.innerHTML = `<div class="panel empty-state">No tenant available.</div>`;
    return;
  }

  el.innerHTML = simulatorTenants.map(t => `
    <div class="panel" style="margin-bottom:16px;">
      <h3>Log Simulator &mdash; ${escapeHtml(t.name)}</h3>
      <p style="color:var(--text-dim); font-size:12px; margin:0 0 12px;">
        Simulates a slow, realistic attacker kill-chain (recon &rarr; brute force &rarr; SQL injection &rarr; lateral movement)
        against this tenant's own virtual datacenter, streaming native-format logs (Syslog/CEF/Access Log/Windows-Event-style)
        while this app is running. Runs only in this process -- stopping the app stops the simulator.
      </p>
      <div class="toolbar" style="margin-bottom:10px;">
        <span class="badge STOPPED" id="sim-status-badge-${t.id}">STOPPED</span>
        <span id="sim-phase-label-${t.id}" style="color:var(--text-dim); font-size:12px;">Phase: -</span>
        <span id="sim-count-label-${t.id}" style="color:var(--text-dim); font-size:12px;">Events generated: 0</span>
      </div>
      <div class="toolbar">
        <input type="number" id="sim-speed-multiplier-${t.id}" value="1" min="1" max="500" title="Speed multiplier (1 = realistic pace, higher = faster for testing)">
        <button id="sim-start-btn-${t.id}" onclick="startSimulatorFromPanel(${t.id})">Start</button>
        <button class="secondary" id="sim-stop-btn-${t.id}" onclick="stopSimulatorFromPanel(${t.id})">Stop</button>
        <button class="danger" onclick="deleteSimulatedEventsFromPanel(${t.id})">Delete Simulated Events</button>
      </div>
      <div id="sim-error-label-${t.id}" style="color:var(--critical); font-size:12px; margin-top:8px;"></div>
    </div>`).join("");

  await refreshAllSimulatorStatuses();
  clearInterval(simulatorPollInterval);
  simulatorPollInterval = setInterval(refreshAllSimulatorStatuses, 4000);
}

function stopSimulatorAdminPolling() {
  clearInterval(simulatorPollInterval);
  simulatorPollInterval = null;
}

async function refreshAllSimulatorStatuses() {
  let statuses;
  try {
    statuses = await api("/simulator/status-all");
  } catch (err) {
    return;
  }
  const idle = { running: false, current_phase: null, events_generated: 0, last_error: null };
  for (const t of simulatorTenants) {
    applyStatusToPanel(t.id, statuses[t.id] || idle);
  }
}

function applyStatusToPanel(tenantId, status) {
  const badge = document.getElementById(`sim-status-badge-${tenantId}`);
  if (!badge) return; // panel no longer on screen
  badge.textContent = status.running ? "RUNNING" : "STOPPED";
  badge.className = `badge ${status.running ? "RUNNING" : "STOPPED"}`;
  document.getElementById(`sim-phase-label-${tenantId}`).textContent = `Phase: ${status.current_phase || "-"}`;
  document.getElementById(`sim-count-label-${tenantId}`).textContent = `Events generated: ${status.events_generated || 0}`;
  document.getElementById(`sim-error-label-${tenantId}`).textContent = status.last_error ? `Last error: ${status.last_error}` : "";
  document.getElementById(`sim-start-btn-${tenantId}`).disabled = !!status.running;
  document.getElementById(`sim-stop-btn-${tenantId}`).disabled = !status.running;
}

async function startSimulatorFromPanel(tenantId) {
  const speedInput = document.getElementById(`sim-speed-multiplier-${tenantId}`);
  const speed_multiplier = parseFloat(speedInput.value || "1");
  try {
    await api(`/simulator/${tenantId}/start`, { method: "POST", body: JSON.stringify({ speed_multiplier }) });
  } catch (err) {
    alert(err.message);
  }
  refreshAllSimulatorStatuses();
}

async function stopSimulatorFromPanel(tenantId) {
  try {
    await api(`/simulator/${tenantId}/stop`, { method: "POST" });
  } catch (err) {
    alert(err.message);
  }
  refreshAllSimulatorStatuses();
}

async function deleteSimulatedEventsFromPanel(tenantId) {
  if (!confirm("Delete all simulator-generated events for this tenant? Imported events are not affected. This cannot be undone.")) return;
  try {
    const result = await api(`/simulator/${tenantId}/events`, { method: "DELETE" });
    alert(`Deleted ${result.deleted_count} simulated event(s).`);
  } catch (err) {
    alert(err.message);
  }
  refreshAllSimulatorStatuses();
}

window.loadSimulatorAdminPanel = loadSimulatorAdminPanel;
window.stopSimulatorAdminPolling = stopSimulatorAdminPolling;
window.startSimulatorFromPanel = startSimulatorFromPanel;
window.stopSimulatorFromPanel = stopSimulatorFromPanel;
window.deleteSimulatedEventsFromPanel = deleteSimulatedEventsFromPanel;
