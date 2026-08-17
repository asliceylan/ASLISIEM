async function loadLogSources() {
  const sources = await api("/log-sources");
  renderLogSourcesTable(sources);
}

function renderLogSourcesTable(sources) {
  const el = document.getElementById("log-sources-table");
  if (!sources.length) {
    el.innerHTML = `<div class="empty-state">No log sources configured.</div>`;
    return;
  }
  el.innerHTML = `<table>
    <tr><th>Name</th><th>Log Format</th><th>Status</th><th>Last Seen</th></tr>
    ${sources.map(s => `
      <tr>
        <td>${escapeHtml(s.name)}</td>
        <td>${escapeHtml(s.log_format)}</td>
        <td><span class="badge ${s.status === "Active" ? "SUCCESS" : s.status === "Inactive" ? "STOPPED" : "NEVER_RUN"}">${escapeHtml(s.status)}</span></td>
        <td>${s.last_seen ? fmtDate(s.last_seen) : `<span style="color:var(--text-dim);">Never</span>`}</td>
      </tr>`).join("")}
  </table>`;
}

window.loadLogSources = loadLogSources;
