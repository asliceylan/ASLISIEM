async function loadAssets() {
  const assets = await api("/assets");
  renderAssetsTable(assets);
}

function renderAssetsTable(assets) {
  const el = document.getElementById("assets-table");
  if (!assets.length) {
    el.innerHTML = `<div class="empty-state">No assets discovered yet -- import or simulate some logs first.</div>`;
    return;
  }
  el.innerHTML = `
    <div style="color:var(--text-dim); font-size:12px; margin-bottom:8px;">${assets.length} asset(s), auto-discovered from log traffic</div>
    <table>
      <tr><th>IP Address</th><th>Scope</th><th>Device Type</th><th>Log Source</th><th>First Seen</th><th>Last Seen</th><th>Log Count</th><th>Offenses</th></tr>
      ${assets.map(a => `
        <tr>
          <td>${escapeHtml(a.ip)}</td>
          <td>${escapeHtml(a.scope)}</td>
          <td>${a.device_type ? escapeHtml(a.device_type) : `<span style="color:var(--text-dim);">Unknown</span>`}</td>
          <td>${a.log_formats ? escapeHtml(a.log_formats) : `<span style="color:var(--text-dim);">Unknown</span>`}</td>
          <td>${fmtDate(a.first_seen)}</td>
          <td>${fmtDate(a.last_seen)}</td>
          <td>${a.log_count}</td>
          <td>${a.offense_count}</td>
        </tr>`).join("")}
    </table>`;
}

window.loadAssets = loadAssets;
