let eventsTimeChart = null;
let severityChart = null;

async function loadDashboard() {
  const [stats, eot, sev, topEvents, topIps, recentOff, ruleActivity, recentImports] = await Promise.all([
    api("/dashboard/stats"),
    api("/dashboard/events-over-time"),
    api("/dashboard/offense-severity"),
    api("/dashboard/top-event-types"),
    api("/dashboard/top-source-ips"),
    api("/dashboard/recent-offenses"),
    api("/dashboard/rule-activity"),
    api("/dashboard/recent-imports"),
  ]);

  renderKpis(stats);
  renderEventsOverTime(eot);
  renderSeverity(sev);
  renderTopList("top-event-types", topEvents, i => `${i.label} <b>${i.count}</b>`);
  renderTopList("top-source-ips", topIps, i => `${i.ip} <b>${i.count}</b>`);
  renderRuleActivity(ruleActivity);
  renderRecentOffenses(recentOff);
  renderRecentImports(recentImports);
}

function renderKpis(stats) {
  const cards = [
    ["Total Imported Events", stats.total_events],
    ["Open Offenses", stats.open_offenses],
    ["Critical Offenses", stats.critical_offenses],
    ["Active Detection Rules", stats.active_rules],
    ["Imported Files", stats.imported_files],
    ["Total Rule Matches", stats.total_rule_matches],
  ];
  document.getElementById("kpi-row").innerHTML = cards.map(([label, value]) => `
    <div class="kpi-card"><div class="label">${label}</div><div class="value">${value}</div></div>
  `).join("");
}

function renderEventsOverTime(data) {
  const ctx = document.getElementById("chart-events-time");
  if (eventsTimeChart) eventsTimeChart.destroy();
  if (!data.labels.length) {
    ctx.getContext("2d").clearRect(0, 0, ctx.width, ctx.height);
    return;
  }
  eventsTimeChart = new Chart(ctx, {
    type: "line",
    data: { labels: data.labels, datasets: [{ label: "Events", data: data.values, borderColor: "#3aa0ff", backgroundColor: "rgba(58,160,255,0.15)", fill: true, tension: 0.3 }] },
    options: { plugins: { legend: { display: false } }, scales: { x: { ticks: { color: "#8a95a5" } }, y: { ticks: { color: "#8a95a5" }, beginAtZero: true } } },
  });
}

function renderSeverity(data) {
  const ctx = document.getElementById("chart-severity");
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{ data: [data.Critical, data.High, data.Medium, data.Low], backgroundColor: ["#e5484d", "#f2994a", "#f2c94c", "#56c288"] }],
    },
    options: { plugins: { legend: { position: "bottom", labels: { color: "#d7dde5" } } } },
  });
}

function renderTopList(elId, items, renderFn) {
  const el = document.getElementById(elId);
  if (!items.length) { el.innerHTML = `<div class="empty-state">No data</div>`; return; }
  el.innerHTML = `<table>${items.map(i => `<tr><td>${renderFn(i)}</td></tr>`).join("")}</table>`;
}

function renderRuleActivity(rules) {
  const el = document.getElementById("rule-activity");
  if (!rules.length) { el.innerHTML = `<div class="empty-state">No detection rules created.</div>`; return; }
  el.innerHTML = `<table>${rules.map(r => `<tr><td>${escapeHtml(r.name)}</td><td style="text-align:right;">${r.match_count} matches</td></tr>`).join("")}</table>`;
}

function renderRecentOffenses(offenses) {
  const el = document.getElementById("recent-offenses");
  if (!offenses.length) { el.innerHTML = `<div class="empty-state">No offenses found.</div>`; return; }
  el.innerHTML = `<table>${offenses.map(o => `
    <tr class="clickable" onclick="openOffenseDetail(${o.id})">
      <td>#${o.id} ${escapeHtml(o.title)}</td>
      <td><span class="badge ${o.severity}">${o.severity}</span></td>
      <td><span class="badge ${o.status}">${o.status}</span></td>
    </tr>`).join("")}</table>`;
}

function renderRecentImports(imports) {
  const el = document.getElementById("recent-imports");
  if (!imports.length) { el.innerHTML = `<div class="empty-state">No events imported.</div>`; return; }
  el.innerHTML = `<table>${imports.map(i => `
    <tr><td>${escapeHtml(i.filename)}</td><td>${i.event_count} events</td><td>${i.status}</td></tr>`).join("")}</table>`;
}

window.loadDashboard = loadDashboard;
