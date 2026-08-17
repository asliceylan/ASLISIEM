async function loadTenantsPage() {
  if (!window.currentSession || window.currentSession.role !== "full_admin") {
    document.getElementById("tenants-table").innerHTML = `<div class="empty-state">Full Admin access required.</div>`;
    document.getElementById("users-table").innerHTML = "";
    return;
  }
  await renderTenantsTable();
  await renderUsersTable();
}

async function renderTenantsTable() {
  const tenants = await api("/tenants");
  const el = document.getElementById("tenants-table");
  if (!tenants.length) {
    el.innerHTML = `<div class="empty-state">No tenants yet.</div>`;
    return;
  }
  el.innerHTML = `<table>
    <tr><th>Name</th><th>Slug</th><th>Status</th><th></th></tr>
    ${tenants.map(t => `
      <tr>
        <td>${escapeHtml(t.name)}</td>
        <td>${escapeHtml(t.slug)}</td>
        <td><span class="badge ${t.enabled ? "RUNNING" : "STOPPED"}">${t.enabled ? "Enabled" : "Disabled"}</span></td>
        <td><button class="secondary" onclick="toggleTenantEnabled(${t.id}, ${!t.enabled})">${t.enabled ? "Disable" : "Enable"}</button></td>
      </tr>`).join("")}
  </table>`;
}

async function toggleTenantEnabled(tenantId, enabled) {
  try {
    await api(`/tenants/${tenantId}`, { method: "PUT", body: JSON.stringify({ enabled }) });
    renderTenantsTable();
  } catch (err) {
    alert(err.message);
  }
}

async function renderUsersTable() {
  const users = await api("/users");
  const el = document.getElementById("users-table");
  if (!users.length) {
    el.innerHTML = `<div class="empty-state">No users yet.</div>`;
    return;
  }
  const selfId = window.currentSession?.id;
  el.innerHTML = `<table>
    <tr><th>Username</th><th>Role</th><th>Tenant</th><th></th></tr>
    ${users.map(u => `
      <tr>
        <td>${escapeHtml(u.username)}</td>
        <td>${u.role === "full_admin" ? "Full Admin" : "Tenant Admin"}</td>
        <td>${escapeHtml(u.tenant_name || "-")}</td>
        <td style="white-space:nowrap;">
          <button class="secondary" onclick="resetUserPassword(${u.id})">Reset Password</button>
          <button class="danger" onclick="deleteUser(${u.id}, '${escapeHtml(u.username)}')" ${u.id === selfId ? "disabled title=\"Cannot delete your own account\"" : ""}>Delete</button>
        </td>
      </tr>`).join("")}
  </table>`;
}

async function resetUserPassword(userId) {
  const newPassword = prompt("Enter a new password for this user:");
  if (!newPassword) return;
  try {
    await api(`/users/${userId}/password`, { method: "PUT", body: JSON.stringify({ password: newPassword }) });
    alert("Password updated.");
  } catch (err) {
    alert(err.message);
  }
}

async function deleteUser(userId, username) {
  if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  try {
    await api(`/users/${userId}`, { method: "DELETE" });
    renderUsersTable();
  } catch (err) {
    alert(err.message);
  }
}

document.getElementById("new-tenant-btn")?.addEventListener("click", () => {
  openModal(`
    <h2>New Tenant</h2>
    <label>Name</label>
    <input type="text" id="tenant-name" placeholder="e.g. Acme Corp">
    <label style="margin-top:12px;">Slug</label>
    <input type="text" id="tenant-slug" placeholder="e.g. acme-corp">
    <div class="modal-actions">
      <button class="secondary" onclick="closeModal()">Cancel</button>
      <button id="save-tenant-btn">Create</button>
    </div>`);

  document.getElementById("save-tenant-btn").addEventListener("click", async () => {
    const name = document.getElementById("tenant-name").value.trim();
    const slug = document.getElementById("tenant-slug").value.trim();
    if (!name || !slug) { alert("Name and slug are required."); return; }
    try {
      await api("/tenants", { method: "POST", body: JSON.stringify({ name, slug }) });
      closeModal();
      renderTenantsTable();
    } catch (err) {
      alert(err.message);
    }
  });
});

document.getElementById("new-user-btn")?.addEventListener("click", async () => {
  const tenants = await api("/tenants");
  openModal(`
    <h2>New User</h2>
    <label>Username</label>
    <input type="text" id="user-username">
    <label style="margin-top:12px;">Password</label>
    <input type="password" id="user-password">
    <label style="margin-top:12px;">Role</label>
    <select id="user-role">
      <option value="tenant_admin">Tenant Admin</option>
      <option value="full_admin">Full Admin</option>
    </select>
    <label style="margin-top:12px;">Tenant (required for Tenant Admin)</label>
    <select id="user-tenant">
      <option value="">-- select tenant --</option>
      ${tenants.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("")}
    </select>
    <div class="modal-actions">
      <button class="secondary" onclick="closeModal()">Cancel</button>
      <button id="save-user-btn">Create</button>
    </div>`);

  document.getElementById("save-user-btn").addEventListener("click", async () => {
    const username = document.getElementById("user-username").value.trim();
    const password = document.getElementById("user-password").value;
    const role = document.getElementById("user-role").value;
    const tenantValue = document.getElementById("user-tenant").value;
    const tenant_id = tenantValue ? parseInt(tenantValue, 10) : null;
    if (!username || !password) { alert("Username and password are required."); return; }
    if (role === "tenant_admin" && !tenant_id) { alert("Select a tenant for a Tenant Admin."); return; }
    try {
      await api("/users", { method: "POST", body: JSON.stringify({ username, password, role, tenant_id }) });
      closeModal();
      renderUsersTable();
    } catch (err) {
      alert(err.message);
    }
  });
});

window.loadTenantsPage = loadTenantsPage;
window.toggleTenantEnabled = toggleTenantEnabled;
window.resetUserPassword = resetUserPassword;
window.deleteUser = deleteUser;
