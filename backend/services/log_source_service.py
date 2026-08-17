from backend.database.models import Event, Tenant
from backend.simulator import control, topology

MANUAL_IMPORT_NAME = "Manual Import (AQL Export)"


def list_log_sources(tenant_id=None):
    """Computed live from Event on every call -- same "no persisted table"
    approach as asset_service.list_assets(). topology.DEVICES's simulator
    devices always have device.name == device.device_type (verified in
    topology.py), so Event.device_type values match topology keys directly
    with no separate mapping table needed.

    tenant_id=None (unscoped/full_admin default) reproduces the original
    single-tenant behavior exactly: topology.DEVICES plus a global
    event/simulator-status view. A concrete tenant_id switches to that
    tenant's own topology (topology.build_devices), its own events, and its
    own simulator status -- there is no aggregated multi-tenant view yet
    (would need per-tenant sections in the UI, left for a later iteration)."""
    devices = topology.DEVICES
    if tenant_id is not None:
        devices = topology.build_devices(Tenant.query.get(tenant_id))

    last_seen_by_device = {}
    last_seen_import = None

    events_q = Event.query
    if tenant_id is not None:
        events_q = events_q.filter_by(tenant_id=tenant_id)

    for event in events_q.all():
        ts = event.timestamp or event.created_at
        if not ts:
            continue
        if event.source == "import":
            if not last_seen_import or ts > last_seen_import:
                last_seen_import = ts
        elif event.device_type:
            current = last_seen_by_device.get(event.device_type)
            if not current or ts > current:
                last_seen_by_device[event.device_type] = ts

    sim_status = control.get_status(tenant_id)
    status_label = "Active" if sim_status["running"] else "Inactive"

    sources = []
    for device in devices.values():
        last_seen = last_seen_by_device.get(device.name)
        sources.append({
            "name": device.hostname,
            "device_type": device.name,
            "log_format": device.log_format,
            "status": status_label,
            "last_seen": last_seen.isoformat() if last_seen else None,
        })

    sources.append({
        "name": MANUAL_IMPORT_NAME,
        "device_type": None,
        "log_format": "csv/json",
        "status": "Manual",
        "last_seen": last_seen_import.isoformat() if last_seen_import else None,
    })

    return sources
