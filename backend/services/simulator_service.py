from flask import current_app

from backend.database.db import db
from backend.database.models import Event, OffenseEvent, Tenant
from backend.simulator import control, topology


def start(tenant_id, speed_multiplier=1.0):
    tenant = Tenant.query.get(tenant_id)
    if tenant is None or not tenant.enabled:
        return {"started": False, "reason": "tenant not found or disabled"}
    devices = topology.build_devices(tenant)
    # Pass the real Flask app object (not the request-local proxy) since the
    # background thread outlives this request and needs app_context() itself.
    return control.start_simulator(
        current_app._get_current_object(), tenant_id=tenant_id, devices=devices,
        speed_multiplier=speed_multiplier,
    )


def stop(tenant_id):
    return control.stop_simulator(tenant_id)


def status(tenant_id):
    return control.get_status(tenant_id)


def status_all():
    return control.get_all_statuses()


def delete_simulated_events(tenant_id):
    """Deletes every simulator-sourced Event belonging to this tenant.
    OffenseEvent rows referencing them are deleted first -- there is no
    cascade from Event to OffenseEvent (only Offense -> OffenseEvent
    cascades), so skipping this would leave dangling references. Offenses
    themselves are left in place; their event_count/first_seen/last_seen
    may go stale -- a documented, accepted limitation of this manual,
    on-demand action (not automatic pruning)."""
    simulator_event_ids = [
        row[0] for row in db.session.query(Event.id)
        .filter_by(source="simulator", tenant_id=tenant_id).all()
    ]
    if not simulator_event_ids:
        return 0
    OffenseEvent.query.filter(OffenseEvent.event_id.in_(simulator_event_ids)).delete(synchronize_session=False)
    deleted = Event.query.filter(Event.id.in_(simulator_event_ids)).delete(synchronize_session=False)
    db.session.commit()
    return deleted
