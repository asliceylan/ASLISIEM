import os
import threading

from backend.simulator.runner import SimulatorThread

_lock = threading.Lock()
# One SimulatorThread per tenant, keyed by tenant_id -- replaces the old
# single global _thread now that each tenant gets its own independent
# Start/Stop control (see backend/database/models.Tenant). Access is always
# guarded by _lock since routes running in different request threads can
# start/stop different tenants concurrently.
_threads = {}

_IDLE_STATUS = {
    "running": False, "current_phase": None, "events_generated": 0,
    "rules_auto_created": 0, "last_error": None,
}


def start_simulator(app, tenant_id, devices=None, speed_multiplier=1.0):
    """Starts the background simulator thread for one tenant. No-ops if that
    tenant's simulator is already running. Defensively refuses to start
    inside the Werkzeug reloader's monitor process (debug=True spawns a
    parent that never serves HTTP and a child with WERKZEUG_RUN_MAIN=true
    that does) -- in this app's manual-start-only design that process never
    receives this call anyway, since only the serving child handles
    requests, but the check costs nothing and is exactly what was asked
    for."""
    global _threads
    with _lock:
        existing = _threads.get(tenant_id)
        if existing is not None and existing.is_alive():
            return {"started": False, "reason": "already running", **existing.status()}

        if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
            return {"started": False, "reason": "refusing to start in the reloader's monitor process"}

        thread = SimulatorThread(app, tenant_id=tenant_id, devices=devices, speed_multiplier=speed_multiplier)
        thread.start()
        _threads[tenant_id] = thread
        return {"started": True, **thread.status()}


def stop_simulator(tenant_id):
    global _threads
    with _lock:
        thread = _threads.get(tenant_id)
        if thread is None or not thread.is_alive():
            _threads.pop(tenant_id, None)
            return {"stopped": False, "reason": "not running", **_IDLE_STATUS}
        thread.stop()
        thread.join(timeout=2)
        status = thread.status()
        _threads.pop(tenant_id, None)
        return {"stopped": True, **status}


def get_status(tenant_id=None):
    """tenant_id=None returns an aggregate view (status of whichever tenant
    happens to be running, or idle if none are) -- kept for callers that
    predate multi-tenancy and only care "is anything running" (see
    log_source_service.py, not yet tenant-scoped itself). Real per-tenant
    callers always pass a concrete tenant_id."""
    with _lock:
        if tenant_id is None:
            for thread in _threads.values():
                if thread.is_alive():
                    return thread.status()
            return dict(_IDLE_STATUS)
        thread = _threads.get(tenant_id)
        if thread is None or not thread.is_alive():
            return dict(_IDLE_STATUS)
        return thread.status()


def get_all_statuses():
    """Returns {tenant_id: status} for every tenant that currently has (or
    recently had) a live thread -- lets the UI render every tenant's
    Log Simulator card from a single request instead of one per tenant."""
    with _lock:
        return {tenant_id: thread.status() for tenant_id, thread in _threads.items() if thread.is_alive()}


def is_running(tenant_id):
    with _lock:
        thread = _threads.get(tenant_id)
        return thread is not None and thread.is_alive()
