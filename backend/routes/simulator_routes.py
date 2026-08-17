from flask import Blueprint, request, jsonify

from backend.services import auth_service, simulator_service

bp = Blueprint("simulator", __name__, url_prefix="/api/simulator")


def _check_tenant_access(tenant_id):
    """A tenant_admin may only control their own tenant's simulator; a
    full_admin may control any tenant's. Returns an (response, status)
    error pair to return immediately, or None if access is allowed."""
    if not auth_service.can_access_tenant(tenant_id):
        return jsonify({"error": "Not allowed to control this tenant's simulator"}), 403
    return None


@bp.route("/status-all", methods=["GET"])
def status_all():
    return jsonify(simulator_service.status_all())


@bp.route("/<int:tenant_id>/status", methods=["GET"])
def status(tenant_id):
    denied = _check_tenant_access(tenant_id)
    if denied:
        return denied
    return jsonify(simulator_service.status(tenant_id))


@bp.route("/<int:tenant_id>/start", methods=["POST"])
def start(tenant_id):
    denied = _check_tenant_access(tenant_id)
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    try:
        speed_multiplier = float(payload.get("speed_multiplier", 1.0))
    except (TypeError, ValueError):
        return jsonify({"error": "speed_multiplier must be a number"}), 400
    return jsonify(simulator_service.start(tenant_id, speed_multiplier=speed_multiplier))


@bp.route("/<int:tenant_id>/stop", methods=["POST"])
def stop(tenant_id):
    denied = _check_tenant_access(tenant_id)
    if denied:
        return denied
    return jsonify(simulator_service.stop(tenant_id))


@bp.route("/<int:tenant_id>/events", methods=["DELETE"])
def delete_events(tenant_id):
    denied = _check_tenant_access(tenant_id)
    if denied:
        return denied
    deleted_count = simulator_service.delete_simulated_events(tenant_id)
    return jsonify({"deleted_count": deleted_count})
