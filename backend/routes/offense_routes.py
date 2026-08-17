from flask import Blueprint, request, jsonify

from backend.services import auth_service, offense_service, filter_service

bp = Blueprint("offenses", __name__, url_prefix="/api/offenses")


@bp.route("", methods=["GET"])
def list_offenses():
    tenant_ids = auth_service.tenant_scope_multi(request.args.get("tenant_ids"))
    try:
        filters = filter_service.parse_filters_json(request.args.get("filters"))
        offenses = offense_service.list_offenses(tenant_ids=tenant_ids, filters=filters)
    except filter_service.InvalidFilterError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify([o.to_dict() for o in offenses])


@bp.route("/<int:offense_id>", methods=["GET"])
def get_offense(offense_id):
    offense = offense_service.get_offense(offense_id)
    if not offense or not auth_service.can_access_tenant(offense.tenant_id):
        return jsonify({"error": "Offense not found"}), 404
    events = offense_service.get_offense_events(offense_id)
    data = offense.to_dict()
    data["events"] = [e.to_dict() for e in sorted(events, key=lambda e: e.timestamp or e.created_at)]
    return jsonify(data)


@bp.route("/<int:offense_id>/status", methods=["PUT"])
def set_status(offense_id):
    offense = offense_service.get_offense(offense_id)
    if not offense or not auth_service.can_access_tenant(offense.tenant_id):
        return jsonify({"error": "Offense not found"}), 404
    payload = request.get_json(force=True)
    status = payload.get("status")
    if status not in ("OPEN", "CLOSED"):
        return jsonify({"error": "status must be OPEN or CLOSED"}), 400
    offense = offense_service.update_status(offense_id, status)
    return jsonify(offense.to_dict())
