from flask import Blueprint, request, jsonify

from backend.database.models import Event
from backend.services import auth_service, filter_service
from backend.services.event_service import build_mitre_guess, query_events

bp = Blueprint("events", __name__, url_prefix="/api/events")


@bp.route("", methods=["GET"])
def list_events():
    tenant_id = auth_service.tenant_scope(request.args.get("tenant_id"))
    try:
        filters = filter_service.parse_filters_json(request.args.get("filters"))
        items, total, page, per_page, truncated = query_events(request.args, tenant_id=tenant_id, filters=filters)
    except filter_service.InvalidFilterError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "items": [e.to_dict() for e in items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "truncated": truncated,
    })


@bp.route("/<int:event_id>", methods=["GET"])
def get_event(event_id):
    event = Event.query.get(event_id)
    if not event or not auth_service.can_access_tenant(event.tenant_id):
        return jsonify({"error": "Event not found"}), 404
    data = event.to_dict()
    data["mitre_guess"] = build_mitre_guess(event)
    return jsonify(data)
