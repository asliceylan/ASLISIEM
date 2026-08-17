from flask import Blueprint, request, jsonify

from backend.database.models import Tenant
from backend.services import auth_service, rule_service
from backend.engine.rule_engine import run_rule, run_all_rules

bp = Blueprint("rules", __name__, url_prefix="/api/rules")


def _get_accessible_rule(rule_id):
    """Fetches a rule, or None if it doesn't exist or the current user isn't
    allowed to see it (cross-tenant access) -- callers turn None into a 404,
    never leaking whether the rule exists in another tenant."""
    rule = rule_service.get_rule(rule_id)
    if not rule or not auth_service.can_access_tenant(rule.tenant_id):
        return None
    return rule


@bp.route("", methods=["GET"])
def list_rules():
    tenant_id = auth_service.tenant_scope(request.args.get("tenant_id"))
    rules = rule_service.list_rules(tenant_id=tenant_id)
    return jsonify([r.to_dict(include_stats=True) for r in rules])


@bp.route("", methods=["POST"])
def create_rule():
    payload = request.get_json(force=True)
    if not payload.get("name"):
        return jsonify({"error": "Rule name is required"}), 400
    tenant_id = auth_service.resolve_write_tenant_id(payload.get("tenant_id"))
    if tenant_id is None:
        return jsonify({"error": "tenant_id is required"}), 400
    unresolvable = rule_service.find_unresolvable_fields(payload, tenant_id=tenant_id)
    if unresolvable:
        return jsonify({"error": f"These fields don't match any imported event data: {', '.join(unresolvable)}"}), 400
    rule = rule_service.create_rule(payload, tenant_id=tenant_id)
    run_rule(rule)
    return jsonify(rule.to_dict()), 201


@bp.route("/<int:rule_id>", methods=["GET"])
def get_rule(rule_id):
    rule = _get_accessible_rule(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(rule.to_dict(include_stats=True))


@bp.route("/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    rule = _get_accessible_rule(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    payload = request.get_json(force=True)
    unresolvable = rule_service.find_unresolvable_fields(payload, tenant_id=rule.tenant_id)
    if unresolvable:
        return jsonify({"error": f"These fields don't match any imported event data: {', '.join(unresolvable)}"}), 400
    rule = rule_service.update_rule(rule_id, payload)
    run_rule(rule)
    return jsonify(rule.to_dict())


@bp.route("/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    if not _get_accessible_rule(rule_id):
        return jsonify({"error": "Rule not found"}), 404
    rule_service.delete_rule(rule_id)
    return jsonify({"deleted": True})


@bp.route("/<int:rule_id>/copy", methods=["POST"])
@auth_service.require_full_admin
def copy_rule(rule_id):
    # Full-admin only -- copying across tenants is a cross-tenant admin
    # action, not scoped to "the caller's own tenant" like everything else
    # in this file (see auth_service.require_full_admin).
    if not rule_service.get_rule(rule_id):
        return jsonify({"error": "Rule not found"}), 404

    payload = request.get_json(force=True)
    raw_tenant_ids = payload.get("tenant_ids")
    if not isinstance(raw_tenant_ids, list) or not raw_tenant_ids:
        return jsonify({"error": "tenant_ids must be a non-empty list"}), 400
    try:
        tenant_ids = [int(t) for t in raw_tenant_ids]
    except (TypeError, ValueError):
        return jsonify({"error": "tenant_ids must be a list of integers"}), 400

    unknown = [t for t in tenant_ids if Tenant.query.get(t) is None]
    if unknown:
        return jsonify({"error": f"Unknown tenant_id(s): {unknown}"}), 400

    copies = rule_service.copy_rule(rule_id, tenant_ids)
    for copy in copies:
        run_rule(copy)
    return jsonify([c.to_dict() for c in copies]), 201


@bp.route("/<int:rule_id>/evaluate", methods=["POST"])
def evaluate_rule(rule_id):
    rule = _get_accessible_rule(rule_id)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    offenses = run_rule(rule)
    return jsonify({
        "offenses_created_or_updated": len(offenses),
        "offense_ids": [o.id for o in offenses],
    })
