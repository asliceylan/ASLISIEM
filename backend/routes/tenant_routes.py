from flask import Blueprint, request, jsonify

from backend.services import auth_service, tenant_service

bp = Blueprint("tenants", __name__, url_prefix="/api/tenants")


@bp.route("", methods=["GET"])
@auth_service.require_full_admin
def list_tenants():
    return jsonify([t.to_dict() for t in tenant_service.list_tenants()])


@bp.route("", methods=["POST"])
@auth_service.require_full_admin
def create_tenant():
    payload = request.get_json(force=True)
    name = (payload.get("name") or "").strip()
    slug = (payload.get("slug") or "").strip().lower()
    if not name or not slug:
        return jsonify({"error": "name and slug are required"}), 400
    if tenant_service.get_tenant_by_slug(slug):
        return jsonify({"error": "slug already in use"}), 400
    tenant = tenant_service.create_tenant(name, slug)
    return jsonify(tenant.to_dict()), 201


@bp.route("/<int:tenant_id>", methods=["PUT"])
@auth_service.require_full_admin
def update_tenant(tenant_id):
    payload = request.get_json(force=True)
    tenant = tenant_service.update_tenant(tenant_id, payload)
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404
    return jsonify(tenant.to_dict())
