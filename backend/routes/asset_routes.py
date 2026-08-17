from flask import Blueprint, jsonify, request

from backend.services import asset_service, auth_service

bp = Blueprint("assets", __name__, url_prefix="/api/assets")


@bp.route("", methods=["GET"])
def list_assets():
    tenant_id = auth_service.tenant_scope(request.args.get("tenant_id"))
    return jsonify(asset_service.list_assets(tenant_id=tenant_id))
