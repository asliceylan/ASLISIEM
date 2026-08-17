from flask import Blueprint, jsonify, request

from backend.services import auth_service, log_source_service

bp = Blueprint("log_sources", __name__, url_prefix="/api/log-sources")


@bp.route("", methods=["GET"])
def list_log_sources():
    tenant_id = auth_service.tenant_scope(request.args.get("tenant_id"))
    return jsonify(log_source_service.list_log_sources(tenant_id=tenant_id))
