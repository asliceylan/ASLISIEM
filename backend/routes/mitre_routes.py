from flask import Blueprint, request, jsonify

from backend.config import Config
from backend.services import auth_service, mitre_catalog_service
from backend.services.mitre_sync_service import sync_domain, sync_all_domains

bp = Blueprint("mitre", __name__, url_prefix="/api/mitre")


@bp.route("/status", methods=["GET"])
def status():
    return jsonify(mitre_catalog_service.list_sync_status())


@bp.route("/sync", methods=["POST"])
@auth_service.require_full_admin
def sync():
    payload = request.get_json(silent=True) or {}
    domain = payload.get("domain")
    if domain:
        if domain not in Config.MITRE_DOMAINS:
            return jsonify({"error": f"Unknown domain '{domain}'"}), 400
        result = sync_domain(domain)
        return jsonify({"results": {domain: result}})
    results = sync_all_domains()
    return jsonify({"results": results})


@bp.route("/techniques", methods=["GET"])
def list_techniques():
    domain = request.args.get("domain")
    query = request.args.get("q", "")
    limit = request.args.get("limit", 25, type=int)
    if domain and domain not in Config.MITRE_DOMAINS:
        return jsonify({"error": f"Unknown domain '{domain}'"}), 400
    return jsonify(mitre_catalog_service.search_techniques(query=query, domain=domain, limit=limit))


@bp.route("/techniques/<technique_id>", methods=["GET"])
def get_technique(technique_id):
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "domain query parameter is required"}), 400
    if domain not in Config.MITRE_DOMAINS:
        return jsonify({"error": f"Unknown domain '{domain}'"}), 400
    technique = mitre_catalog_service.get_technique(domain, technique_id)
    if not technique:
        return jsonify({"error": "Technique not found"}), 404
    return jsonify(technique)
