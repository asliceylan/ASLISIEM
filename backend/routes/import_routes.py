from flask import Blueprint, request, jsonify, current_app

from backend.services import auth_service
from backend.services.import_service import (
    allowed_file, save_temp_file, build_preview, confirm_import,
)
from backend.engine.rule_engine import run_all_rules
from backend.database.models import Import, Event

bp = Blueprint("imports", __name__, url_prefix="/api/import")

@bp.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename, current_app.config["ALLOWED_EXTENSIONS"]):
        return jsonify({"error": "Only CSV and JSON files are supported"}), 400

    temp_id, temp_name, path, ext = save_temp_file(file, current_app.config["TMP_UPLOAD_FOLDER"])
    try:
        preview = build_preview(file.filename, temp_name, path, ext)
    except Exception as exc:
        return jsonify({"error": f"Failed to parse file: {exc}"}), 400
    return jsonify(preview)

@bp.route("/confirm", methods=["POST"])
def confirm():
    payload = request.get_json(force=True) or {}
    temp_name = payload.get("temp_name")
    original_filename = payload.get("original_filename")
    file_type = payload.get("file_type")
    mapping = payload.get("mapping", {})

    if not temp_name or not original_filename or not file_type:
        return jsonify({"error": "Missing temp_name/original_filename/file_type"}), 400

    # A tenant_admin's imports always land in their own tenant; a full_admin
    # must pick one explicitly (same "every write belongs to exactly one
    # tenant" rule as rule creation -- see auth_service.resolve_write_tenant_id).
    tenant_id = auth_service.resolve_write_tenant_id(payload.get("tenant_id"))
    if tenant_id is None:
        return jsonify({"error": "tenant_id is required"}), 400

    try:
        result = confirm_import(
            temp_name, original_filename, file_type, mapping,
            current_app.config["TMP_UPLOAD_FOLDER"],
            current_app.config["UPLOAD_FOLDER"],
            tenant_id=tenant_id,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Import failed: {exc}"}), 500

    # Evaluate this tenant's rules against its (now larger) event set.
    # Events are append-only; historical imports remain in the same database.
    run_all_rules(tenant_id=tenant_id)

    import_row = result["import"]
    response = import_row.to_dict()
    response.update({
        "imported_count": result["imported_count"],
        "skipped_count": result["skipped_count"],
        "failed_count": result["failed_count"],
        "source_record_count": result["source_record_count"],
        "database_event_count": Event.query.count(),
        "database_import_count": Import.query.count(),
    })
    return jsonify(response)

@bp.route("", methods=["GET"])
def list_imports():
    imports = Import.query.order_by(Import.imported_at.desc()).all()
    return jsonify([i.to_dict() for i in imports])
