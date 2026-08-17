import os
import uuid

from backend.database.db import db
from backend.database.models import Import, Event
from backend.parsers.csv_parser import parse_csv
from backend.parsers.json_parser import parse_json
from backend.parsers.normalizer import (
    suggest_mapping, suggest_extraction, normalize_record, TARGET_FIELDS
)

def allowed_file(filename, allowed_ext):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_ext

def save_temp_file(file_storage, tmp_folder):
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    temp_id = uuid.uuid4().hex
    temp_name = f"{temp_id}.{ext}"
    path = os.path.join(tmp_folder, temp_name)
    file_storage.save(path)
    return temp_id, temp_name, path, ext

def parse_file(path, ext):
    if ext == "csv":
        return parse_csv(path)
    if ext == "json":
        return parse_json(path)
    raise ValueError("Unsupported file type")

def build_preview(original_filename, temp_name, path, ext):
    records, fields = parse_file(path, ext)
    source_headers = (records[0].get("__source_headers__", []) if records else [])
    direct = suggest_mapping(fields, records)
    extraction = suggest_extraction(fields, records)

    # For the user's known QRadar AQL export, the positional/semantic mapping
    # is more reliable than generic extraction suggestions. Generic extraction
    # is used only when no direct/QRadar mapping exists.
    mapping_suggestion = {}
    for target in TARGET_FIELDS:
        direct_spec = direct.get(target)
        extraction_spec = extraction.get(target)
        mapping_suggestion[target] = (
            direct_spec if direct_spec and direct_spec.get("source_field") else extraction_spec or direct_spec
        )

    qradar_preview_rows = []
    if len(fields) >= 84:
        for record in records[:5]:
            qradar_preview_rows.append({
                "Event ID": record.get("column_056"),
                "Event Name": record.get("column_022"),
                "Source IP": record.get("column_050"),
                "Timestamp": record.get("column_067"),
                "Process Name": __import__("backend.parsers.normalizer", fromlist=["_extract_key_value"])._extract_key_value(record.get("column_006"), "Process Name"),
                "Computer": record.get("column_005"),
                "Log Source": record.get("column_070"),
                "Raw Event": (record.get("column_021") or "")[:500],
            })

    return {
        "temp_name": temp_name,
        "original_filename": original_filename,
        "file_type": ext,
        "record_count": len(records),
        "detected_fields": fields,
        "source_headers": source_headers,
        "target_fields": TARGET_FIELDS,
        "suggested_mapping": mapping_suggestion,
        "preview_rows": records[:10],
        "qradar_preview_rows": qradar_preview_rows,
    }

def confirm_import(temp_name, original_filename, ext, mapping, tmp_folder, upload_folder, tenant_id=None):
    temp_path = os.path.join(tmp_folder, temp_name)
    if not os.path.exists(temp_path):
        raise FileNotFoundError("Uploaded temp file not found. Please re-upload.")

    records, fields = parse_file(temp_path, ext)
    file_size = os.path.getsize(temp_path)

    # Automatic import: no manual field mapping is required. Determine a
    # reliable normalization once from the actual source file, then apply it
    # to every row. All source columns/values are still preserved in raw_data.
    auto_mapping = suggest_mapping(fields, records)
    extraction = suggest_extraction(fields, records)
    effective_mapping = {}
    for target in TARGET_FIELDS:
        direct_spec = auto_mapping.get(target)
        extraction_spec = extraction.get(target)
        effective_mapping[target] = (
            direct_spec if direct_spec and direct_spec.get("source_field") else extraction_spec
        )

    imported_count = 0
    skipped_count = 0
    failed_count = 0

    import_row = Import(
        filename=original_filename,
        file_type=ext,
        file_size=file_size,
        event_count=0,
        status="IMPORTING",
    )
    db.session.add(import_row)
    db.session.flush()

    try:
        for record in records:
            try:
                normalized = normalize_record(record, effective_mapping)
                # Keep every source row, even if normalized fields are empty.
                db.session.add(Event(import_id=import_row.id, tenant_id=tenant_id, **normalized))
                imported_count += 1
            except Exception:
                failed_count += 1

        import_row.event_count = imported_count
        import_row.status = "IMPORTED" if failed_count == 0 else "IMPORTED_WITH_ERRORS"
        db.session.commit()
        # Verify the append actually reached the persistent database.
        persisted_count = Event.query.filter_by(import_id=import_row.id).count()
        if persisted_count != imported_count:
            raise RuntimeError(
                f"Persistence verification failed: expected {imported_count} events, found {persisted_count}"
            )
    except Exception:
        db.session.rollback()
        raise

    final_path = os.path.join(upload_folder, f"{import_row.id}_{original_filename}")
    try:
        os.replace(temp_path, final_path)
    except Exception:
        pass

    return {
        "import": import_row,
        "imported_count": imported_count,
        "skipped_count": skipped_count,
        "failed_count": failed_count,
        "source_record_count": len(records),
    }
