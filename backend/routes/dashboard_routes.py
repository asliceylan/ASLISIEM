from collections import Counter
from flask import Blueprint, jsonify, request

from backend.database.models import Event, Import, Rule, Offense
from backend.config import Config
from backend.services import auth_service

bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


def _scope():
    return auth_service.tenant_scope(request.args.get("tenant_id"))


@bp.route("/stats", methods=["GET"])
def stats():
    tenant_id = _scope()
    events_q = Event.query
    offenses_q = Offense.query
    rules_q = Rule.query
    if tenant_id is not None:
        events_q = events_q.filter_by(tenant_id=tenant_id)
        offenses_q = offenses_q.filter_by(tenant_id=tenant_id)
        rules_q = rules_q.filter_by(tenant_id=tenant_id)

    total_events = events_q.count()
    open_offenses = offenses_q.filter_by(status="OPEN").count()
    critical_offenses = offenses_q.filter_by(severity="Critical").count()
    active_rules = rules_q.filter_by(enabled=True).count()
    # Import rows aren't tenant-scoped (see Event.tenant_id docstring's
    # sibling note in import_service.py) -- this count stays global for now.
    imported_files = Import.query.count()
    total_offenses = offenses_q.count()

    return jsonify({
        "total_events": total_events,
        "open_offenses": open_offenses,
        "critical_offenses": critical_offenses,
        "active_rules": active_rules,
        "imported_files": imported_files,
        "total_rule_matches": total_offenses,
    })


@bp.route("/events-over-time", methods=["GET"])
def events_over_time():
    tenant_id = _scope()
    q = Event.query.filter(Event.timestamp.isnot(None))
    if tenant_id is not None:
        q = q.filter_by(tenant_id=tenant_id)
    buckets = Counter()
    for e in q.all():
        key = e.timestamp.strftime("%Y-%m-%d %H:00")
        buckets[key] += 1
    labels = sorted(buckets.keys())
    return jsonify({"labels": labels, "values": [buckets[l] for l in labels]})


@bp.route("/offense-severity", methods=["GET"])
def offense_severity():
    tenant_id = _scope()
    q = Offense.query
    if tenant_id is not None:
        q = q.filter_by(tenant_id=tenant_id)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for o in q.all():
        if o.severity in counts:
            counts[o.severity] += 1
    return jsonify(counts)


@bp.route("/top-event-types", methods=["GET"])
def top_event_types():
    tenant_id = _scope()
    q = Event.query
    if tenant_id is not None:
        q = q.filter_by(tenant_id=tenant_id)
    counter = Counter()
    for e in q.all():
        label = f"{e.event_id or '-'} {e.event_name or ''}".strip()
        counter[label] += 1
    top = counter.most_common(10)
    return jsonify([{"label": k, "count": v} for k, v in top])


@bp.route("/top-source-ips", methods=["GET"])
def top_source_ips():
    tenant_id = _scope()
    q = Event.query
    if tenant_id is not None:
        q = q.filter_by(tenant_id=tenant_id)
    counter = Counter()
    for e in q.all():
        if e.source_ip:
            counter[e.source_ip] += 1
    top = counter.most_common(10)
    return jsonify([{"ip": k, "count": v} for k, v in top])


@bp.route("/recent-offenses", methods=["GET"])
def recent_offenses():
    tenant_id = _scope()
    q = Offense.query
    if tenant_id is not None:
        q = q.filter_by(tenant_id=tenant_id)
    offenses = q.order_by(Offense.created_at.desc()).limit(10).all()
    return jsonify([o.to_dict() for o in offenses])


@bp.route("/rule-activity", methods=["GET"])
def rule_activity():
    tenant_id = _scope()
    q = Rule.query
    if tenant_id is not None:
        q = q.filter_by(tenant_id=tenant_id)
    return jsonify([
        {"id": r.id, "name": r.name, "enabled": r.enabled, "match_count": len(r.offenses)}
        for r in q.all()
    ])


@bp.route("/recent-imports", methods=["GET"])
def recent_imports():
    # Import rows aren't tenant-scoped -- see the /stats note above.
    imports = Import.query.order_by(Import.imported_at.desc()).limit(10).all()
    return jsonify([i.to_dict() for i in imports])


@bp.route("/storage", methods=["GET"])
def storage():
    tenant_id = _scope()
    events_q = Event.query
    offenses_q = Offense.query
    if tenant_id is not None:
        events_q = events_q.filter_by(tenant_id=tenant_id)
        offenses_q = offenses_q.filter_by(tenant_id=tenant_id)
    return jsonify({
        "data_dir": Config.DATA_DIR,
        "database_path": Config.DB_PATH,
        "event_count": events_q.count(),
        "import_count": Import.query.count(),
        "offense_count": offenses_q.count(),
    })
