import json
from backend.database.db import db
from backend.database.models import Event, Rule
from backend.engine.condition_evaluator import EVENT_COLUMNS, get_field_value


def list_rules(tenant_id=None):
    query = Rule.query
    if tenant_id is not None:
        query = query.filter_by(tenant_id=tenant_id)
    return query.order_by(Rule.created_at.desc()).all()


def get_rule(rule_id):
    return Rule.query.get(rule_id)


def create_rule(payload, tenant_id=None, auto_pattern_type=None):
    # tenant_id here must already be the resolved, authoritative value (see
    # auth_service.resolve_write_tenant_id) -- this function trusts its
    # caller, it does not re-derive it from payload/session itself.
    # auto_pattern_type is set only by suggestion_service's unattended
    # automation (see auto_apply_new_rule_suggestions) -- never by a
    # manually submitted payload, so it's a real function parameter, not
    # something read from payload.
    rule = Rule(
        name=payload.get("name"),
        description=payload.get("description"),
        enabled=payload.get("enabled", True),
        severity=payload.get("severity", "Medium"),
        conditions_json=json.dumps(payload.get("conditions", {})),
        grouping_json=json.dumps(payload.get("grouping", [])),
        threshold_count=payload.get("threshold_count", 1),
        distinct_field=payload.get("distinct_field") or None,
        time_window_value=payload.get("time_window_value", 0),
        time_window_unit=payload.get("time_window_unit", "minutes"),
        mitre_json=json.dumps(payload.get("mitre", [])),
        response=payload.get("response", "CREATE_OFFENSE"),
        tenant_id=tenant_id,
        auto_pattern_type=auto_pattern_type,
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def update_rule(rule_id, payload):
    rule = Rule.query.get(rule_id)
    if not rule:
        return None
    for field, column in [
        ("name", "name"),
        ("description", "description"),
        ("enabled", "enabled"),
        ("severity", "severity"),
        ("threshold_count", "threshold_count"),
        ("time_window_value", "time_window_value"),
        ("time_window_unit", "time_window_unit"),
        ("response", "response"),
    ]:
        if field in payload:
            setattr(rule, column, payload[field])
    if "distinct_field" in payload:
        rule.distinct_field = payload["distinct_field"] or None
    if "conditions" in payload:
        rule.conditions_json = json.dumps(payload["conditions"])
    if "grouping" in payload:
        rule.grouping_json = json.dumps(payload["grouping"])
    if "mitre" in payload:
        rule.mitre_json = json.dumps(payload["mitre"])
    db.session.commit()
    return rule


def copy_rule(rule_id, target_tenant_ids):
    """Creates one independent Rule copy per target tenant, cloning every
    rule-defining column (including the raw conditions_json/grouping_json/
    mitre_json/distinct_field strings, copied verbatim rather than
    re-parsed and re-serialized -- guarantees a byte-identical copy at
    creation time). Each copy is a brand-new row with its own id and no
    link back to the source: editing the source (or any other copy)
    afterward never affects the others. Returns the list of newly created
    Rule objects, in the same order as target_tenant_ids.

    Deliberately does NOT re-run find_unresolvable_fields against each
    target tenant's data -- the source rule was already validated once at
    creation time, and a copy landing in a tenant that doesn't (yet) have
    matching data is the same legitimate "write a rule before the data
    arrives" case find_unresolvable_fields itself already tolerates.

    auto_pattern_type is copied too: manually copying an auto-generated
    rule into another tenant "claims" that pattern_type for that tenant as
    well, so suggestion_service's automation won't independently create a
    duplicate there later (see auto_apply_new_rule_suggestions)."""
    source = Rule.query.get(rule_id)
    if not source:
        return None

    copies = []
    for tenant_id in target_tenant_ids:
        copy = Rule(
            name=source.name,
            description=source.description,
            enabled=source.enabled,
            severity=source.severity,
            conditions_json=source.conditions_json,
            grouping_json=source.grouping_json,
            threshold_count=source.threshold_count,
            distinct_field=source.distinct_field,
            time_window_value=source.time_window_value,
            time_window_unit=source.time_window_unit,
            mitre_json=source.mitre_json,
            response=source.response,
            tenant_id=tenant_id,
            auto_pattern_type=source.auto_pattern_type,
        )
        db.session.add(copy)
        copies.append(copy)
    db.session.commit()
    return copies


def delete_rule(rule_id):
    rule = Rule.query.get(rule_id)
    if not rule:
        return False
    db.session.delete(rule)
    db.session.commit()
    return True


def collect_referenced_fields(payload):
    """Every field name referenced by a rule payload's conditions, grouping,
    and distinct_field -- the full set that a saved rule would actually try
    to resolve via get_field_value at evaluation time."""
    fields = set()
    conditions = payload.get("conditions") or {}
    for group in conditions.get("groups", []):
        for cond in group.get("conditions", []):
            field = cond.get("field")
            if field:
                fields.add(field)
    for field in payload.get("grouping") or []:
        if field:
            fields.add(field)
    if payload.get("distinct_field"):
        fields.add(payload["distinct_field"])
    return fields


def find_unresolvable_fields(payload, tenant_id=None):
    """Field names that will never resolve to anything for this rule, so the
    rule builder/API can reject them up front instead of silently saving a
    rule that can never match (the same failure mode as the SQL Injection
    rule's "Path" field being corrupted into "event_id" without warning).

    EVENT_COLUMNS are always valid (real, always-resolvable Event columns).
    Anything else is only checked against currently-imported data -- there
    is no static list of possible CEF/derived field names, they come from
    whatever's actually been ingested (see normalizer.py), scoped to the
    rule's own tenant_id when given (a field only present in another
    tenant's data must still be rejected here). If the events table is
    empty, nothing is rejected: writing a rule before matching data has
    arrived is a legitimate, common workflow, not a mistake.
    """
    dynamic_fields = [f for f in collect_referenced_fields(payload) if f not in EVENT_COLUMNS]
    if not dynamic_fields:
        return []

    query = Event.query
    if tenant_id is not None:
        query = query.filter_by(tenant_id=tenant_id)
    events = query.all()
    if not events:
        return []

    unresolvable = []
    for field in dynamic_fields:
        if not any(get_field_value(e, field) not in (None, "") for e in events):
            unresolvable.append(field)
    return unresolvable
