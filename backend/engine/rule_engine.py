from datetime import datetime

from backend.database.db import db
from backend.database.models import Event, Rule, Offense, OffenseEvent, RuleMatchGroup, RuleMatchWindow
from backend.engine.logical_evaluator import evaluate_condition_groups
from backend.engine.correlation_engine import group_events
from backend.engine.time_window_engine import find_matching_windows


def _event_ts(event):
    return event.timestamp or event.created_at or datetime.utcnow()


def run_rule(rule):
    """Evaluate a single rule against all real imported events currently in
    the database. Only creates an offense when the user-configured
    conditions, grouping, threshold and time window are all satisfied by
    real imported data. Returns the list of offenses created or updated.

    Only ever considers events whose tenant_id matches the rule's own --
    this is a correctness/security requirement, not a performance
    optimization: a tenant-scoped rule must never see another tenant's
    events. rule.tenant_id is commonly None in single-tenant contexts
    (existing tests, pre-migration data before schema_guard backfills it),
    in which case this naturally matches only the other equally-untenanted
    events (filter_by(tenant_id=None) -> WHERE tenant_id IS NULL)."""
    if not rule.enabled:
        return []

    conditions = rule.conditions()
    if not conditions or not conditions.get("groups"):
        return []  # a rule with no conditions must never match anything

    all_events = Event.query.filter_by(tenant_id=rule.tenant_id).all()
    matched = [e for e in all_events if evaluate_condition_groups(e, conditions)]
    if not matched:
        return []

    grouping_fields = rule.grouping()
    groups = group_events(matched, grouping_fields)

    window_seconds = rule.time_window_seconds()
    results = []

    for group_key, group_events_list in groups.items():
        windows = find_matching_windows(
            group_events_list, rule.threshold_count, window_seconds, distinct_field=rule.distinct_field,
        )
        for window_events in windows:
            offense = _create_or_update_offense(rule, group_key, window_events)
            if offense:
                results.append(offense)

    return results


def run_all_rules(tenant_id=None):
    """Runs every enabled rule. When tenant_id is given, only that tenant's
    rules are considered (used by each per-tenant simulator thread so it
    doesn't redundantly re-run every other tenant's rules on every cycle);
    omitting it preserves the original all-rules behavior. Per-rule event
    isolation happens inside run_rule() regardless of this parameter."""
    query = Rule.query.filter_by(enabled=True)
    if tenant_id is not None:
        query = query.filter_by(tenant_id=tenant_id)
    all_results = []
    for rule in query.all():
        all_results.extend(run_rule(rule))
    return all_results


def _create_or_update_offense(rule, group_key, window_events):
    """Create one durable offense per unique matched event window.

    Historical events are never deleted or replaced. Re-running a rule against
    the same database is idempotent because the exact event set has a stable
    fingerprint. When a later CSV import adds new matching events, its new
    matching window has a different fingerprint and therefore creates a new
    offense while all previous offenses remain intact.
    """
    if not window_events:
        return None

    event_ids = sorted({e.id for e in window_events})
    fingerprint = ",".join(str(eid) for eid in event_ids)
    existing_window = RuleMatchWindow.query.filter_by(
        rule_id=rule.id, event_fingerprint=fingerprint
    ).first()

    first_seen = min(_event_ts(e) for e in window_events)
    last_seen = max(_event_ts(e) for e in window_events)
    sample = min(window_events, key=_event_ts)

    if existing_window and existing_window.offense_id:
        offense = Offense.query.get(existing_window.offense_id)
        if offense:
            return offense

    # Backward compatibility for databases created before RuleMatchWindow was
    # introduced: if the legacy correlation record points to an offense whose
    # linked event set is exactly this window, register that historical window
    # instead of creating a duplicate offense.
    legacy_key = f"{rule.id}:{group_key}"
    legacy_group = RuleMatchGroup.query.filter_by(
        rule_id=rule.id, correlation_key=legacy_key
    ).first()
    if legacy_group and legacy_group.offense_id:
        legacy_offense = Offense.query.get(legacy_group.offense_id)
        if legacy_offense:
            legacy_ids = sorted(
                link.event_id for link in OffenseEvent.query.filter_by(
                    offense_id=legacy_offense.id
                ).all()
            )
            if legacy_ids == event_ids:
                db.session.add(RuleMatchWindow(
                    rule_id=rule.id,
                    correlation_key=group_key,
                    event_fingerprint=fingerprint,
                    offense_id=legacy_offense.id,
                    first_event_time=first_seen,
                    last_event_time=last_seen,
                ))
                db.session.commit()
                return legacy_offense

    offense = Offense(
        rule_id=rule.id,
        title=rule.name,
        description=rule.description,
        severity=rule.severity,
        status="OPEN",
        source_ip=getattr(sample, "source_ip", None),
        username=getattr(sample, "username", None),
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=len(event_ids),
        tenant_id=rule.tenant_id,
    )
    db.session.add(offense)
    db.session.flush()

    for eid in event_ids:
        db.session.add(OffenseEvent(offense_id=offense.id, event_id=eid))

    db.session.add(RuleMatchWindow(
        rule_id=rule.id,
        correlation_key=group_key,
        event_fingerprint=fingerprint,
        offense_id=offense.id,
        first_event_time=first_seen,
        last_event_time=last_seen,
    ))

    # Keep the legacy correlation record updated for compatibility with older
    # databases/UI logic, but do not use it as the sole duplicate key.
    correlation_key = f"{rule.id}:{group_key}"
    match_group = RuleMatchGroup.query.filter_by(
        rule_id=rule.id, correlation_key=correlation_key
    ).first()
    if match_group:
        match_group.offense_id = offense.id
        match_group.last_event_time = last_seen
    else:
        db.session.add(RuleMatchGroup(
            rule_id=rule.id,
            correlation_key=correlation_key,
            offense_id=offense.id,
            last_event_time=last_seen,
        ))

    db.session.commit()
    return offense
