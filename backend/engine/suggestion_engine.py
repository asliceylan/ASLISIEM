import hashlib
from collections import defaultdict
from datetime import datetime

from backend.database.models import Event, OffenseEvent
from backend.engine import pattern_detectors

COVERAGE_SUPPRESS_RATIO = 0.8


def _stable_id(*parts):
    return hashlib.sha1(":".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _coverage_ratio(event_ids):
    if not event_ids:
        return 0.0
    covered = OffenseEvent.query.filter(OffenseEvent.event_id.in_(event_ids)).count()
    # covered may double-count an event linked to multiple offenses; that only
    # ever pushes the ratio up, which is the conservative (suppress-more)
    # direction for a "don't suggest what's already handled" filter.
    return min(covered / len(event_ids), 1.0)


def _source_ip(group_key):
    # group_key is either "source_ip" (port_scan/spray/sql_injection) or
    # "source_ip|username" (brute_force) -- see pattern_detectors._hit.
    return group_key.split("|", 1)[0]


def _aggregate_pattern_hits(pattern_hits):
    """One suggestion per pattern_type, not one per source IP: every hit of
    the same attack type shares an identical (attack-type-level, not
    per-actor) suggested_rule template (see pattern_detectors.py), so hits
    are merged into a single suggestion with aggregated evidence across all
    the actors/instances that triggered it."""
    by_type = defaultdict(list)
    for hit in pattern_hits:
        by_type[hit["pattern_type"]].append(hit)

    suggestions = []
    for pattern_type, hits in by_type.items():
        all_event_ids = sorted({eid for hit in hits for eid in hit["matched_event_ids"]})
        if _coverage_ratio(all_event_ids) >= COVERAGE_SUPPRESS_RATIO:
            continue

        distinct_sources = {_source_ip(hit["group_key"]) for hit in hits}
        first_seen = min(hit["first_seen"] for hit in hits)
        last_seen = max(hit["last_seen"] for hit in hits)
        template = hits[0]["suggested_rule"]

        suggestions.append({
            "id": _stable_id("new_rule", pattern_type),
            "kind": "new_rule",
            "pattern_type": pattern_type,
            "title": template["name"],
            "rationale": (
                f"{template['description']} Observed from {len(distinct_sources)} distinct source IP(s), "
                f"{len(all_event_ids)} matching event(s) total, between {first_seen.isoformat()} "
                f"and {last_seen.isoformat()}."
            ),
            "evidence": {
                "event_count": len(all_event_ids),
                "distinct_sources": len(distinct_sources),
                "first_seen": first_seen.isoformat() if first_seen else None,
                "last_seen": last_seen.isoformat() if last_seen else None,
            },
            "suggested_rule": template,
        })
    return suggestions


def generate_suggestions(tenant_id=None):
    """tenant_id=None scans every tenant's events (unscoped); a concrete
    tenant_id restricts pattern detection to that tenant's own events only
    -- mirrors rule_engine.run_all_rules(tenant_id=None)'s convention.

    Tuning suggestions (rule_tuning_advisor.py) are deliberately NOT
    produced here anymore -- they're unsuitable for unattended automation
    (see suggestion_service.auto_apply_new_rule_suggestions) and there is
    currently no UI surface left to review them manually. The module
    itself is untouched and still fully tested; it's just not wired in."""
    query = Event.query
    if tenant_id is not None:
        query = query.filter_by(tenant_id=tenant_id)
    events = query.all()

    pattern_hits = pattern_detectors.detect_all(events)
    new_rule_suggestions = _aggregate_pattern_hits(pattern_hits)

    return {
        "new_rule_suggestions": new_rule_suggestions,
        "generated_at": datetime.utcnow().isoformat(),
    }
