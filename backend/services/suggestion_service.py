from backend.database.models import Rule
from backend.engine import suggestion_engine
from backend.engine.rule_engine import run_rule
from backend.services import rule_service


def auto_apply_new_rule_suggestions(tenant_id):
    """Called periodically (see backend/simulator/runner.py's
    SimulatorThread) while a tenant's simulator is running. Converts every
    new-rule suggestion for that tenant straight into a real, enabled Rule
    -- no human approval step -- and immediately evaluates it against that
    tenant's own events (may create offenses right away). Returns the list
    of newly created Rule objects (empty if nothing new this cycle).

    Dedup: skips any suggestion whose pattern_type already has a Rule for
    this tenant (Rule.auto_pattern_type match, regardless of whether that
    rule is currently enabled/disabled or was later edited/copied here).
    This is the primary, race-free guard -- it doesn't depend on a newly
    created rule having had time to accumulate offenses yet, unlike
    suggestion_engine's own coverage-ratio suppression, which stays in
    place as a complementary, slower-acting secondary signal (catches
    "some other rule already covers this pattern" even when no
    auto-generated rule exists yet), not a replacement for this check.

    Tuning suggestions are never part of this path -- see suggestion_
    engine.generate_suggestions()'s docstring for why they're unsuitable
    for unattended automation."""
    result = suggestion_engine.generate_suggestions(tenant_id=tenant_id)

    existing_pattern_types = {
        row[0] for row in Rule.query
        .filter_by(tenant_id=tenant_id)
        .filter(Rule.auto_pattern_type.isnot(None))
        .with_entities(Rule.auto_pattern_type)
        .all()
    }

    created = []
    for suggestion in result["new_rule_suggestions"]:
        pattern_type = suggestion["pattern_type"]
        if pattern_type in existing_pattern_types:
            continue
        rule = rule_service.create_rule(
            suggestion["suggested_rule"], tenant_id=tenant_id, auto_pattern_type=pattern_type,
        )
        run_rule(rule)
        created.append(rule)
        existing_pattern_types.add(pattern_type)

    return created
