from statistics import mean

from backend.engine.condition_evaluator import get_field_value
from backend.engine.correlation_engine import group_events
from backend.engine.logical_evaluator import evaluate_condition_groups
from backend.engine.time_window_engine import find_matching_windows

NOISY_MIN_OFFENSES = 10
NOISY_MULTIPLIER = 3
MISSING_WINDOW_SUGGESTED_MINUTES = 5
GROUPING_MIN_DISTINCT = 3


def detect_dead_rule(rule, all_events):
    """An enabled rule that has never produced an offense, even though its
    conditions do match imported events -- something about threshold/window/
    grouping is preventing it from ever firing."""
    if not rule.enabled or len(rule.offenses) > 0:
        return None
    conditions = rule.conditions()
    if not conditions or not conditions.get("groups"):
        return None

    matched = [e for e in all_events if evaluate_condition_groups(e, conditions)]
    if not matched:
        return {
            "tuning_type": "dead_rule",
            "rule_id": rule.id,
            "title": f"‘{rule.name}’ never matches any event",
            "rationale": "This rule's conditions do not match any currently imported event. Check the field names and values.",
            "suggested_rule": {},
        }

    groups = group_events(matched, rule.grouping())
    window_seconds = rule.time_window_seconds()
    any_window_reached = any(
        find_matching_windows(group, rule.threshold_count, window_seconds)
        for group in groups.values()
    )
    if any_window_reached:
        # The rule should already have produced an offense; whatever is
        # blocking it (e.g. it was only just enabled) isn't a tuning issue
        # this advisor can diagnose from static conditions alone.
        return None

    largest_group = max((len(group) for group in groups.values()), default=0)
    return {
        "tuning_type": "dead_rule",
        "rule_id": rule.id,
        "title": f"‘{rule.name}’ has never triggered",
        "rationale": (
            f"Conditions match {len(matched)} event(s) across {len(groups)} group(s), but none reach the "
            f"configured threshold of {rule.threshold_count} within the {rule.time_window_value} "
            f"{rule.time_window_unit} window. The largest group has {largest_group} matching event(s). "
            f"Consider lowering threshold_count to {largest_group} and/or widening the time window."
        ),
        "suggested_rule": {"threshold_count": max(largest_group, 1)},
    }


def detect_noisy_rule(rule, offense_counts_by_rule):
    """A rule producing far more offenses than its peers -- likely too
    permissive (low threshold, no time window, or too-broad conditions)."""
    if not rule.enabled:
        return None
    count = offense_counts_by_rule.get(rule.id, 0)
    if count < NOISY_MIN_OFFENSES:
        return None
    others = [c for rid, c in offense_counts_by_rule.items() if rid != rule.id and c > 0]
    if not others:
        return None
    avg_others = mean(others)
    if avg_others <= 0 or count < avg_others * NOISY_MULTIPLIER:
        return None

    suggested_threshold = rule.threshold_count + max(1, rule.threshold_count // 2)
    suggested_rule = {"threshold_count": suggested_threshold}
    window_hint = ""
    if not rule.time_window_seconds():
        suggested_rule["time_window_value"] = MISSING_WINDOW_SUGGESTED_MINUTES
        suggested_rule["time_window_unit"] = "minutes"
        window_hint = " and adding a time window"

    return {
        "tuning_type": "noisy_rule",
        "rule_id": rule.id,
        "title": f"‘{rule.name}’ is unusually noisy",
        "rationale": (
            f"This rule has produced {count} offenses, {count / avg_others:.1f}x the average of "
            f"{avg_others:.1f} across other active rules. Consider raising threshold_count to "
            f"{suggested_threshold}{window_hint}."
        ),
        "suggested_rule": suggested_rule,
    }


def detect_missing_time_window(rule):
    """threshold_count > 1 with no time window means the threshold can be
    satisfied by events spread arbitrarily far apart across the entire
    imported history, not just a real-time burst (see
    time_window_engine.find_matching_windows)."""
    if not rule.enabled or rule.threshold_count <= 1 or rule.time_window_seconds() > 0:
        return None
    return {
        "tuning_type": "missing_time_window",
        "rule_id": rule.id,
        "title": f"‘{rule.name}’ has a threshold but no time window",
        "rationale": (
            f"threshold_count is {rule.threshold_count} but no time window is set, so the threshold can be "
            f"satisfied by events spread arbitrarily far apart, not just a real-time burst. Consider adding "
            f"a {MISSING_WINDOW_SUGGESTED_MINUTES}-minute window."
        ),
        "suggested_rule": {
            "time_window_value": MISSING_WINDOW_SUGGESTED_MINUTES,
            "time_window_unit": "minutes",
        },
    }


def detect_missing_grouping(rule, all_events):
    """threshold_count > 1 with no grouping field mixes unrelated actors
    into a single correlation count."""
    if not rule.enabled or rule.threshold_count <= 1 or rule.grouping():
        return None
    conditions = rule.conditions()
    if not conditions or not conditions.get("groups"):
        return None
    matched = [e for e in all_events if evaluate_condition_groups(e, conditions)]
    distinct_ips = {get_field_value(e, "source_ip") for e in matched if get_field_value(e, "source_ip")}
    if len(distinct_ips) < GROUPING_MIN_DISTINCT:
        return None
    return {
        "tuning_type": "missing_grouping",
        "rule_id": rule.id,
        "title": f"‘{rule.name}’ has no grouping field",
        "rationale": (
            f"Matched events come from {len(distinct_ips)} distinct source IPs but are not grouped, so the "
            f"threshold count mixes unrelated actors together. Consider grouping by source_ip."
        ),
        "suggested_rule": {"grouping": ["source_ip"]},
    }


def advise_all_rules(rules, all_events):
    offense_counts = {r.id: len(r.offenses) for r in rules}
    checks = (
        lambda r: detect_dead_rule(r, all_events),
        lambda r: detect_noisy_rule(r, offense_counts),
        detect_missing_time_window,
        lambda r: detect_missing_grouping(r, all_events),
    )
    suggestions = []
    for rule in rules:
        for check in checks:
            result = check(rule)
            if result:
                suggestions.append(result)
    return suggestions
