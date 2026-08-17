from backend.engine.condition_evaluator import get_field_value


def group_events(events, grouping_fields):
    """Group events by the exact combination of values of grouping_fields.
    If grouping_fields is empty, all matched events form a single group."""
    groups = {}
    if not grouping_fields:
        groups["ALL"] = list(events)
        return groups

    for event in events:
        values = [str(get_field_value(event, field)) for field in grouping_fields]
        key = "|".join(f"{f}={v}" for f, v in zip(grouping_fields, values))
        groups.setdefault(key, []).append(event)
    return groups
