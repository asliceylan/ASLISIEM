EVENT_COLUMNS = {
    "event_id", "event_name", "source_ip", "source_port",
    "destination_ip", "destination_port", "username", "process_name", "timestamp",
}


def get_field_value(event, field):
    """Fetch a field's value from an Event row, falling back to raw_data
    for fields that are not normalized Event columns."""
    if field in EVENT_COLUMNS:
        return getattr(event, field, None)
    raw = event.get_raw()
    # Search semantic fields extracted from QRadar key=value payloads first.
    derived = raw.get("__derived_fields__", {}) if isinstance(raw, dict) else {}
    if field in derived:
        return derived.get(field)
    lower_field = str(field).lower()
    for k, v in derived.items():
        if str(k).lower() == lower_field:
            return v
    # Search the original header-based source view.
    by_header = raw.get("__source_by_header__", {}) if isinstance(raw, dict) else {}
    if field in by_header:
        return by_header.get(field)
    for k, v in by_header.items():
        if str(k).lower() == lower_field:
            return v
    # Finally search the physical source columns.
    if field in raw:
        return raw.get(field)
    for k, v in raw.items():
        if str(k).lower() == lower_field:
            return v
    return None


def _to_comparable(value):
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)


def evaluate_condition(event, condition):
    """condition: {"field": str, "operator": str, "value": any}"""
    field = condition.get("field")
    operator = condition.get("operator")
    expected = condition.get("value")

    actual = get_field_value(event, field)

    if operator == "exists":
        return actual not in (None, "")
    if operator == "not_exists":
        return actual in (None, "")

    if operator in ("in", "not_in"):
        values = expected if isinstance(expected, list) else [
            v.strip() for v in str(expected).split(",")
        ]
        values_str = [str(v).lower() for v in values]
        actual_str = str(actual).lower() if actual is not None else ""
        result = actual_str in values_str
        return result if operator == "in" else not result

    if actual is None:
        # equals/contains/etc against a missing field is False; not_equals/not_contains is True
        return operator in ("not_equals", "not_contains")

    a = _to_comparable(actual)
    e = _to_comparable(expected)

    if operator == "equals":
        return str(actual).lower() == str(expected).lower()
    if operator == "not_equals":
        return str(actual).lower() != str(expected).lower()
    if operator == "contains":
        return str(expected).lower() in str(actual).lower()
    if operator == "not_contains":
        return str(expected).lower() not in str(actual).lower()
    if operator == "greater_than":
        try:
            return float(a) > float(e)
        except (TypeError, ValueError):
            return False
    if operator == "less_than":
        try:
            return float(a) < float(e)
        except (TypeError, ValueError):
            return False

    return False
