"""Generic Parameter/Operator/Value filter engine shared by the Log
Activity (Event) and Offenses (Offense) "Add Filter" builders.

Mirrors the operator vocabulary of backend/engine/condition_evaluator.py
(used by the Rule engine) for consistency, but real, whitelisted columns
are translated into SQLAlchemy .filter() clauses here for efficient,
paginated DB-side filtering -- condition_evaluator's own in-memory
row-by-row evaluation is reused as-is (see apply_post_filters) only for
fields that are NOT real columns (e.g. Log Activity's "Path", resolved
from Event.raw_data's derived fields), since those can't be translated
to SQL at all.
"""
import json

from sqlalchemy import func

from backend.engine.condition_evaluator import evaluate_condition

# {field_name: real_column_attr_name_or_None}. A field mapped to None is
# not a real column -- apply_post_filters resolves it in Python instead of
# being translated to SQL by apply_sql_filters.
EVENT_FILTERABLE_FIELDS = {
    "event_id": "event_id",
    "event_name": "event_name",
    "source_ip": "source_ip",
    "source_port": "source_port",
    "destination_ip": "destination_ip",
    "destination_port": "destination_port",
    "username": "username",
    "process_name": "process_name",
    "timestamp": "timestamp",
    "device_type": "device_type",
    "log_format": "log_format",
    "tenant_id": "tenant_id",
    "Path": None,
}

OFFENSE_FILTERABLE_FIELDS = {
    "status": "status",
    "severity": "severity",
    "source_ip": "source_ip",
    "username": "username",
    "tenant_id": "tenant_id",
    "created_at": "created_at",
}

# Same 9 operators the "Add Filter" UI exposes (equals, does not equal,
# contains, does not contain, equals any of, exists, does not exist,
# greater than, less than). "not_in" is deliberately excluded -- it isn't
# offered in the UI and condition_evaluator's "in"/"not_in" pair isn't
# needed twice for this feature.
OPERATORS = {
    "equals", "not_equals", "contains", "not_contains", "in",
    "exists", "not_exists", "greater_than", "less_than",
}


class InvalidFilterError(ValueError):
    pass


def parse_filters_json(raw):
    """Parses the raw `filters` query-string value (JSON-encoded list of
    {field,operator,value} objects) into a Python list. Returns None (no
    filters) for an absent/empty value."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        raise InvalidFilterError("filters must be valid JSON")
    if not isinstance(parsed, list):
        raise InvalidFilterError("filters must be a JSON array")
    return parsed


def validate_filters(filters, allowed_fields):
    """Validates a parsed filter list against a page's field whitelist.
    Returns [] for None (no filters supplied) so callers can iterate the
    result unconditionally."""
    if filters is None:
        return []
    for f in filters:
        if not isinstance(f, dict):
            raise InvalidFilterError("each filter must be an object")
        field = f.get("field")
        operator = f.get("operator")
        if field not in allowed_fields:
            raise InvalidFilterError(f"unknown filter field: {field}")
        if operator not in OPERATORS:
            raise InvalidFilterError(f"unknown filter operator: {operator}")
    return filters


def split_sql_and_post_filters(filters, allowed_fields):
    """Splits a validated filter list into (sql_filters, post_filters)
    based on whether allowed_fields maps the field to a real column name
    (str) or None (post-filter/derived field)."""
    sql_filters = [f for f in filters if allowed_fields.get(f["field"]) is not None]
    post_filters = [f for f in filters if allowed_fields.get(f["field"]) is None]
    return sql_filters, post_filters


def _split_in_values(value):
    return value if isinstance(value, list) else [v.strip() for v in str(value).split(",")]


def _coerce(column, value):
    # SQLite is loosely typed, but comparing e.g. an Integer column
    # (tenant_id) against a string value from the UI is safer done
    # explicitly than left to implicit affinity coercion.
    try:
        col_type = column.type.python_type
    except (NotImplementedError, AttributeError):
        return value
    if col_type in (int, float) and value not in (None, ""):
        try:
            return col_type(value)
        except (TypeError, ValueError):
            return value
    return value


def _is_string_column(column):
    try:
        return column.type.python_type is str
    except (NotImplementedError, AttributeError):
        return False


def apply_sql_filters(query, model, filters, allowed_fields):
    """Applies the SQL-whitelisted subset of a validated filter list (see
    split_sql_and_post_filters) as AND'd SQLAlchemy .filter() clauses.
    String columns compare case-insensitively for equals/not_equals/in, to
    match condition_evaluator.evaluate_condition's own case-insensitive
    string comparisons (contains/not_contains already are, via .ilike())."""
    for f in filters:
        column = getattr(model, allowed_fields[f["field"]])
        operator = f["operator"]
        value = f.get("value")
        is_str_col = _is_string_column(column)

        if operator == "exists":
            query = query.filter(column.isnot(None))
        elif operator == "not_exists":
            query = query.filter(column.is_(None))
        elif operator == "in":
            values = _split_in_values(value)
            if is_str_col:
                query = query.filter(func.lower(column).in_([str(v).lower() for v in values]))
            else:
                query = query.filter(column.in_([_coerce(column, v) for v in values]))
        elif operator == "equals":
            if is_str_col:
                query = query.filter(func.lower(column) == str(value).lower())
            else:
                query = query.filter(column == _coerce(column, value))
        elif operator == "not_equals":
            if is_str_col:
                query = query.filter(func.lower(column) != str(value).lower())
            else:
                query = query.filter(column != _coerce(column, value))
        elif operator == "contains":
            query = query.filter(column.ilike(f"%{value}%"))
        elif operator == "not_contains":
            query = query.filter(~column.ilike(f"%{value}%"))
        elif operator == "greater_than":
            query = query.filter(column > _coerce(column, value))
        elif operator == "less_than":
            query = query.filter(column < _coerce(column, value))
    return query


def apply_post_filters(items, filters):
    """Applies the non-SQL (derived-field) subset of a validated filter
    list to an already-loaded list of Event ORM objects, reusing
    condition_evaluator's exact operator semantics -- see module
    docstring for why this can't be translated to SQL instead."""
    if not filters:
        return items
    return [item for item in items if all(evaluate_condition(item, f) for f in filters)]
