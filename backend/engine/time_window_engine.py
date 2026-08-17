from datetime import datetime

from backend.engine.condition_evaluator import get_field_value


def _ts(event):
    return event.timestamp or event.created_at or datetime.utcnow()


def _count(events, distinct_field):
    """Raw event count by default; count of DISTINCT values of
    distinct_field when one is given (e.g. "6 distinct destination_port
    values" instead of "6 events") -- see backend/database/models.py's
    Rule.distinct_field docstring for why this exists."""
    if distinct_field:
        return len({get_field_value(e, distinct_field) for e in events})
    return len(events)


def find_matching_windows(events, threshold_count, window_seconds, distinct_field=None):
    """Sort events by time and greedily find non-overlapping stretches where
    at least threshold_count events (or, if distinct_field is set, at least
    threshold_count DISTINCT values of that field) occur within
    window_seconds of each other.
    If window_seconds is 0, the whole group is treated as a single window
    (no time constraint), matching QRadar's behavior when no window is set."""
    events_sorted = sorted(events, key=_ts)
    n = len(events_sorted)
    windows = []

    if window_seconds <= 0:
        if _count(events_sorted, distinct_field) >= max(threshold_count, 1):
            windows.append(events_sorted)
        return windows

    i = 0
    while i < n:
        j = i
        while j < n and (_ts(events_sorted[j]) - _ts(events_sorted[i])).total_seconds() <= window_seconds:
            j += 1
        count = _count(events_sorted[i:j], distinct_field)
        if count >= threshold_count:
            windows.append(events_sorted[i:j])
            i = j
        else:
            i += 1
    return windows
