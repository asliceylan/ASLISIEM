from datetime import datetime, timedelta
from types import SimpleNamespace

from backend.engine.time_window_engine import find_matching_windows


def _event(ts, destination_port):
    return SimpleNamespace(timestamp=ts, created_at=ts, destination_port=destination_port)


def test_distinct_field_none_preserves_raw_count_behavior():
    base = datetime(2026, 1, 1, 12, 0, 0)
    events = [_event(base + timedelta(seconds=i), "443") for i in range(6)]
    windows = find_matching_windows(events, threshold_count=6, window_seconds=60)
    assert len(windows) == 1
    assert len(windows[0]) == 6


def test_distinct_field_rejects_burst_with_too_few_distinct_values():
    # 10 events within the window -- would satisfy a raw-count threshold of
    # 6, but only 3 distinct destination_port values ever appear, so a
    # distinct_field threshold of 6 must NOT match. This is the exact
    # mechanism that stops WAF/firewall-attack events (fixed dpt=443) from
    # satisfying the Port Scan rule.
    base = datetime(2026, 1, 1, 12, 0, 0)
    ports = ["443", "443", "443", "8080", "8080", "22", "443", "8080", "22", "443"]
    events = [_event(base + timedelta(seconds=i), p) for i, p in enumerate(ports)]
    windows = find_matching_windows(events, threshold_count=6, window_seconds=60, distinct_field="destination_port")
    assert windows == []


def test_distinct_field_matches_when_enough_distinct_values():
    base = datetime(2026, 1, 1, 12, 0, 0)
    ports = ["22", "80", "443", "3389", "8080", "8443"]
    events = [_event(base + timedelta(seconds=i), p) for i, p in enumerate(ports)]
    windows = find_matching_windows(events, threshold_count=6, window_seconds=60, distinct_field="destination_port")
    assert len(windows) == 1
    assert len(windows[0]) == 6


def test_distinct_field_with_no_time_window_counts_whole_group():
    base = datetime(2026, 1, 1, 12, 0, 0)
    ports = ["22", "80", "443", "22", "80", "443"]  # only 3 distinct values
    events = [_event(base + timedelta(hours=i), p) for i, p in enumerate(ports)]
    windows = find_matching_windows(events, threshold_count=6, window_seconds=0, distinct_field="destination_port")
    assert windows == []

    ports_enough = ["22", "80", "443", "3389", "8080", "8443"]
    events2 = [_event(base + timedelta(hours=i), p) for i, p in enumerate(ports_enough)]
    windows2 = find_matching_windows(events2, threshold_count=6, window_seconds=0, distinct_field="destination_port")
    assert len(windows2) == 1
