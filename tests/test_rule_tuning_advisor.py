import json
import pytest
from datetime import datetime, timedelta

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Offense, Rule
from backend.engine import rule_tuning_advisor


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _make_rule(conditions=None, grouping=None, threshold_count=1, time_window_value=0,
               time_window_unit="minutes", enabled=True, name="Test Rule"):
    rule = Rule(
        name=name,
        enabled=enabled,
        conditions_json=json.dumps(conditions or {}),
        grouping_json=json.dumps(grouping or []),
        threshold_count=threshold_count,
        time_window_value=time_window_value,
        time_window_unit=time_window_unit,
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def _fail_conditions():
    return {"logic": "OR", "groups": [{"logic": "AND", "conditions": [
        {"field": "event_name", "operator": "contains", "value": "fail"},
    ]}]}


def _make_event(source_ip, ts, username="jsmith", event_name="An account failed to log on."):
    event = Event(source_ip=source_ip, username=username, event_name=event_name,
                  event_id="4625", timestamp=ts, source="import")
    db.session.add(event)
    db.session.commit()
    return event


def _make_offense(rule):
    offense = Offense(rule_id=rule.id, title=rule.name, severity=rule.severity, status="OPEN")
    db.session.add(offense)
    db.session.commit()
    return offense


def test_detect_dead_rule_flags_matching_conditions_below_threshold(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=10)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(3):
        _make_event("203.0.113.44", base + timedelta(seconds=i))

    result = rule_tuning_advisor.detect_dead_rule(rule, Event.query.all())
    assert result["tuning_type"] == "dead_rule"
    assert result["rule_id"] == rule.id
    assert result["suggested_rule"]["threshold_count"] == 3


def test_detect_dead_rule_conditions_never_match_any_event(app):
    rule = _make_rule(conditions={"logic": "OR", "groups": [{"logic": "AND", "conditions": [
        {"field": "event_id", "operator": "equals", "value": "9999"},
    ]}]}, threshold_count=1)
    _make_event("203.0.113.44", datetime(2026, 1, 1, 12, 0, 0))

    result = rule_tuning_advisor.detect_dead_rule(rule, Event.query.all())
    assert result["tuning_type"] == "dead_rule"
    assert "never matches" in result["title"]


def test_detect_dead_rule_returns_none_when_offenses_exist(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=10)
    _make_offense(rule)
    _make_event("203.0.113.44", datetime(2026, 1, 1, 12, 0, 0))
    assert rule_tuning_advisor.detect_dead_rule(rule, Event.query.all()) is None


def test_detect_dead_rule_returns_none_for_disabled_rule(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=10, enabled=False)
    _make_event("203.0.113.44", datetime(2026, 1, 1, 12, 0, 0))
    assert rule_tuning_advisor.detect_dead_rule(rule, Event.query.all()) is None


def test_detect_noisy_rule_flags_outlier_offense_count(app):
    r1 = _make_rule(name="Noisy")
    r2 = _make_rule(name="Normal A")
    r3 = _make_rule(name="Normal B")
    counts = {r1.id: 15, r2.id: 2, r3.id: 3}

    result = rule_tuning_advisor.detect_noisy_rule(r1, counts)
    assert result["tuning_type"] == "noisy_rule"
    assert result["rule_id"] == r1.id
    assert result["suggested_rule"]["threshold_count"] > r1.threshold_count


def test_detect_noisy_rule_returns_none_when_close_to_peers(app):
    r1 = _make_rule(name="A")
    r2 = _make_rule(name="B")
    r3 = _make_rule(name="C")
    counts = {r1.id: 12, r2.id: 11, r3.id: 10}
    assert rule_tuning_advisor.detect_noisy_rule(r1, counts) is None


def test_detect_noisy_rule_returns_none_below_minimum_offenses(app):
    r1 = _make_rule(name="A")
    counts = {r1.id: 5}
    assert rule_tuning_advisor.detect_noisy_rule(r1, counts) is None


def test_detect_missing_time_window_flags_threshold_without_window(app):
    rule = _make_rule(threshold_count=5, time_window_value=0)
    result = rule_tuning_advisor.detect_missing_time_window(rule)
    assert result["tuning_type"] == "missing_time_window"
    assert result["suggested_rule"]["time_window_value"] > 0


def test_detect_missing_time_window_returns_none_when_window_set(app):
    rule = _make_rule(threshold_count=5, time_window_value=10, time_window_unit="minutes")
    assert rule_tuning_advisor.detect_missing_time_window(rule) is None


def test_detect_missing_time_window_returns_none_when_threshold_is_one(app):
    rule = _make_rule(threshold_count=1, time_window_value=0)
    assert rule_tuning_advisor.detect_missing_time_window(rule) is None


def test_detect_missing_grouping_flags_broad_ungrouped_conditions(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=3, grouping=[])
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
        _make_event(ip, base + timedelta(seconds=i))

    result = rule_tuning_advisor.detect_missing_grouping(rule, Event.query.all())
    assert result["tuning_type"] == "missing_grouping"
    assert result["suggested_rule"]["grouping"] == ["source_ip"]


def test_detect_missing_grouping_returns_none_when_already_grouped(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=3, grouping=["source_ip"])
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
        _make_event(ip, base + timedelta(seconds=i))
    assert rule_tuning_advisor.detect_missing_grouping(rule, Event.query.all()) is None


def test_detect_missing_grouping_returns_none_when_too_few_distinct_ips(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=3, grouping=[])
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, ip in enumerate(["203.0.113.1", "203.0.113.2"]):
        _make_event(ip, base + timedelta(seconds=i))
    assert rule_tuning_advisor.detect_missing_grouping(rule, Event.query.all()) is None


def test_advise_all_rules_stacks_multiple_issues_for_one_rule(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=3, grouping=[], time_window_value=0)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
        _make_event(ip, base + timedelta(seconds=i))

    suggestions = rule_tuning_advisor.advise_all_rules([rule], Event.query.all())
    types = {s["tuning_type"] for s in suggestions}
    assert "missing_time_window" in types
    assert "missing_grouping" in types
    assert all(s["rule_id"] == rule.id for s in suggestions)


def test_advise_all_rules_returns_nothing_for_well_tuned_rule(app):
    rule = _make_rule(conditions=_fail_conditions(), threshold_count=3, grouping=["source_ip"],
                       time_window_value=5, time_window_unit="minutes")
    _make_offense(rule)
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
        _make_event(ip, base + timedelta(seconds=i))

    assert rule_tuning_advisor.advise_all_rules([rule], Event.query.all()) == []
