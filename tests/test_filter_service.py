import json
from datetime import datetime

import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event
from backend.services import filter_service


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _make_events():
    e1 = Event(
        event_id="1001", event_name="Login Success", source_ip="10.0.0.5",
        source_port="443", username="alice", device_type="firewall",
        log_format="cef", timestamp=datetime(2026, 1, 1, 10, 0, 0),
        raw_data=json.dumps({"__derived_fields__": {"Path": "/login"}}),
    )
    e2 = Event(
        event_id="1002", event_name="Login Failed", source_ip="10.0.0.9",
        source_port="8080", username="bob", device_type="waf",
        log_format="access_log", timestamp=datetime(2026, 1, 2, 10, 0, 0),
        raw_data=json.dumps({"__derived_fields__": {"Path": "/admin?id=1"}}),
    )
    e3 = Event(
        event_id="1003", event_name="Port Scan", source_ip="10.0.0.9",
        source_port="22", username=None, device_type="router",
        log_format="syslog", timestamp=datetime(2026, 1, 3, 10, 0, 0),
        raw_data=json.dumps({}),
    )
    db.session.add_all([e1, e2, e3])
    db.session.commit()
    return e1, e2, e3


# ---- validate_filters ----

def test_validate_filters_none_returns_empty_list(app):
    assert filter_service.validate_filters(None, filter_service.EVENT_FILTERABLE_FIELDS) == []


def test_validate_filters_rejects_unknown_field(app):
    with pytest.raises(filter_service.InvalidFilterError):
        filter_service.validate_filters(
            [{"field": "not_a_real_field", "operator": "equals", "value": "x"}],
            filter_service.EVENT_FILTERABLE_FIELDS,
        )


def test_validate_filters_rejects_unknown_operator(app):
    with pytest.raises(filter_service.InvalidFilterError):
        filter_service.validate_filters(
            [{"field": "source_ip", "operator": "not_in", "value": "x"}],
            filter_service.EVENT_FILTERABLE_FIELDS,
        )


def test_validate_filters_accepts_known_field_and_operator(app):
    filters = [{"field": "source_ip", "operator": "equals", "value": "10.0.0.5"}]
    assert filter_service.validate_filters(filters, filter_service.EVENT_FILTERABLE_FIELDS) == filters


# ---- parse_filters_json ----

def test_parse_filters_json_empty_returns_none(app):
    assert filter_service.parse_filters_json(None) is None
    assert filter_service.parse_filters_json("") is None


def test_parse_filters_json_parses_valid_json(app):
    raw = json.dumps([{"field": "source_ip", "operator": "equals", "value": "1.2.3.4"}])
    assert filter_service.parse_filters_json(raw) == [{"field": "source_ip", "operator": "equals", "value": "1.2.3.4"}]


def test_parse_filters_json_rejects_malformed_json(app):
    with pytest.raises(filter_service.InvalidFilterError):
        filter_service.parse_filters_json("{not valid json")


def test_parse_filters_json_rejects_non_list_json(app):
    with pytest.raises(filter_service.InvalidFilterError):
        filter_service.parse_filters_json(json.dumps({"field": "x"}))


# ---- split_sql_and_post_filters ----

def test_split_separates_path_as_post_filter(app):
    filters = [
        {"field": "source_ip", "operator": "equals", "value": "10.0.0.5"},
        {"field": "Path", "operator": "contains", "value": "/admin"},
    ]
    sql_filters, post_filters = filter_service.split_sql_and_post_filters(filters, filter_service.EVENT_FILTERABLE_FIELDS)
    assert sql_filters == [filters[0]]
    assert post_filters == [filters[1]]


# ---- apply_sql_filters: one sub-test per operator ----

def test_apply_sql_filters_equals_is_case_insensitive(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "username", "operator": "equals", "value": "ALICE"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert [e.id for e in q.all()] == [e1.id]


def test_apply_sql_filters_not_equals(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "source_ip", "operator": "not_equals", "value": "10.0.0.9"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert [e.id for e in q.all()] == [e1.id]


def test_apply_sql_filters_contains(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "event_name", "operator": "contains", "value": "login"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert {e.id for e in q.all()} == {e1.id, e2.id}


def test_apply_sql_filters_not_contains(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "event_name", "operator": "not_contains", "value": "login"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert [e.id for e in q.all()] == [e3.id]


def test_apply_sql_filters_in_matches_any_listed_value(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "device_type", "operator": "in", "value": "firewall,router"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert {e.id for e in q.all()} == {e1.id, e3.id}


def test_apply_sql_filters_exists(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "username", "operator": "exists", "value": None}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert {e.id for e in q.all()} == {e1.id, e2.id}


def test_apply_sql_filters_not_exists(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "username", "operator": "not_exists", "value": None}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert [e.id for e in q.all()] == [e3.id]


def test_apply_sql_filters_greater_than_and_less_than_on_timestamp(app):
    e1, e2, e3 = _make_events()
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "timestamp", "operator": "greater_than", "value": "2026-01-01 12:00:00"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert {e.id for e in q.all()} == {e2.id, e3.id}
    q2 = filter_service.apply_sql_filters(Event.query, Event, [{"field": "timestamp", "operator": "less_than", "value": "2026-01-02 12:00:00"}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert {e.id for e in q2.all()} == {e1.id, e2.id}


def test_apply_sql_filters_coerces_integer_column(app):
    e1, e2, e3 = _make_events()
    from backend.database.models import Tenant
    tenant = Tenant(name="T", slug="filter-test-t", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    e1.tenant_id = tenant.id
    db.session.commit()
    # value arrives as a string from the query string, must still match an Integer column
    q = filter_service.apply_sql_filters(Event.query, Event, [{"field": "tenant_id", "operator": "equals", "value": str(tenant.id)}], filter_service.EVENT_FILTERABLE_FIELDS)
    assert [e.id for e in q.all()] == [e1.id]


def test_apply_sql_filters_combines_multiple_conditions_with_and(app):
    e1, e2, e3 = _make_events()
    filters = [
        {"field": "source_ip", "operator": "equals", "value": "10.0.0.9"},
        {"field": "device_type", "operator": "equals", "value": "waf"},
    ]
    q = filter_service.apply_sql_filters(Event.query, Event, filters, filter_service.EVENT_FILTERABLE_FIELDS)
    assert [e.id for e in q.all()] == [e2.id]


# ---- apply_post_filters (Path, derived field via condition_evaluator) ----

def test_apply_post_filters_matches_derived_path_field(app):
    e1, e2, e3 = _make_events()
    filtered = filter_service.apply_post_filters([e1, e2, e3], [{"field": "Path", "operator": "contains", "value": "admin"}])
    assert [e.id for e in filtered] == [e2.id]


def test_apply_post_filters_empty_list_is_a_no_op(app):
    e1, e2, e3 = _make_events()
    assert filter_service.apply_post_filters([e1, e2, e3], []) == [e1, e2, e3]


def test_apply_post_filters_combines_with_and(app):
    e1, e2, e3 = _make_events()
    filters = [
        {"field": "Path", "operator": "exists", "value": None},
        {"field": "Path", "operator": "not_contains", "value": "admin"},
    ]
    filtered = filter_service.apply_post_filters([e1, e2, e3], filters)
    assert [e.id for e in filtered] == [e1.id]
