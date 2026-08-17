import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Tenant
from backend.services import rule_service
from backend.services.ingest_service import ingest_raw_log
from backend.simulator import log_templates, topology


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _payload(field):
    return {
        "name": "Test Rule",
        "conditions": {"logic": "OR", "groups": [{"logic": "AND", "conditions": [
            {"field": field, "operator": "exists", "value": ""},
        ]}]},
    }


def _seed_access_log_event(tenant_id=None):
    web = topology.DEVICES["dmz_web"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_access_log(web, ts, "203.0.113.44", "GET", "/product.php?id=1", 200, 512)
    return ingest_raw_log(raw, web, tenant_id=tenant_id)


def test_event_column_field_is_always_valid_even_with_no_data(app):
    assert rule_service.find_unresolvable_fields(_payload("event_id")) == []


def test_dynamic_field_with_no_events_is_allowed(app):
    # No data imported yet -- writing a rule proactively is legitimate,
    # must not be blocked.
    assert rule_service.find_unresolvable_fields(_payload("Path")) == []


def test_dynamic_field_present_in_existing_data_is_valid(app):
    _seed_access_log_event()
    assert rule_service.find_unresolvable_fields(_payload("Path")) == []


def test_dynamic_field_absent_from_all_data_is_rejected(app):
    _seed_access_log_event()
    result = rule_service.find_unresolvable_fields(_payload("Pathh"))
    assert result == ["Pathh"]


def test_unresolvable_grouping_field_is_rejected(app):
    _seed_access_log_event()
    payload = _payload("event_id")
    payload["grouping"] = ["NotARealField"]
    assert rule_service.find_unresolvable_fields(payload) == ["NotARealField"]


def test_unresolvable_distinct_field_is_rejected(app):
    _seed_access_log_event()
    payload = _payload("event_id")
    payload["distinct_field"] = "NotARealField"
    assert rule_service.find_unresolvable_fields(payload) == ["NotARealField"]


def test_valid_distinct_field_is_accepted(app):
    _seed_access_log_event()
    payload = _payload("event_id")
    payload["distinct_field"] = "destination_port"  # EVENT_COLUMNS member
    assert rule_service.find_unresolvable_fields(payload) == []


def test_create_rule_route_rejects_unresolvable_field(app):
    tenant_id = Tenant.query.first().id
    _seed_access_log_event(tenant_id=tenant_id)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    payload = _payload("Pathh")
    payload["tenant_id"] = tenant_id
    response = client.post("/api/rules", json=payload)
    assert response.status_code == 400
    assert "Pathh" in response.get_json()["error"]


def test_create_rule_route_accepts_valid_field(app):
    tenant_id = Tenant.query.first().id
    _seed_access_log_event(tenant_id=tenant_id)
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    payload = _payload("Path")
    payload["tenant_id"] = tenant_id
    response = client.post("/api/rules", json=payload)
    assert response.status_code == 201


def test_create_rule_route_requires_tenant_id_for_full_admin(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.post("/api/rules", json=_payload("event_id"))
    assert response.status_code == 400
    assert "tenant_id" in response.get_json()["error"]
