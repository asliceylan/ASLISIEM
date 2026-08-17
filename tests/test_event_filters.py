import json
from datetime import datetime

import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Tenant


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


def _login_full_admin(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})


def _make_events():
    e1 = Event(event_id="1", event_name="Login Success", source_ip="10.0.0.5", username="alice",
               device_type="firewall", log_format="cef", timestamp=datetime(2026, 1, 1),
               raw_data=json.dumps({"__derived_fields__": {"Path": "/login"}}))
    e2 = Event(event_id="2", event_name="Login Failed", source_ip="10.0.0.9", username="bob",
               device_type="waf", log_format="access_log", timestamp=datetime(2026, 1, 2),
               raw_data=json.dumps({"__derived_fields__": {"Path": "/admin?id=1' OR '1'='1"}}))
    e3 = Event(event_id="3", event_name="Port Scan", source_ip="10.0.0.9", username=None,
               device_type="router", log_format="syslog", timestamp=datetime(2026, 1, 3),
               raw_data=json.dumps({}))
    db.session.add_all([e1, e2, e3])
    db.session.commit()
    return e1, e2, e3


def _filters_param(filters):
    return json.dumps(filters)


def test_device_type_filter(app):
    e1, e2, e3 = _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/events?filters={_filters_param([{'field':'device_type','operator':'equals','value':'waf'}])}")
    assert response.status_code == 200
    data = response.get_json()
    assert {e["event_id"] for e in data["items"]} == {"2"}
    assert data["truncated"] is False


def test_in_operator_matches_multiple_values(app):
    e1, e2, e3 = _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/events?filters={_filters_param([{'field':'device_type','operator':'in','value':'firewall,router'}])}")
    data = response.get_json()
    assert {e["event_id"] for e in data["items"]} == {"1", "3"}


def test_filters_combine_with_existing_named_params(app):
    e1, e2, e3 = _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(
        f"/api/events?source_ip=10.0.0.9&filters={_filters_param([{'field':'device_type','operator':'equals','value':'waf'}])}"
    )
    data = response.get_json()
    assert {e["event_id"] for e in data["items"]} == {"2"}


def test_path_derived_field_post_filter(app):
    e1, e2, e3 = _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/events?filters={_filters_param([{'field':'Path','operator':'contains','value':'admin'}])}")
    data = response.get_json()
    assert {e["event_id"] for e in data["items"]} == {"2"}
    assert data["total"] == 1
    assert data["truncated"] is False


def test_path_post_filter_combines_with_sql_filter(app):
    e1, e2, e3 = _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(
        f"/api/events?filters={_filters_param([{'field':'Path','operator':'exists','value':None}, {'field':'device_type','operator':'equals','value':'firewall'}])}"
    )
    data = response.get_json()
    assert {e["event_id"] for e in data["items"]} == {"1"}


def test_path_post_filter_paginates_correctly_in_memory(app):
    for i in range(5):
        db.session.add(Event(
            event_id=f"path-{i}", event_name="X", timestamp=datetime(2026, 1, 1),
            raw_data=json.dumps({"__derived_fields__": {"Path": "/match"}}),
        ))
    db.session.add(Event(event_id="no-match", event_name="X", timestamp=datetime(2026, 1, 1), raw_data=json.dumps({})))
    db.session.commit()

    client = app.test_client()
    _login_full_admin(client)
    response = client.get(
        f"/api/events?per_page=2&page=2&filters={_filters_param([{'field':'Path','operator':'equals','value':'/match'}])}"
    )
    data = response.get_json()
    assert data["total"] == 5
    assert len(data["items"]) == 2
    assert data["page"] == 2
    assert data["per_page"] == 2


def test_malformed_filters_json_returns_400(app):
    _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/events?filters=not-json")
    assert response.status_code == 400


def test_unknown_field_returns_400(app):
    _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/events?filters={_filters_param([{'field':'raw_data','operator':'equals','value':'x'}])}")
    assert response.status_code == 400


def test_no_filters_behaves_exactly_as_before(app):
    e1, e2, e3 = _make_events()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/events")
    data = response.get_json()
    assert data["total"] == 3
    assert data["truncated"] is False


def test_tenant_id_filter_field(app):
    e1, e2, e3 = _make_events()
    tenant = Tenant(name="Ev Filters T", slug="ev-filters-t", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    e1.tenant_id = tenant.id
    db.session.commit()

    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/events?filters={_filters_param([{'field':'tenant_id','operator':'equals','value':str(tenant.id)}])}")
    data = response.get_json()
    assert {e["event_id"] for e in data["items"]} == {"1"}
