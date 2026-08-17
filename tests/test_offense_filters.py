import json
from datetime import datetime

import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense, Tenant

FILTERS_TENANT_SLUG = "off-filters-t"


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


def _make_offenses():
    tenant = Tenant(name="Off Filters T", slug=FILTERS_TENANT_SLUG, enabled=True)
    db.session.add(tenant)
    db.session.commit()
    o1 = Offense(title="Brute Force", severity="High", status="OPEN", source_ip="10.0.0.5", username="alice", tenant_id=tenant.id, created_at=datetime(2026, 1, 1))
    o2 = Offense(title="Port Scan", severity="Low", status="CLOSED", source_ip="10.0.0.9", username="bob", tenant_id=tenant.id, created_at=datetime(2026, 1, 5))
    o3 = Offense(title="SQL Injection", severity="Critical", status="OPEN", source_ip="10.0.0.9", username="alice", tenant_id=tenant.id, created_at=datetime(2026, 1, 10))
    db.session.add_all([o1, o2, o3])
    db.session.commit()
    return o1, o2, o3


def _filters_param(filters):
    return json.dumps(filters)


def test_status_filter_is_applied_server_side(app):
    o1, o2, o3 = _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?filters={_filters_param([{'field':'status','operator':'equals','value':'CLOSED'}])}")
    assert response.status_code == 200
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Port Scan"}


def test_severity_filter(app):
    o1, o2, o3 = _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?filters={_filters_param([{'field':'severity','operator':'equals','value':'Critical'}])}")
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"SQL Injection"}


def test_multiple_filters_combine_with_and(app):
    o1, o2, o3 = _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?filters={_filters_param([{'field':'source_ip','operator':'equals','value':'10.0.0.9'}, {'field':'username','operator':'equals','value':'alice'}])}")
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"SQL Injection"}


def test_filters_combine_with_existing_tenant_ids_scope(app):
    o1, o2, o3 = _make_offenses()
    other_tenant = Tenant(name="Other", slug="off-filters-other", enabled=True)
    db.session.add(other_tenant)
    db.session.commit()
    db.session.add(Offense(title="Other Tenant Open", severity="High", status="OPEN", tenant_id=other_tenant.id))
    db.session.commit()

    client = app.test_client()
    _login_full_admin(client)
    response = client.get(
        f"/api/offenses?tenant_ids={other_tenant.id}&filters={_filters_param([{'field':'status','operator':'equals','value':'OPEN'}])}"
    )
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Other Tenant Open"}


def test_created_at_greater_than_filter(app):
    o1, o2, o3 = _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?filters={_filters_param([{'field':'created_at','operator':'greater_than','value':'2026-01-03'}])}")
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Port Scan", "SQL Injection"}


def test_malformed_filters_json_returns_400(app):
    _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/offenses?filters={not-valid-json")
    assert response.status_code == 400
    assert "error" in response.get_json()


def test_unknown_filter_field_returns_400(app):
    _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?filters={_filters_param([{'field':'title','operator':'equals','value':'x'}])}")
    assert response.status_code == 400


def test_unknown_filter_operator_returns_400(app):
    _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?filters={_filters_param([{'field':'status','operator':'not_in','value':'x'}])}")
    assert response.status_code == 400


def test_no_filters_param_returns_everything_unfiltered(app):
    o1, o2, o3 = _make_offenses()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/offenses")
    assert response.status_code == 200
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Brute Force", "Port Scan", "SQL Injection"}
