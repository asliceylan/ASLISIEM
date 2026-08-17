import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense, Rule, Tenant, User
from backend.services.ingest_service import ingest_raw_log
from backend.simulator import log_templates, topology
from werkzeug.security import generate_password_hash


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


def _two_tenants_with_data():
    a = Tenant(name="Tenant A", slug="dash-a", enabled=True)
    b = Tenant(name="Tenant B", slug="dash-b", enabled=True)
    db.session.add_all([a, b])
    db.session.commit()

    mail = topology.DEVICES["dmz_mail"]
    for i in range(2):
        raw = log_templates.render_winevent(
            mail, datetime(2026, 1, 1, 12, i, 0), 4625,
            "An account failed to log on.", "jsmith", "203.0.113.1", logon_type=3,
        )
        ingest_raw_log(raw, mail, tenant_id=a.id)
    for i in range(5):
        raw = log_templates.render_winevent(
            mail, datetime(2026, 1, 1, 12, i, 0), 4625,
            "An account failed to log on.", "jsmith", "203.0.113.2", logon_type=3,
        )
        ingest_raw_log(raw, mail, tenant_id=b.id)

    db.session.add(Offense(title="A offense", severity="Critical", status="OPEN", tenant_id=a.id))
    db.session.add(Offense(title="B offense 1", severity="High", status="OPEN", tenant_id=b.id))
    db.session.add(Offense(title="B offense 2", severity="High", status="OPEN", tenant_id=b.id))
    db.session.commit()
    return a, b


def _login_full_admin(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})


def _login_as_tenant_admin(client, tenant):
    username = f"{tenant.slug}-dash-login"
    db.session.add(User(
        username=username, password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()
    client.post("/login", data={"username": username, "password": "pw"})


def test_stats_unscoped_for_full_admin_by_default(app):
    a, b = _two_tenants_with_data()
    client = app.test_client()
    _login_full_admin(client)
    data = client.get("/api/dashboard/stats").get_json()
    assert data["total_events"] == 7  # 2 + 5, both tenants combined
    assert data["total_rule_matches"] == 3


def test_stats_scoped_via_query_param_for_full_admin(app):
    a, b = _two_tenants_with_data()
    client = app.test_client()
    _login_full_admin(client)
    data = client.get(f"/api/dashboard/stats?tenant_id={a.id}").get_json()
    assert data["total_events"] == 2
    assert data["total_rule_matches"] == 1


def test_stats_forced_to_own_tenant_for_tenant_admin(app):
    a, b = _two_tenants_with_data()
    client = app.test_client()
    _login_as_tenant_admin(client, b)
    # Even requesting Tenant A's id explicitly must be ignored.
    data = client.get(f"/api/dashboard/stats?tenant_id={a.id}").get_json()
    assert data["total_events"] == 5
    assert data["total_rule_matches"] == 2


def test_top_source_ips_scoped_to_tenant(app):
    a, b = _two_tenants_with_data()
    client = app.test_client()
    _login_as_tenant_admin(client, a)
    data = client.get("/api/dashboard/top-source-ips").get_json()
    ips = {row["ip"] for row in data}
    assert ips == {"203.0.113.1"}


def test_recent_offenses_scoped_to_tenant(app):
    a, b = _two_tenants_with_data()
    client = app.test_client()
    _login_as_tenant_admin(client, b)
    data = client.get("/api/dashboard/recent-offenses").get_json()
    assert len(data) == 2
    assert all(o["title"].startswith("B offense") for o in data)
