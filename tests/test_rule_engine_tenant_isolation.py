import json
import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Offense, Rule, Tenant, User
from backend.engine.rule_engine import run_all_rules, run_rule
from backend.services import rule_service
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


def _two_tenants():
    a = Tenant(name="Tenant A", slug="tenant-a", enabled=True)
    b = Tenant(name="Tenant B", slug="tenant-b", enabled=True)
    db.session.add_all([a, b])
    db.session.commit()
    return a, b


def _bruteforce_rule(tenant_id, threshold=1):
    rule = Rule(
        name="Failed Logon Rule", enabled=True, tenant_id=tenant_id,
        conditions_json=json.dumps({"logic": "OR", "groups": [{"logic": "AND", "conditions": [
            {"field": "event_id", "operator": "equals", "value": "4625"},
        ]}]}),
        grouping_json=json.dumps(["source_ip"]),
        threshold_count=threshold, time_window_value=10, time_window_unit="minutes",
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def _failed_logon_event(tenant_id, source_ip="203.0.113.44"):
    mail = topology.DEVICES["dmz_mail"]
    raw = log_templates.render_winevent(
        mail, datetime(2026, 1, 1, 12, 0, 0), 4625,
        "An account failed to log on.", "jsmith", source_ip, logon_type=3,
    )
    return ingest_raw_log(raw, mail, tenant_id=tenant_id)


def test_rule_never_matches_another_tenants_event(app):
    a, b = _two_tenants()
    rule_b = _bruteforce_rule(b.id)
    _failed_logon_event(a.id)  # only Tenant A has a matching event

    offenses = run_rule(rule_b)

    assert offenses == []
    assert Offense.query.count() == 0


def test_rule_matches_its_own_tenants_event(app):
    a, b = _two_tenants()
    rule_b = _bruteforce_rule(b.id)
    _failed_logon_event(b.id)

    offenses = run_rule(rule_b)

    assert len(offenses) == 1
    assert offenses[0].tenant_id == b.id


def test_two_tenants_with_identical_rules_stay_fully_isolated(app):
    a, b = _two_tenants()
    rule_a = _bruteforce_rule(a.id)
    rule_b = _bruteforce_rule(b.id)
    _failed_logon_event(a.id, source_ip="203.0.113.1")
    _failed_logon_event(b.id, source_ip="203.0.113.2")

    offenses_a = run_rule(rule_a)
    offenses_b = run_rule(rule_b)

    assert len(offenses_a) == 1 and offenses_a[0].tenant_id == a.id
    assert len(offenses_b) == 1 and offenses_b[0].tenant_id == b.id
    # Each tenant's offense links only to its own tenant's event.
    assert Event.query.filter_by(tenant_id=a.id).count() == 1
    assert Event.query.filter_by(tenant_id=b.id).count() == 1


def test_run_all_rules_with_tenant_id_only_runs_that_tenants_rules(app):
    a, b = _two_tenants()
    _bruteforce_rule(a.id)
    _bruteforce_rule(b.id)
    _failed_logon_event(a.id)
    _failed_logon_event(b.id)

    offenses = run_all_rules(tenant_id=a.id)

    assert len(offenses) == 1
    assert offenses[0].tenant_id == a.id


def test_find_unresolvable_fields_is_scoped_to_tenant(app):
    a, b = _two_tenants()
    # Tenant A has data too (so "no events at all" doesn't short-circuit the
    # check), just never anything with a "Path" field -- only Tenant B's
    # access-log data has that.
    _failed_logon_event(a.id)
    web = topology.DEVICES["dmz_web"]
    raw = log_templates.render_access_log(web, datetime(2026, 1, 1), "203.0.113.44", "GET", "/x", 200, 100)
    ingest_raw_log(raw, web, tenant_id=b.id)

    payload = {"conditions": {"logic": "OR", "groups": [{"logic": "AND", "conditions": [
        {"field": "Path", "operator": "exists", "value": ""},
    ]}]}}
    assert rule_service.find_unresolvable_fields(payload, tenant_id=b.id) == []
    assert rule_service.find_unresolvable_fields(payload, tenant_id=a.id) == ["Path"]


def _login_as_tenant_admin(client, tenant):
    username = f"{tenant.slug}-login-admin"
    db.session.add(User(
        username=username, password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()
    client.post("/login", data={"username": username, "password": "pw"})


def test_tenant_admin_cannot_read_another_tenants_event_via_api(app):
    a, b = _two_tenants()
    event = _failed_logon_event(b.id)
    client = app.test_client()
    _login_as_tenant_admin(client, a)

    response = client.get(f"/api/events/{event.id}")
    assert response.status_code == 404


def test_tenant_admin_event_list_is_scoped_to_own_tenant(app):
    a, b = _two_tenants()
    _failed_logon_event(a.id, source_ip="203.0.113.10")
    _failed_logon_event(b.id, source_ip="203.0.113.20")
    client = app.test_client()
    _login_as_tenant_admin(client, a)

    response = client.get("/api/events")
    data = response.get_json()
    assert data["total"] == 1
    assert data["items"][0]["source_ip"] == "203.0.113.10"


def test_tenant_admin_cannot_read_another_tenants_rule_via_api(app):
    a, b = _two_tenants()
    rule_b = _bruteforce_rule(b.id)
    client = app.test_client()
    _login_as_tenant_admin(client, a)

    assert client.get(f"/api/rules/{rule_b.id}").status_code == 404
    assert client.put(f"/api/rules/{rule_b.id}", json={"name": "Hijacked"}).status_code == 404
    assert client.delete(f"/api/rules/{rule_b.id}").status_code == 404
    assert Rule.query.get(rule_b.id).name == "Failed Logon Rule"  # untouched


def test_tenant_admin_create_rule_is_forced_onto_own_tenant_regardless_of_payload(app):
    a, b = _two_tenants()
    client = app.test_client()
    _login_as_tenant_admin(client, a)

    payload = {
        "name": "Sneaky Rule", "tenant_id": b.id,  # attempts to write into Tenant B
        "conditions": {"logic": "OR", "groups": [{"logic": "AND", "conditions": [
            {"field": "event_id", "operator": "exists", "value": ""},
        ]}]},
    }
    response = client.post("/api/rules", json=payload)
    assert response.status_code == 201
    assert response.get_json()["tenant_id"] == a.id  # payload's tenant_id was ignored
