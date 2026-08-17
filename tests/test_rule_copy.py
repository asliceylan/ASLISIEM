import json
import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense, Rule, Tenant, User
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


def _three_tenants():
    a = Tenant(name="Tenant A", slug="copy-a", enabled=True)
    b = Tenant(name="Tenant B", slug="copy-b", enabled=True)
    c = Tenant(name="Tenant C", slug="copy-c", enabled=True)
    db.session.add_all([a, b, c])
    db.session.commit()
    return a, b, c


def _source_rule(tenant_id):
    rule = Rule(
        name="Failed Logon Rule", enabled=True, tenant_id=tenant_id, severity="High",
        description="desc", threshold_count=1, time_window_value=10, time_window_unit="minutes",
        distinct_field="source_ip",
        conditions_json=json.dumps({"logic": "OR", "groups": [{"logic": "AND", "conditions": [
            {"field": "event_id", "operator": "equals", "value": "4625"},
        ]}]}),
        grouping_json=json.dumps(["source_ip"]),
        mitre_json=json.dumps([{"tactic_id": "TA0006", "technique_id": "T1110"}]),
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def _login_full_admin(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})


def _failed_logon_event(tenant_id, source_ip="203.0.113.44"):
    mail = topology.DEVICES["dmz_mail"]
    raw = log_templates.render_winevent(
        mail, datetime(2026, 1, 1, 12, 0, 0), 4625,
        "An account failed to log on.", "jsmith", source_ip, logon_type=3,
    )
    return ingest_raw_log(raw, mail, tenant_id=tenant_id)


def test_copy_creates_independent_rule_per_target_tenant(app):
    a, b, c = _three_tenants()
    rule = _source_rule(a.id)
    client = app.test_client()
    _login_full_admin(client)

    response = client.post(f"/api/rules/{rule.id}/copy", json={"tenant_ids": [b.id, c.id]})
    assert response.status_code == 201
    copies = response.get_json()
    assert len(copies) == 2
    assert {c_["tenant_id"] for c_ in copies} == {b.id, c.id}
    assert all(c_["id"] != rule.id for c_ in copies)
    assert copies[0]["id"] != copies[1]["id"]

    for c_ in copies:
        stored = Rule.query.get(c_["id"])
        assert stored.name == "Failed Logon Rule"
        assert stored.conditions_json == rule.conditions_json
        assert stored.grouping_json == rule.grouping_json
        assert stored.mitre_json == rule.mitre_json
        assert stored.distinct_field == "source_ip"
        assert stored.threshold_count == 1


def test_editing_source_after_copy_does_not_affect_copies(app):
    a, b, _ = _three_tenants()
    rule = _source_rule(a.id)
    client = app.test_client()
    _login_full_admin(client)

    response = client.post(f"/api/rules/{rule.id}/copy", json={"tenant_ids": [b.id]})
    copy_id = response.get_json()[0]["id"]

    rule_service.update_rule(rule.id, {"name": "Renamed", "threshold_count": 99})

    copy = Rule.query.get(copy_id)
    assert copy.name == "Failed Logon Rule"
    assert copy.threshold_count == 1


def test_copy_is_immediately_evaluated_against_target_tenants_events(app):
    a, b, _ = _three_tenants()
    rule = _source_rule(a.id)
    _failed_logon_event(b.id)  # Tenant B already has a matching event
    client = app.test_client()
    _login_full_admin(client)

    client.post(f"/api/rules/{rule.id}/copy", json={"tenant_ids": [b.id]})

    offenses = Offense.query.filter_by(tenant_id=b.id).all()
    assert len(offenses) == 1
    assert Offense.query.filter_by(tenant_id=a.id).count() == 0  # source tenant untouched


def test_tenant_admin_cannot_copy_rules(app):
    a, b, _ = _three_tenants()
    rule = _source_rule(a.id)
    db.session.add(User(
        username="copy-tenant-admin", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=a.id,
    ))
    db.session.commit()
    client = app.test_client()
    client.post("/login", data={"username": "copy-tenant-admin", "password": "pw"})

    response = client.post(f"/api/rules/{rule.id}/copy", json={"tenant_ids": [b.id]})
    assert response.status_code == 403
    assert Rule.query.filter_by(tenant_id=b.id).count() == 0


def test_copy_nonexistent_rule_returns_404(app):
    _, b, _ = _three_tenants()
    client = app.test_client()
    _login_full_admin(client)
    response = client.post("/api/rules/99999/copy", json={"tenant_ids": [b.id]})
    assert response.status_code == 404


def test_copy_rejects_unknown_target_tenant(app):
    a, _, _ = _three_tenants()
    rule = _source_rule(a.id)
    client = app.test_client()
    _login_full_admin(client)
    response = client.post(f"/api/rules/{rule.id}/copy", json={"tenant_ids": [99999]})
    assert response.status_code == 400
    assert Rule.query.count() == 1  # only the source, no partial copy created


def test_copy_rejects_empty_tenant_ids(app):
    a, _, _ = _three_tenants()
    rule = _source_rule(a.id)
    client = app.test_client()
    _login_full_admin(client)
    response = client.post(f"/api/rules/{rule.id}/copy", json={"tenant_ids": []})
    assert response.status_code == 400
