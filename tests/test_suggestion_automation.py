import pytest
from datetime import datetime, timedelta

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense, Rule, Tenant
from backend.engine import pattern_detectors
from backend.services import rule_service, suggestion_service
from backend.services.ingest_service import ingest_raw_log
from backend.simulator import log_templates, topology


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


def _tenant(slug="auto-a"):
    tenant = Tenant(name="Auto Tenant", slug=slug, enabled=True)
    db.session.add(tenant)
    db.session.commit()
    return tenant


def _brute_force_events(tenant_id, source_ip="203.0.113.44", username="jsmith"):
    mail = topology.DEVICES["dmz_mail"]
    base = datetime(2026, 1, 1, 12, 0, 0)
    events = []
    for i in range(pattern_detectors.BRUTE_FORCE_THRESHOLD):
        raw = log_templates.render_winevent(
            mail, base + timedelta(seconds=i * 10), 4625,
            "An account failed to log on.", username, source_ip, logon_type=3,
        )
        events.append(ingest_raw_log(raw, mail, tenant_id=tenant_id))
    return events


def test_auto_apply_creates_real_enabled_rule_and_runs_it_immediately(app):
    tenant = _tenant()
    _brute_force_events(tenant.id)

    created = suggestion_service.auto_apply_new_rule_suggestions(tenant.id)

    assert len(created) == 1
    rule = created[0]
    assert rule.tenant_id == tenant.id
    assert rule.enabled is True
    assert rule.auto_pattern_type == "brute_force"
    assert Rule.query.get(rule.id) is not None  # really persisted, not just in-memory

    # Immediately evaluated -- the pattern already matches enough events to
    # cross threshold, so it should have created an offense right away.
    assert Offense.query.filter_by(rule_id=rule.id, tenant_id=tenant.id).count() == 1


def test_auto_apply_never_creates_a_second_rule_for_the_same_pattern(app):
    tenant = _tenant()
    _brute_force_events(tenant.id)

    first = suggestion_service.auto_apply_new_rule_suggestions(tenant.id)
    assert len(first) == 1

    # Same pattern, more matching events land, called again immediately --
    # coverage-ratio suppression may not have kicked in yet, but the direct
    # auto_pattern_type dedup must still block a second rule regardless.
    _brute_force_events(tenant.id, source_ip="203.0.113.99", username="agarcia")
    second = suggestion_service.auto_apply_new_rule_suggestions(tenant.id)

    assert second == []
    assert Rule.query.filter_by(tenant_id=tenant.id, auto_pattern_type="brute_force").count() == 1


def test_auto_apply_is_scoped_per_tenant(app):
    a = _tenant("auto-b1")
    b = Tenant(name="Auto Tenant B", slug="auto-b2", enabled=True)
    db.session.add(b)
    db.session.commit()
    _brute_force_events(a.id)  # only tenant A has matching events

    created_a = suggestion_service.auto_apply_new_rule_suggestions(a.id)
    created_b = suggestion_service.auto_apply_new_rule_suggestions(b.id)

    assert len(created_a) == 1
    assert created_b == []
    assert Rule.query.filter_by(tenant_id=b.id).count() == 0


def test_copying_an_auto_generated_rule_prevents_duplicate_auto_creation_in_target(app):
    a = _tenant("auto-c1")
    b = Tenant(name="Auto Tenant C", slug="auto-c2", enabled=True)
    db.session.add(b)
    db.session.commit()

    _brute_force_events(a.id)
    created = suggestion_service.auto_apply_new_rule_suggestions(a.id)
    auto_rule = created[0]

    rule_service.copy_rule(auto_rule.id, [b.id])
    assert Rule.query.filter_by(tenant_id=b.id, auto_pattern_type="brute_force").count() == 1

    # Tenant B's own simulator later detects the same pattern independently --
    # must NOT create a second, redundant automatic rule.
    _brute_force_events(b.id, source_ip="203.0.113.7", username="cwhite")
    created_b = suggestion_service.auto_apply_new_rule_suggestions(b.id)
    assert created_b == []
    assert Rule.query.filter_by(tenant_id=b.id, auto_pattern_type="brute_force").count() == 1


def test_manual_rule_creation_is_unaffected_and_leaves_auto_pattern_type_none(app):
    # Critical regression proof: the manual "+ New Rule" flow (POST
    # /api/rules) must behave exactly as before this feature existed.
    tenant = _tenant("auto-manual")
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})

    response = client.post("/api/rules", json={
        "name": "Manually Written Rule", "tenant_id": tenant.id,
        "conditions": {"logic": "OR", "groups": [{"logic": "AND", "conditions": [
            {"field": "event_id", "operator": "exists", "value": ""},
        ]}]},
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["auto_pattern_type"] is None

    stored = Rule.query.get(data["id"])
    assert stored.auto_pattern_type is None
