import pytest
from datetime import datetime, timedelta

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense, OffenseEvent, Tenant
from backend.engine import pattern_detectors, suggestion_engine
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


def _brute_force_events(source_ip="203.0.113.44", username="jsmith", tenant_id=None):
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


def test_generate_suggestions_returns_expected_shape(app):
    _brute_force_events()
    result = suggestion_engine.generate_suggestions()
    assert "new_rule_suggestions" in result
    assert "tuning_suggestions" not in result  # dropped -- see suggestion_engine docstring
    assert "generated_at" in result
    assert len(result["new_rule_suggestions"]) == 1
    assert result["new_rule_suggestions"][0]["pattern_type"] == "brute_force"
    assert result["new_rule_suggestions"][0]["kind"] == "new_rule"


def test_generate_suggestions_suppresses_already_covered_pattern(app):
    events = _brute_force_events()
    offense = Offense(title="Existing brute force offense", severity="High", status="OPEN")
    db.session.add(offense)
    db.session.flush()
    for event in events:
        db.session.add(OffenseEvent(offense_id=offense.id, event_id=event.id))
    db.session.commit()

    result = suggestion_engine.generate_suggestions()
    assert result["new_rule_suggestions"] == []


def test_generate_suggestions_deduplicates_same_pattern_across_source_ips(app):
    _brute_force_events(source_ip="203.0.113.44", username="jsmith")
    _brute_force_events(source_ip="203.0.113.99", username="agarcia")
    _brute_force_events(source_ip="203.0.113.5", username="bwong")

    result = suggestion_engine.generate_suggestions()
    brute_force_suggestions = [s for s in result["new_rule_suggestions"] if s["pattern_type"] == "brute_force"]
    assert len(brute_force_suggestions) == 1
    suggestion = brute_force_suggestions[0]
    assert "203.0.113" not in suggestion["title"]
    assert suggestion["evidence"]["distinct_sources"] == 3
    assert suggestion["evidence"]["event_count"] == 3 * pattern_detectors.BRUTE_FORCE_THRESHOLD


def test_generate_suggestions_ids_are_stable_across_calls(app):
    _brute_force_events()
    first = suggestion_engine.generate_suggestions()
    second = suggestion_engine.generate_suggestions()
    assert first["new_rule_suggestions"][0]["id"] == second["new_rule_suggestions"][0]["id"]


def _two_tenants():
    a = Tenant(name="Tenant A", slug="sugg-a", enabled=True)
    b = Tenant(name="Tenant B", slug="sugg-b", enabled=True)
    db.session.add_all([a, b])
    db.session.commit()
    return a, b


def test_generate_suggestions_is_scoped_to_tenant(app):
    a, b = _two_tenants()
    _brute_force_events(tenant_id=a.id)  # only Tenant A has matching events

    result_a = suggestion_engine.generate_suggestions(tenant_id=a.id)
    result_b = suggestion_engine.generate_suggestions(tenant_id=b.id)

    assert len(result_a["new_rule_suggestions"]) == 1
    assert result_b["new_rule_suggestions"] == []


def test_generate_suggestions_unscoped_sees_every_tenant(app):
    a, b = _two_tenants()
    _brute_force_events(source_ip="203.0.113.44", tenant_id=a.id)
    _brute_force_events(source_ip="203.0.113.99", username="agarcia", tenant_id=b.id)

    result = suggestion_engine.generate_suggestions()
    brute_force = [s for s in result["new_rule_suggestions"] if s["pattern_type"] == "brute_force"]
    assert len(brute_force) == 1
    assert brute_force[0]["evidence"]["distinct_sources"] == 2  # both tenants' events merged
