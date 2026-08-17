import json
import pytest
from datetime import datetime, timedelta

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Rule
from backend.engine import pattern_detectors, rule_engine
from backend.engine.logical_evaluator import evaluate_condition_groups
from tests.pattern_fixtures import (
    POSITIVE_FIXTURES,
    access_log_request as _access_log_request,
    fw_intrusion_hit as _fw_intrusion_hit,
    port_scan_hit as _port_scan_hit,
    waf_blocked_hit as _waf_blocked_hit,
    winevent as _winevent,
)


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_detect_brute_force_finds_burst_of_failed_logons(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.BRUTE_FORCE_THRESHOLD):
        _winevent(base + timedelta(seconds=i * 10), 4625, "jsmith", "203.0.113.44",
                  "An account failed to log on.")
    hits = pattern_detectors.detect_brute_force(Event.query.all())
    assert len(hits) == 1
    assert hits[0]["pattern_type"] == "brute_force"
    assert len(hits[0]["matched_event_ids"]) == pattern_detectors.BRUTE_FORCE_THRESHOLD
    assert hits[0]["suggested_rule"]["grouping"] == ["source_ip", "username"]
    assert hits[0]["suggested_rule"]["conditions"]["groups"][0]["conditions"][0]["value"] == "4625"


def test_detect_brute_force_below_threshold_is_not_flagged(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.BRUTE_FORCE_THRESHOLD - 1):
        _winevent(base + timedelta(seconds=i * 10), 4625, "jsmith", "203.0.113.44",
                  "An account failed to log on.")
    assert pattern_detectors.detect_brute_force(Event.query.all()) == []


def test_detect_password_spray_finds_many_distinct_usernames(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        _winevent(base + timedelta(seconds=i * 10), 4625, user, "203.0.113.44",
                  "An account failed to log on.")
    hits = pattern_detectors.detect_password_spray(Event.query.all())
    assert len(hits) == 1
    assert hits[0]["pattern_type"] == "password_spray"
    assert hits[0]["suggested_rule"]["grouping"] == ["source_ip"]


def test_detect_password_spray_below_threshold_is_not_flagged(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, user in enumerate(["alice", "bob", "carol"]):
        _winevent(base + timedelta(seconds=i * 10), 4625, user, "203.0.113.44",
                  "An account failed to log on.")
    assert pattern_detectors.detect_password_spray(Event.query.all()) == []


def test_detect_port_scan_finds_many_distinct_ports(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, port in enumerate([22, 80, 443, 3389, 8080, 8443]):
        _port_scan_hit(base + timedelta(seconds=i * 2), "203.0.113.44", port)
    hits = pattern_detectors.detect_port_scan(Event.query.all())
    assert len(hits) == 1
    assert hits[0]["pattern_type"] == "port_scan"


def test_port_scan_suggested_conditions_match_scan_but_not_web_traffic(app):
    # Validates the ACTUAL rule that would be created from this suggestion,
    # not just the detector's own event selection -- the two must agree.
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, port in enumerate([22, 80, 443, 3389, 8080, 8443]):
        _port_scan_hit(base + timedelta(seconds=i * 2), "203.0.113.44", port)
    hits = pattern_detectors.detect_port_scan(Event.query.all())
    conditions = hits[0]["suggested_rule"]["conditions"]

    scan_event = Event.query.get(hits[0]["matched_event_ids"][0])
    assert evaluate_condition_groups(scan_event, conditions)

    web_event = _access_log_request(base, "203.0.113.99", "id=1")
    assert not evaluate_condition_groups(web_event, conditions)


def test_detect_port_scan_below_threshold_is_not_flagged(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, port in enumerate([22, 80, 443]):
        _port_scan_hit(base + timedelta(seconds=i * 2), "203.0.113.44", port)
    assert pattern_detectors.detect_port_scan(Event.query.all()) == []


def test_detect_port_scan_ignores_access_log_web_traffic_burst(app):
    # access_log events always carry a destination_port (e.g. 443) but never
    # a source_port (access_log_parser.py hardcodes it to None) -- a burst of
    # ordinary web requests must NOT be mistaken for a port scan.
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(10):
        _access_log_request(base + timedelta(seconds=i), "203.0.113.44", f"id={i}")
    assert pattern_detectors.detect_port_scan(Event.query.all()) == []


def _create_port_scan_rule():
    """Mirrors exactly what 'Suggest Rules' -> 'Use this draft' -> Save
    would persist for the port_scan suggestion -- including distinct_field,
    the root-cause fix for the rule matching WAF/firewall-attack bursts."""
    rule = Rule(
        name="Port Scan: Multiple Destination Ports Probed",
        conditions_json=json.dumps(pattern_detectors.PORT_SCAN_CONDITIONS),
        grouping_json=json.dumps(["source_ip"]),
        threshold_count=pattern_detectors.PORT_SCAN_MIN_PORTS,
        distinct_field="destination_port",
        time_window_value=pattern_detectors.PORT_SCAN_WINDOW_SECONDS,
        time_window_unit="seconds",
    )
    db.session.add(rule)
    db.session.commit()
    return rule


def test_saved_port_scan_rule_still_matches_real_port_scan(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, port in enumerate([22, 80, 443, 3389, 8080, 8443]):
        _port_scan_hit(base + timedelta(seconds=i * 2), "203.0.113.44", port)
    rule = _create_port_scan_rule()
    assert len(rule_engine.run_rule(rule)) == 1


def test_saved_port_scan_rule_ignores_waf_blocked_burst(app):
    # Root-cause regression: WAF-blocked events always use a fixed
    # dpt=443 (see pattern_fixtures.waf_blocked_hit / scenario.py), so no
    # matter how many pile up they only ever contribute ONE distinct
    # destination_port value -- distinct_field is what actually stops this
    # now, at the SAVED RULE level (not just the Python detector).
    POSITIVE_FIXTURES["waf_blocked"]()
    rule = _create_port_scan_rule()
    assert rule_engine.run_rule(rule) == []


def test_saved_port_scan_rule_ignores_fw_attack_detected_burst(app):
    POSITIVE_FIXTURES["fw_attack_detected"]()
    rule = _create_port_scan_rule()
    assert rule_engine.run_rule(rule) == []


def test_detect_sql_injection_finds_burst_of_payloads(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    payloads = [
        "id=1'%20OR%20'1'='1",
        "id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "id=1;%20DROP%20TABLE%20users;--",
    ]
    for i, payload in enumerate(payloads):
        _access_log_request(base + timedelta(seconds=i * 5), "203.0.113.44", payload)
    hits = pattern_detectors.detect_sql_injection(Event.query.all())
    assert len(hits) == 1
    assert hits[0]["pattern_type"] == "sql_injection"
    # The generic template must actually match the events that triggered it
    # when run back through the real rule engine's condition evaluator.
    for event_id in hits[0]["matched_event_ids"]:
        event = Event.query.get(event_id)
        assert evaluate_condition_groups(event, hits[0]["suggested_rule"]["conditions"])


def test_detect_sql_injection_ignores_clean_requests(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(5):
        _access_log_request(base + timedelta(seconds=i * 5), "203.0.113.44", "id=1")
    assert pattern_detectors.detect_sql_injection(Event.query.all()) == []


def test_detect_waf_blocked_finds_burst(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.WAF_BLOCKED_MIN_HITS):
        _waf_blocked_hit(base + timedelta(seconds=i * 5), "203.0.113.44")
    hits = pattern_detectors.detect_waf_blocked(Event.query.all())
    assert len(hits) == 1
    assert hits[0]["pattern_type"] == "waf_blocked"


def test_detect_waf_blocked_below_threshold_is_not_flagged(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.WAF_BLOCKED_MIN_HITS - 1):
        _waf_blocked_hit(base + timedelta(seconds=i * 5), "203.0.113.44")
    assert pattern_detectors.detect_waf_blocked(Event.query.all()) == []


def test_detect_waf_blocked_ignores_non_waf_devices(app):
    # A regular firewall CEF event must never be mistaken for a WAF block,
    # even with a similarly-shaped extension -- device_type is the gate.
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, port in enumerate([22, 80, 443]):
        _port_scan_hit(base + timedelta(seconds=i * 2), "203.0.113.44", port)
    assert pattern_detectors.detect_waf_blocked(Event.query.all()) == []


def test_waf_blocked_suggested_conditions_match_real_event(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.WAF_BLOCKED_MIN_HITS):
        _waf_blocked_hit(base + timedelta(seconds=i * 5), "203.0.113.44")
    hits = pattern_detectors.detect_waf_blocked(Event.query.all())
    conditions = hits[0]["suggested_rule"]["conditions"]
    event = Event.query.get(hits[0]["matched_event_ids"][0])
    assert evaluate_condition_groups(event, conditions)


def test_detect_fw_attack_detected_finds_burst(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.FW_ATTACK_MIN_HITS):
        _fw_intrusion_hit(base + timedelta(seconds=i * 5), "203.0.113.44")
    hits = pattern_detectors.detect_fw_attack_detected(Event.query.all())
    assert len(hits) == 1
    assert hits[0]["pattern_type"] == "fw_attack_detected"


def test_detect_fw_attack_detected_below_threshold_is_not_flagged(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    _fw_intrusion_hit(base, "203.0.113.44")
    assert pattern_detectors.detect_fw_attack_detected(Event.query.all()) == []


def test_detect_fw_attack_detected_ignores_port_scan_signature(app):
    # Naming-collision regression: "Port Scan Detected" must never satisfy
    # the "Network Intrusion Detected" condition, and vice versa.
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i, port in enumerate([22, 80, 443]):
        _port_scan_hit(base + timedelta(seconds=i * 2), "203.0.113.44", port)
    assert pattern_detectors.detect_fw_attack_detected(Event.query.all()) == []


def test_fw_attack_detected_suggested_conditions_match_real_event(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.FW_ATTACK_MIN_HITS):
        _fw_intrusion_hit(base + timedelta(seconds=i * 5), "203.0.113.44")
    hits = pattern_detectors.detect_fw_attack_detected(Event.query.all())
    conditions = hits[0]["suggested_rule"]["conditions"]
    event = Event.query.get(hits[0]["matched_event_ids"][0])
    assert evaluate_condition_groups(event, conditions)


def test_detect_all_combines_every_detector(app):
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(pattern_detectors.BRUTE_FORCE_THRESHOLD):
        _winevent(base + timedelta(seconds=i * 10), 4625, "jsmith", "203.0.113.44",
                  "An account failed to log on.")
    hits = pattern_detectors.detect_all(Event.query.all())
    assert {h["pattern_type"] for h in hits} == {"brute_force"}
