import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, MitreTechnique
from backend.engine import event_mitre_classifier
from backend.services.event_service import build_mitre_guess
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


def _winevent(event_id, message, username="jsmith", source_ip="203.0.113.44", logon_type=3):
    mail = topology.DEVICES["dmz_mail"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_winevent(mail, ts, event_id, message, username, source_ip, logon_type=logon_type)
    return ingest_raw_log(raw, mail)


def _cef(signature_id, name, ext):
    fw = topology.DEVICES["firewall"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_cef(fw, ts, signature_id, name, "7", ext)
    return ingest_raw_log(raw, fw)


def _access_log(query):
    web = topology.DEVICES["dmz_web"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_access_log(web, ts, "203.0.113.44", "GET", f"/product.php?{query}", 200, 512)
    return ingest_raw_log(raw, web)


def test_classify_event_failed_logon_returns_brute_force_technique(app):
    event = _winevent(4625, "An account failed to log on.")
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1110", "domain": "enterprise"}]


def test_classify_event_process_creation_returns_execution_technique(app):
    event = _winevent(4688, "A new process has been created.")
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1059", "domain": "enterprise"}]


def test_classify_event_special_privileges_returns_valid_accounts_technique(app):
    event = _winevent(4672, "Special privileges assigned to new logon.")
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1078", "domain": "enterprise"}]


def test_classify_event_account_created_returns_persistence_technique(app):
    event = _winevent(4720, "A user account was created.")
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1136", "domain": "enterprise"}]


def test_classify_event_audit_log_cleared_returns_defense_evasion_technique(app):
    event = _winevent(1102, "The audit log was cleared.")
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1070.001", "domain": "enterprise"}]


def test_classify_event_benign_successful_logon_returns_empty(app):
    event = _winevent(4624, "An account was successfully logged on.")
    assert event_mitre_classifier.classify_event(event) == []


def test_classify_event_device_labeled_port_scan_returns_recon_technique(app):
    ext = {"src": "203.0.113.44", "dst": "198.51.100.10", "dpt": "22", "act": "deny"}
    event = _cef("5001", "Port Scan Detected", ext)
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1595", "domain": "enterprise"}]


def test_classify_event_destination_port_alone_does_not_trigger_port_scan(app):
    # Same shape as a real network event (source/destination/port all set)
    # but the device did NOT label it a scan -- must NOT be tagged, unlike
    # pattern_detectors.detect_port_scan's group-level distinct-port count.
    ext = {"src": "198.51.100.20", "dst": "10.10.5.50", "dpt": "445", "act": "allow"}
    event = _cef("5010", "New Internal Connection Allowed", ext)
    assert event_mitre_classifier.classify_event(event) == []


def test_classify_event_sql_injection_payload_returns_exploit_technique(app):
    event = _access_log("id=1%20UNION%20SELECT%20username,password%20FROM%20users--")
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1190", "domain": "enterprise"}]


def test_classify_event_clean_access_log_returns_empty(app):
    event = _access_log("id=1")
    assert event_mitre_classifier.classify_event(event) == []


def test_classify_event_waf_blocked_device_returns_exploit_technique(app):
    waf = topology.DEVICES["waf"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    ext = {"src": "203.0.113.44", "dst": "198.51.100.10", "dpt": "443", "act": "blocked"}
    raw = log_templates.render_cef(waf, ts, "9001", "SQL Injection Attack Detected", "9", ext, product="WAF")
    event = ingest_raw_log(raw, waf)
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1190", "domain": "enterprise"}]


def test_classify_event_network_intrusion_detected_returns_exploit_technique(app):
    ext = {"src": "203.0.113.44", "dst": "198.51.100.10", "dpt": "443", "act": "deny"}
    event = _cef("5020", "Network Intrusion Detected", ext)
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1190", "domain": "enterprise"}]


def test_classify_event_port_scan_does_not_trigger_waf_or_intrusion_signals(app):
    # Naming/device-type collision regression, mirroring the equivalent
    # pattern_detectors check: the existing "Port Scan Detected" signature
    # must not accidentally satisfy the new WAF/intrusion signals.
    ext = {"src": "203.0.113.44", "dst": "198.51.100.10", "dpt": "22", "act": "deny"}
    event = _cef("5001", "Port Scan Detected", ext)
    result = event_mitre_classifier.classify_event(event)
    assert result == [{"technique_id": "T1595", "domain": "enterprise"}]


def test_classify_event_multiple_signals_returns_multiple_distinct_techniques(app):
    # Contrived: a single event carrying two independent signals at once
    # (event_id=4688 AND a device-labeled port-scan name) -- proves the
    # "show every triggered signature as its own chip" behavior end to end.
    event = Event(event_id="4688", event_name="Port scan indicator observed during process audit",
                  source="import")
    db.session.add(event)
    db.session.commit()
    result = event_mitre_classifier.classify_event(event)
    assert {r["technique_id"] for r in result} == {"T1059", "T1595"}


def test_classify_event_dedupes_when_multiple_signals_point_to_same_technique(app):
    # event_id 4625 alone is already enough for T1110; event_name also
    # containing "fail" (the real winevent message text always does) must
    # not produce a second, duplicate T1110 entry.
    event = _winevent(4625, "An account failed to log on.")
    result = event_mitre_classifier.classify_event(event)
    assert len(result) == 1


def test_build_mitre_guess_without_synced_catalog_returns_bare_technique_id(app):
    event = _winevent(4625, "An account failed to log on.")
    result = build_mitre_guess(event)
    assert result == [{"technique_id": "T1110"}]


def test_build_mitre_guess_with_synced_catalog_returns_enriched_entry(app):
    db.session.add(MitreTechnique(
        domain="enterprise", stix_id="attack-pattern--fake-t1110", technique_id="T1110",
        name="Brute Force", is_subtechnique=False,
    ))
    db.session.commit()

    event = _winevent(4625, "An account failed to log on.")
    result = build_mitre_guess(event)
    assert len(result) == 1
    assert result[0]["technique_id"] == "T1110"
    assert result[0]["technique_name"] == "Brute Force"
    assert result[0]["tactics"] == []


def test_get_event_route_includes_mitre_guess(app):
    event = _winevent(4625, "An account failed to log on.")
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get(f"/api/events/{event.id}")
    assert response.status_code == 200
    data = response.get_json()
    assert data["mitre_guess"] == [{"technique_id": "T1110"}]


def test_get_event_route_returns_empty_mitre_guess_for_benign_event(app):
    event = _winevent(4624, "An account was successfully logged on.")
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get(f"/api/events/{event.id}")
    assert response.status_code == 200
    assert response.get_json()["mitre_guess"] == []
