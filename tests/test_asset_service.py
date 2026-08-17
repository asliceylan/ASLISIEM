import pytest
from datetime import datetime, timedelta

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense
from backend.services import asset_service
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


def test_classify_ip_scope_internal_ranges(app):
    assert asset_service.classify_ip_scope("10.10.0.254") == "internal"
    assert asset_service.classify_ip_scope("198.51.100.10") == "internal"
    assert asset_service.classify_ip_scope("192.168.1.1") == "internal"


def test_classify_ip_scope_external(app):
    assert asset_service.classify_ip_scope("203.0.113.44") == "external"
    assert asset_service.classify_ip_scope("8.8.8.8") == "external"


def test_classify_ip_scope_unknown_for_invalid_input(app):
    assert asset_service.classify_ip_scope("") == "unknown"
    assert asset_service.classify_ip_scope(None) == "unknown"
    assert asset_service.classify_ip_scope("not-an-ip") == "unknown"


def test_list_assets_empty_when_no_events(app):
    assert asset_service.list_assets() == []


def test_cef_event_does_not_assign_device_type_to_either_ip(app):
    # Regression: neither the attacker (source_ip) nor the target
    # (destination_ip) is the reporting firewall itself in CEF -- assigning
    # device_type from either would mislabel the attacker as "firewall".
    fw = topology.DEVICES["firewall"]
    web = topology.DEVICES["dmz_web"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    ext = {"src": "203.0.113.44", "spt": "51000", "dst": web.ip, "dpt": "22", "act": "deny"}
    raw = log_templates.render_cef(fw, ts, "5001", "Port Scan Detected", "7", ext)
    ingest_raw_log(raw, fw)

    assets = {a["ip"]: a for a in asset_service.list_assets()}
    assert assets["203.0.113.44"]["device_type"] is None
    assert assets["203.0.113.44"]["scope"] == "external"
    assert assets["203.0.113.44"]["log_formats"] == "cef"
    assert assets[web.ip]["device_type"] is None
    assert assets[web.ip]["scope"] == "internal"
    assert assets[web.ip]["log_formats"] == "cef"


def test_self_reporting_event_assigns_device_type_to_destination_ip(app):
    mail = topology.DEVICES["dmz_mail"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_winevent(
        mail, ts, 4625, "An account failed to log on.", "jsmith", "203.0.113.44", logon_type=3,
    )
    ingest_raw_log(raw, mail)

    assets = {a["ip"]: a for a in asset_service.list_assets()}
    assert assets[mail.ip]["device_type"] == "dmz_mail"
    assert assets[mail.ip]["scope"] == "internal"
    assert assets[mail.ip]["log_formats"] == "winevent"
    assert assets["203.0.113.44"]["device_type"] is None
    assert assets["203.0.113.44"]["log_formats"] == "winevent"


def test_log_formats_accumulates_multiple_distinct_formats_for_same_ip(app):
    fw = topology.DEVICES["firewall"]
    web = topology.DEVICES["dmz_web"]
    mail = topology.DEVICES["dmz_mail"]
    ts = datetime(2026, 1, 1, 12, 0, 0)

    ext = {"src": "203.0.113.44", "spt": "51000", "dst": web.ip, "dpt": "22", "act": "deny"}
    raw_cef = log_templates.render_cef(fw, ts, "5001", "Port Scan Detected", "7", ext)
    ingest_raw_log(raw_cef, fw)

    raw_winevent = log_templates.render_winevent(
        mail, ts + timedelta(seconds=1), 4625, "An account failed to log on.",
        "jsmith", "203.0.113.44", logon_type=3,
    )
    ingest_raw_log(raw_winevent, mail)

    assets = {a["ip"]: a for a in asset_service.list_assets()}
    # Sorted alphabetically, comma-separated -- deterministic regardless of
    # the order the underlying events happen to be processed in.
    assert assets["203.0.113.44"]["log_formats"] == "cef, winevent"


def test_log_count_and_seen_range_accumulate_across_events(app):
    mail = topology.DEVICES["dmz_mail"]
    base = datetime(2026, 1, 1, 12, 0, 0)
    for i in range(3):
        raw = log_templates.render_winevent(
            mail, base + timedelta(minutes=i), 4625, "An account failed to log on.",
            "jsmith", "203.0.113.44", logon_type=3,
        )
        ingest_raw_log(raw, mail)

    assets = {a["ip"]: a for a in asset_service.list_assets()}
    attacker = assets["203.0.113.44"]
    assert attacker["log_count"] == 3
    assert attacker["first_seen"] == base.isoformat()
    assert attacker["last_seen"] == (base + timedelta(minutes=2)).isoformat()


def test_offense_count_derived_from_offense_source_ip(app):
    mail = topology.DEVICES["dmz_mail"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_winevent(
        mail, ts, 4625, "An account failed to log on.", "jsmith", "203.0.113.44", logon_type=3,
    )
    ingest_raw_log(raw, mail)

    db.session.add(Offense(source_ip="203.0.113.44", title="Test Offense", severity="High", status="OPEN"))
    db.session.add(Offense(source_ip="203.0.113.44", title="Test Offense 2", severity="High", status="OPEN"))
    db.session.commit()

    assets = {a["ip"]: a for a in asset_service.list_assets()}
    assert assets["203.0.113.44"]["offense_count"] == 2
    assert assets[mail.ip]["offense_count"] == 0


def test_get_assets_route_returns_list(app):
    mail = topology.DEVICES["dmz_mail"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_winevent(
        mail, ts, 4625, "An account failed to log on.", "jsmith", "203.0.113.44", logon_type=3,
    )
    ingest_raw_log(raw, mail)

    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get("/api/assets")
    assert response.status_code == 200
    data = response.get_json()
    ips = {a["ip"] for a in data}
    assert "203.0.113.44" in ips
    assert mail.ip in ips
