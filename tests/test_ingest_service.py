import pytest
from types import SimpleNamespace

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event
from backend.engine.condition_evaluator import get_field_value
from backend.services.ingest_service import ingest_raw_log

DEVICE_FW = SimpleNamespace(ip="10.10.0.254", device_type="firewall", port=None)
DEVICE_WEB = SimpleNamespace(ip="198.51.100.10", device_type="dmz_web", port=443)
DEVICE_MAIL = SimpleNamespace(ip="198.51.100.20", device_type="dmz_mail", port=None)
DEVICE_SW = SimpleNamespace(ip="10.10.0.2", device_type="switch", port=None)


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app


def test_ingest_cef_sets_provenance_and_is_rule_queryable_via_derived_fields(app):
    line = (
        "<134>Jul 31 14:22:03 fw-edge-01 CEF:0|CheckPoint|VPN-1|R81|5001|"
        "Port Scan Detected|7|src=203.0.113.44 dst=198.51.100.10 dpt=22 act=deny"
    )
    event = ingest_raw_log(line, DEVICE_FW)
    assert event.source == "simulator"
    assert event.device_type == "firewall"
    assert event.log_format == "cef"
    # A format-specific field (CEF's "dpt") is NOT one of the 9 normalized
    # columns, yet the existing rule engine can already find it via the
    # raw_data["__derived_fields__"] fallback -- no engine changes needed.
    assert get_field_value(event, "dpt") == "22"
    assert get_field_value(event, "act") == "deny"


def test_ingest_syslog_line(app):
    line = "<166>Jul 31 14:22:07 core-sw-01 sshd[1]: Failed password for invalid user admin from 203.0.113.44 port 22 ssh2"
    event = ingest_raw_log(line, DEVICE_SW)
    assert event.log_format == "syslog"
    assert event.source_ip == "203.0.113.44"


def test_ingest_access_log_line(app):
    line = '203.0.113.44 - - [31/Jul/2026:14:35:20 +0000] "GET /login.php HTTP/1.1" 401 512'
    event = ingest_raw_log(line, DEVICE_WEB)
    assert event.log_format == "access_log"
    assert event.event_id == "401"
    assert get_field_value(event, "Method") == "GET"


def test_ingest_winevent_block(app):
    block = (
        "Log Name: Security\nEvent ID: 4625\nTimeCreated: 2026-07-31 14:22:03\n"
        "Computer: dmz-mail-01\nAccount Name: jsmith\n"
        "Source Network Address: 203.0.113.44\nLogon Type: 3\n"
        "Message: An account failed to log on."
    )
    event = ingest_raw_log(block, DEVICE_MAIL)
    assert event.log_format == "winevent"
    assert event.username == "jsmith"
    assert get_field_value(event, "Logon Type") == "3"


def test_ingest_does_not_create_an_import_row(app):
    created = ingest_raw_log('203.0.113.44 - - [31/Jul/2026:14:35:20 +0000] "GET / HTTP/1.1" 200 10', DEVICE_WEB)
    reloaded = Event.query.get(created.id)
    assert reloaded.import_id is None


def test_existing_import_events_keep_default_source(app):
    event = Event(event_id="4625", event_name="legacy import")
    db.session.add(event)
    db.session.commit()
    reloaded = Event.query.get(event.id)
    assert reloaded.source == "import"
