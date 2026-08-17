import pytest
from datetime import datetime
from unittest.mock import patch

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event
from backend.services import log_source_service
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


def _list_sources(running):
    with patch("backend.services.log_source_service.control.get_status", return_value={"running": running}):
        return log_source_service.list_log_sources()


def test_lists_all_topology_devices_plus_manual_import_row(app):
    sources = _list_sources(running=False)
    names = {s["device_type"] for s in sources if s["device_type"]}
    assert names == set(topology.DEVICES.keys())
    assert any(s["name"] == log_source_service.MANUAL_IMPORT_NAME for s in sources)
    assert len(sources) == len(topology.DEVICES) + 1


def test_status_reflects_simulator_running_state(app):
    device_rows = [s for s in _list_sources(running=True) if s["device_type"]]
    assert device_rows and all(s["status"] == "Active" for s in device_rows)

    device_rows = [s for s in _list_sources(running=False) if s["device_type"]]
    assert device_rows and all(s["status"] == "Inactive" for s in device_rows)


def test_manual_import_row_status_is_independent_of_simulator(app):
    sources = _list_sources(running=True)
    manual_row = next(s for s in sources if s["name"] == log_source_service.MANUAL_IMPORT_NAME)
    assert manual_row["status"] == "Manual"


def test_last_seen_updates_when_a_device_produces_a_log(app):
    mail = topology.DEVICES["dmz_mail"]
    ts = datetime(2026, 1, 1, 12, 0, 0)
    raw = log_templates.render_winevent(
        mail, ts, 4625, "An account failed to log on.", "jsmith", "203.0.113.44", logon_type=3,
    )
    ingest_raw_log(raw, mail)

    sources = {s["device_type"]: s for s in _list_sources(running=False) if s["device_type"]}
    assert sources["dmz_mail"]["last_seen"] == ts.isoformat()
    # a device that never produced a log has no last_seen
    assert sources["waf"]["last_seen"] is None


def test_manual_import_last_seen_tracks_imported_events(app):
    ts = datetime(2026, 1, 2, 9, 0, 0)
    event = Event(source="import", source_ip="203.0.113.1", timestamp=ts)
    db.session.add(event)
    db.session.commit()

    sources = _list_sources(running=False)
    manual_row = next(s for s in sources if s["name"] == log_source_service.MANUAL_IMPORT_NAME)
    assert manual_row["last_seen"] == ts.isoformat()


def test_get_log_sources_route_returns_list(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    with patch("backend.services.log_source_service.control.get_status", return_value={"running": False}):
        response = client.get("/api/log-sources")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data) == len(topology.DEVICES) + 1
