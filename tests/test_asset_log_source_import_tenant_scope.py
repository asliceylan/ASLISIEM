import io
import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Tenant, User
from backend.services import asset_service, log_source_service
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
    a = Tenant(name="Tenant A", slug="asl-a", enabled=True)
    b = Tenant(name="Tenant B", slug="asl-b", enabled=True)
    db.session.add_all([a, b])
    db.session.commit()
    return a, b


def _winevent(tenant_id, source_ip):
    mail = topology.DEVICES["dmz_mail"]
    raw = log_templates.render_winevent(
        mail, datetime(2026, 1, 1, 12, 0, 0), 4625,
        "An account failed to log on.", "jsmith", source_ip, logon_type=3,
    )
    return ingest_raw_log(raw, mail, tenant_id=tenant_id)


def test_list_assets_scoped_to_tenant(app):
    a, b = _two_tenants()
    _winevent(a.id, "203.0.113.11")
    _winevent(b.id, "203.0.113.22")

    ips_a = {asset["ip"] for asset in asset_service.list_assets(tenant_id=a.id)}
    ips_b = {asset["ip"] for asset in asset_service.list_assets(tenant_id=b.id)}
    assert "203.0.113.11" in ips_a and "203.0.113.22" not in ips_a
    assert "203.0.113.22" in ips_b and "203.0.113.11" not in ips_b


def test_list_assets_unscoped_returns_everything(app):
    a, b = _two_tenants()
    _winevent(a.id, "203.0.113.11")
    _winevent(b.id, "203.0.113.22")

    ips = {asset["ip"] for asset in asset_service.list_assets()}
    assert {"203.0.113.11", "203.0.113.22"}.issubset(ips)


def test_list_log_sources_scoped_uses_tenants_own_topology_and_events(app):
    a, b = _two_tenants()
    _winevent(a.id, "203.0.113.11")
    _winevent(b.id, "203.0.113.22")

    sources_a = {s["device_type"]: s for s in log_source_service.list_log_sources(tenant_id=a.id) if s["device_type"]}
    devices_a = topology.build_devices(a)
    assert sources_a["dmz_mail"]["last_seen"] is not None
    assert sources_a["firewall"]["device_type"] == devices_a["firewall"].name

    sources_b = {s["device_type"]: s for s in log_source_service.list_log_sources(tenant_id=b.id) if s["device_type"]}
    assert sources_b["dmz_mail"]["last_seen"] is not None


def test_list_log_sources_unscoped_falls_back_to_default_topology(app):
    sources = {s["device_type"]: s for s in log_source_service.list_log_sources() if s["device_type"]}
    assert sources["firewall"]["name"] == topology.DEVICES["firewall"].hostname


def _login_as_tenant_admin(client, tenant):
    username = f"{tenant.slug}-import-login"
    db.session.add(User(
        username=username, password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()
    client.post("/login", data={"username": username, "password": "pw"})


def test_csv_import_tags_events_with_tenant_admins_own_tenant(app):
    a, _ = _two_tenants()
    client = app.test_client()
    _login_as_tenant_admin(client, a)

    csv_content = "event_id,source_ip,username\n4625,203.0.113.99,jsmith\n"
    upload = client.post(
        "/api/import/upload",
        data={"file": (io.BytesIO(csv_content.encode()), "test.csv")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200
    preview = upload.get_json()

    confirm = client.post("/api/import/confirm", json={
        "temp_name": preview["temp_name"], "original_filename": preview["original_filename"],
        "file_type": preview["file_type"], "mapping": {},
    })
    assert confirm.status_code == 200
    imported_event = Event.query.filter_by(source="import").first()
    assert imported_event.tenant_id == a.id


def test_full_admin_import_requires_tenant_id(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})

    csv_content = "event_id,source_ip,username\n4625,203.0.113.99,jsmith\n"
    upload = client.post(
        "/api/import/upload",
        data={"file": (io.BytesIO(csv_content.encode()), "test.csv")},
        content_type="multipart/form-data",
    )
    preview = upload.get_json()

    confirm = client.post("/api/import/confirm", json={
        "temp_name": preview["temp_name"], "original_filename": preview["original_filename"],
        "file_type": preview["file_type"], "mapping": {},
    })
    assert confirm.status_code == 400
