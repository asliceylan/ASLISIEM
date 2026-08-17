import pytest
from unittest.mock import patch

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Tenant, User
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


def test_tenant_admin_cannot_trigger_mitre_sync(app):
    tenant = Tenant(name="Isolated", slug="mitre-t", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    db.session.add(User(
        username="mitre-tenant-admin", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "mitre-tenant-admin", "password": "pw"})
    response = client.post("/api/mitre/sync", json={})
    assert response.status_code == 403


def test_full_admin_can_trigger_mitre_sync(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    # Mocked to avoid a real network call to the MITRE STIX repo -- this
    # test only proves the authorization gate lets a full_admin through.
    with patch("backend.routes.mitre_routes.sync_all_domains", return_value={}):
        response = client.post("/api/mitre/sync", json={})
    assert response.status_code == 200


def test_mitre_status_remains_open_to_tenant_admin(app):
    # Read-only, non-tenant-specific reference data -- no full_admin gate.
    tenant = Tenant(name="Isolated2", slug="mitre-t2", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    db.session.add(User(
        username="mitre-tenant-admin2", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()

    client = app.test_client()
    client.post("/login", data={"username": "mitre-tenant-admin2", "password": "pw"})
    response = client.get("/api/mitre/status")
    assert response.status_code == 200
