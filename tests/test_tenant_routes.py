import pytest

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


def _login_full_admin(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})


def _login_tenant_admin(client):
    tenant = Tenant(name="Isolated", slug="isolated-t", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    db.session.add(User(
        username="isolated-admin", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()
    client.post("/login", data={"username": "isolated-admin", "password": "pw"})
    return tenant


def test_full_admin_can_list_tenants(app):
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/tenants")
    assert response.status_code == 200
    slugs = {t["slug"] for t in response.get_json()}
    assert "tenant1" in slugs  # from ensure_seed_tenants_and_admin


def test_tenant_list_is_ordered_by_id_not_name(app):
    # A text sort on name would put "Tenant10" right after "Tenant1" and
    # before "Tenant2" -- Tenant1..Tenant10 are seeded in that exact id
    # order (1..10), so ordering by id must return them in ascending id
    # order (and thus in the visually-correct Tenant1, Tenant2, ...,
    # Tenant10 sequence).
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/tenants")
    ids = [t["id"] for t in response.get_json()]
    assert ids == sorted(ids)


def test_tenant_admin_cannot_list_tenants(app):
    client = app.test_client()
    _login_tenant_admin(client)
    response = client.get("/api/tenants")
    assert response.status_code == 403


def test_full_admin_can_create_tenant(app):
    client = app.test_client()
    _login_full_admin(client)
    response = client.post("/api/tenants", json={"name": "New Co", "slug": "new-co"})
    assert response.status_code == 201
    assert response.get_json()["slug"] == "new-co"


def test_create_tenant_rejects_duplicate_slug(app):
    client = app.test_client()
    _login_full_admin(client)
    client.post("/api/tenants", json={"name": "New Co", "slug": "dupe-slug"})
    response = client.post("/api/tenants", json={"name": "Another", "slug": "dupe-slug"})
    assert response.status_code == 400


def test_create_tenant_requires_name_and_slug(app):
    client = app.test_client()
    _login_full_admin(client)
    response = client.post("/api/tenants", json={"name": "No Slug"})
    assert response.status_code == 400


def test_full_admin_can_disable_tenant(app):
    client = app.test_client()
    _login_full_admin(client)
    tenant_id = Tenant.query.filter_by(slug="tenant1").first().id
    response = client.put(f"/api/tenants/{tenant_id}", json={"enabled": False})
    assert response.status_code == 200
    assert response.get_json()["enabled"] is False


def test_tenant_admin_cannot_disable_a_tenant(app):
    client = app.test_client()
    tenant = _login_tenant_admin(client)
    response = client.put(f"/api/tenants/{tenant.id}", json={"enabled": False})
    assert response.status_code == 403
