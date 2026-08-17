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
    tenant = Tenant(name="Isolated", slug="isolated-u", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    db.session.add(User(
        username="isolated-user-admin", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    ))
    db.session.commit()
    client.post("/login", data={"username": "isolated-user-admin", "password": "pw"})


def test_full_admin_can_list_users(app):
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/users")
    assert response.status_code == 200
    usernames = {u["username"] for u in response.get_json()}
    assert "admin" in usernames
    assert "tenant1-admin" in usernames


def test_tenant_admin_cannot_list_users(app):
    client = app.test_client()
    _login_tenant_admin(client)
    assert client.get("/api/users").status_code == 403


def test_full_admin_can_create_tenant_admin_user(app):
    client = app.test_client()
    _login_full_admin(client)
    tenant_id = Tenant.query.filter_by(slug="tenant1").first().id
    response = client.post("/api/users", json={
        "username": "brand-new-admin", "password": "secretpw",
        "role": "tenant_admin", "tenant_id": tenant_id,
    })
    assert response.status_code == 201
    data = response.get_json()
    assert data["role"] == "tenant_admin"
    assert data["tenant_id"] == tenant_id


def test_create_user_rejects_tenant_admin_without_tenant_id(app):
    client = app.test_client()
    _login_full_admin(client)
    response = client.post("/api/users", json={
        "username": "no-tenant-admin", "password": "pw", "role": "tenant_admin",
    })
    assert response.status_code == 400


def test_create_user_rejects_duplicate_username(app):
    client = app.test_client()
    _login_full_admin(client)
    response = client.post("/api/users", json={
        "username": "admin", "password": "pw", "role": "full_admin",
    })
    assert response.status_code == 400


def test_full_admin_can_reset_another_users_password(app):
    client = app.test_client()
    _login_full_admin(client)
    target = User.query.filter_by(username="tenant1-admin").first()
    response = client.put(f"/api/users/{target.id}/password", json={"password": "newpw123"})
    assert response.status_code == 200

    other_client = app.test_client()
    login = other_client.post("/login", data={"username": "tenant1-admin", "password": "newpw123"})
    assert login.status_code == 302


def test_full_admin_cannot_delete_own_account(app):
    client = app.test_client()
    _login_full_admin(client)
    self_id = User.query.filter_by(username="admin").first().id
    response = client.delete(f"/api/users/{self_id}")
    assert response.status_code == 400
    assert User.query.get(self_id) is not None


def test_full_admin_can_delete_another_user(app):
    client = app.test_client()
    _login_full_admin(client)
    target = User.query.filter_by(username="tenant1-admin").first()
    response = client.delete(f"/api/users/{target.id}")
    assert response.status_code == 200
    assert User.query.get(target.id) is None
