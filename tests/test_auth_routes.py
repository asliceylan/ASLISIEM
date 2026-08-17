import pytest

from backend.app import create_app
from backend.database.db import db


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


def test_login_page_renders_when_not_authenticated(app):
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200
    assert b'name="username"' in response.data


def test_root_redirects_to_login_when_not_authenticated(app):
    client = app.test_client()
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_with_correct_credentials_grants_access(app):
    client = app.test_client()
    response = client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=False)
    assert response.status_code == 302

    response = client.get("/")
    assert response.status_code == 200


def test_login_with_wrong_credentials_is_rejected(app):
    client = app.test_client()
    response = client.post("/login", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    assert b"error-msg" in response.data

    # And a subsequent request to / is still gated -- no session was granted.
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302


def test_already_authenticated_get_login_redirects_to_root(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 302


def test_api_route_requires_login(app):
    client = app.test_client()
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 401
    assert response.get_json()["error"]


def test_api_route_accessible_after_login(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200


def test_logout_clears_session(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    assert client.get("/api/dashboard/stats").status_code == 200

    client.get("/logout")
    assert client.get("/api/dashboard/stats").status_code == 401


def test_seeded_tenant_admin_can_log_in(app):
    # ensure_seed_tenants_and_admin (run by create_app() above) creates one
    # tenant_admin per demo tenant with a predictable {slug}123 password.
    client = app.test_client()
    response = client.post("/login", data={"username": "tenant1-admin", "password": "tenant1123"}, follow_redirects=False)
    assert response.status_code == 302
    assert client.get("/api/dashboard/stats").status_code == 200


def test_tenant_admin_wrong_password_is_rejected(app):
    client = app.test_client()
    response = client.post("/login", data={"username": "tenant1-admin", "password": "wrong"})
    assert response.status_code == 401
