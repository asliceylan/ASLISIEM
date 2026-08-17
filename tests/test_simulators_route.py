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


def test_simulators_redirects_to_login_when_not_authenticated(app):
    client = app.test_client()
    response = client.get("/simulators", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_simulators_renders_same_spa_shell_for_full_admin(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get("/simulators")
    assert response.status_code == 200
    # Same index.html shell -- no separate template for this route.
    assert b'id="page-simulators"' in response.data
    assert b'id="app-shell"' in response.data


def test_simulators_renders_same_spa_shell_for_tenant_admin(app):
    client = app.test_client()
    client.post("/login", data={"username": "tenant1-admin", "password": "tenant1123"})
    response = client.get("/simulators")
    assert response.status_code == 200
    assert b'id="page-simulators"' in response.data


def test_simulators_page_has_no_nav_entry(app):
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "admin123"})
    response = client.get("/simulators")
    assert response.status_code == 200
    assert b'data-page="simulators"' not in response.data
