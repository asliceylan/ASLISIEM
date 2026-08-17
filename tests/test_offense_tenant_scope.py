import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Offense, Tenant, User
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


def _three_tenants():
    a = Tenant(name="Tenant A", slug="off-a", enabled=True)
    b = Tenant(name="Tenant B", slug="off-b", enabled=True)
    c = Tenant(name="Tenant C", slug="off-c", enabled=True)
    db.session.add_all([a, b, c])
    db.session.commit()
    for i, t in enumerate([a, b, c]):
        db.session.add(Offense(title=f"Offense {t.slug}", severity="High", status="OPEN", tenant_id=t.id))
    db.session.commit()
    return a, b, c


def _login_full_admin(client):
    client.post("/login", data={"username": "admin", "password": "admin123"})


def test_no_tenant_ids_param_returns_every_tenants_offenses(app):
    _three_tenants()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get("/api/offenses")
    assert response.status_code == 200
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Offense off-a", "Offense off-b", "Offense off-c"}


def test_single_tenant_id_scopes_to_that_tenant_only(app):
    a, b, c = _three_tenants()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?tenant_ids={a.id}")
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Offense off-a"}


def test_multiple_tenant_ids_union_their_offenses_excluding_others(app):
    a, b, c = _three_tenants()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?tenant_ids={a.id},{b.id}")
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Offense off-a", "Offense off-b"}


def test_malformed_tenant_ids_pieces_are_skipped_not_rejected(app):
    a, b, c = _three_tenants()
    client = app.test_client()
    _login_full_admin(client)
    response = client.get(f"/api/offenses?tenant_ids={a.id},,abc,{b.id}")
    assert response.status_code == 200
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Offense off-a", "Offense off-b"}


def test_tenant_admin_always_sees_only_own_tenant_regardless_of_param(app):
    a, b, c = _three_tenants()
    db.session.add(User(
        username="off-tenant-admin", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=a.id,
    ))
    db.session.commit()
    client = app.test_client()
    client.post("/login", data={"username": "off-tenant-admin", "password": "pw"})

    # Even explicitly requesting other tenants must be ignored.
    response = client.get(f"/api/offenses?tenant_ids={b.id},{c.id}")
    titles = {o["title"] for o in response.get_json()}
    assert titles == {"Offense off-a"}

    response_unscoped = client.get("/api/offenses")
    titles_unscoped = {o["title"] for o in response_unscoped.get_json()}
    assert titles_unscoped == {"Offense off-a"}
