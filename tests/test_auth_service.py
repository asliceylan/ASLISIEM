import pytest
from flask import jsonify, session

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Tenant, User
from backend.services import auth_service
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


def _make_tenant_admin(tenant_slug="acme-test"):
    tenant = Tenant(name="Acme Test", slug=tenant_slug, enabled=True)
    db.session.add(tenant)
    db.session.commit()
    user = User(
        username=f"{tenant_slug}-admin", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=tenant.id,
    )
    db.session.add(user)
    db.session.commit()
    return tenant, user


def test_current_user_is_none_without_session(app):
    with app.test_request_context("/"):
        assert auth_service.current_user() is None


def test_current_user_loads_from_session(app):
    full_admin = User.query.filter_by(role="full_admin").first()
    with app.test_request_context("/"):
        session["user_id"] = full_admin.id
        loaded = auth_service.current_user()
        assert loaded is not None
        assert loaded.username == full_admin.username


def test_is_full_admin_true_for_full_admin_false_for_tenant_admin(app):
    full_admin = User.query.filter_by(role="full_admin").first()
    _, tenant_admin = _make_tenant_admin()

    assert auth_service.is_full_admin(user=full_admin) is True
    assert auth_service.is_full_admin(user=tenant_admin) is False


def test_tenant_scope_locks_tenant_admin_to_own_tenant_regardless_of_request(app):
    tenant, tenant_admin = _make_tenant_admin()
    other_tenant = Tenant(name="Other", slug="other-test", enabled=True)
    db.session.add(other_tenant)
    db.session.commit()

    # Even if a tenant_admin's request somehow carries a different
    # tenant_id, tenant_scope must never honor it -- this is the real
    # security boundary, not a UI convenience.
    assert auth_service.tenant_scope(requested_tenant_id=other_tenant.id, user=tenant_admin) == tenant.id
    assert auth_service.tenant_scope(requested_tenant_id=None, user=tenant_admin) == tenant.id


def test_tenant_scope_for_full_admin_honors_request_or_defaults_to_all(app):
    full_admin = User.query.filter_by(role="full_admin").first()
    tenant, _ = _make_tenant_admin()

    assert auth_service.tenant_scope(requested_tenant_id=None, user=full_admin) is None
    assert auth_service.tenant_scope(requested_tenant_id=str(tenant.id), user=full_admin) == tenant.id


def test_tenant_scope_ignores_garbage_requested_tenant_id_for_full_admin(app):
    full_admin = User.query.filter_by(role="full_admin").first()
    assert auth_service.tenant_scope(requested_tenant_id="not-a-number", user=full_admin) is None


def test_require_full_admin_blocks_tenant_admin_with_403(app):
    _, tenant_admin = _make_tenant_admin()

    @auth_service.require_full_admin
    def protected_view():
        return jsonify({"ok": True})

    with app.test_request_context("/"):
        session["user_id"] = tenant_admin.id
        response, status = protected_view()
        assert status == 403

    full_admin = User.query.filter_by(role="full_admin").first()
    with app.test_request_context("/"):
        session["user_id"] = full_admin.id
        response = protected_view()
        assert response.get_json() == {"ok": True}
