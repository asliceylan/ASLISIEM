import pytest
from datetime import datetime

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Rule, Offense, Tenant, User
from backend.database.schema_guard import (
    ensure_default_tenant_and_migrate, ensure_seed_tenants_and_admin,
    ensure_tenant_renames, ensure_offense_columns, DEFAULT_TENANT_SLUG,
    FULL_ADMIN_USERNAME, SEED_TENANTS,
)
from werkzeug.security import check_password_hash, generate_password_hash


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_seed_creates_full_admin_and_demo_tenants_with_tenant_admins(app):
    ensure_seed_tenants_and_admin(db.engine)

    admin = User.query.filter_by(username=FULL_ADMIN_USERNAME).first()
    assert admin is not None
    assert admin.role == "full_admin"
    assert admin.tenant_id is None

    tenants = Tenant.query.filter(Tenant.slug != DEFAULT_TENANT_SLUG).all()
    assert {t.slug for t in tenants} == {slug for _, slug in SEED_TENANTS}

    for _, slug in SEED_TENANTS:
        tenant_admin = User.query.filter_by(username=f"{slug}-admin").first()
        assert tenant_admin is not None
        assert tenant_admin.role == "tenant_admin"
        assert tenant_admin.tenant_id == Tenant.query.filter_by(slug=slug).first().id


def test_seed_backfills_newly_added_tenants_without_touching_existing_ones(app):
    # create_app() (via this fixture) already ran the seed once, so all of
    # SEED_TENANTS already exists. Delete the "newly added" half to
    # simulate an older database that only ever had the original 5 --
    # re-running the seed function must then restore exactly the missing
    # ones, and must leave the ones that were never removed completely
    # untouched (same id, same tenant_admin account). This is the guarantee
    # that lets SEED_TENANTS grow over time (e.g. 5 -> 10) without a real
    # migration step.
    pre_existing = SEED_TENANTS[:5]
    newly_added = SEED_TENANTS[5:]
    assert newly_added, "this test assumes SEED_TENANTS has grown past its original 5 entries"

    original_ids = {}
    for name, slug in pre_existing:
        tenant = Tenant.query.filter_by(slug=slug).first()
        assert tenant is not None  # already seeded by create_app() above
        original_ids[slug] = tenant.id

    for name, slug in newly_added:
        tenant = Tenant.query.filter_by(slug=slug).first()
        if tenant:
            User.query.filter_by(tenant_id=tenant.id).delete()
            db.session.delete(tenant)
    db.session.commit()
    for name, slug in newly_added:
        assert Tenant.query.filter_by(slug=slug).first() is None  # confirm removed

    ensure_seed_tenants_and_admin(db.engine)

    for slug, original_id in original_ids.items():
        assert Tenant.query.filter_by(slug=slug).first().id == original_id

    for name, slug in newly_added:
        tenant = Tenant.query.filter_by(slug=slug).first()
        assert tenant is not None
        assert User.query.filter_by(username=f"{slug}-admin").first() is not None

    assert Tenant.query.filter(Tenant.slug != DEFAULT_TENANT_SLUG).count() == len(SEED_TENANTS)


def test_seed_is_idempotent(app):
    ensure_seed_tenants_and_admin(db.engine)
    ensure_seed_tenants_and_admin(db.engine)

    assert User.query.filter_by(username=FULL_ADMIN_USERNAME).count() == 1
    assert Tenant.query.filter(Tenant.slug != DEFAULT_TENANT_SLUG).count() == len(SEED_TENANTS)
    for _, slug in SEED_TENANTS:
        assert User.query.filter_by(username=f"{slug}-admin").count() == 1


def test_seed_preserves_existing_admin_password_hash(app):
    # create_app() (called by the fixture above) already seeded the default
    # admin/admin123 row once. Simulates a real deployment that changed that
    # password afterward -- re-running seed on the next startup must never
    # touch (reset) an existing admin row.
    from werkzeug.security import generate_password_hash, check_password_hash

    admin = User.query.filter_by(username=FULL_ADMIN_USERNAME).first()
    assert admin is not None
    admin.password_hash = generate_password_hash("custom-changed-pw")
    db.session.commit()

    ensure_seed_tenants_and_admin(db.engine)

    admin = User.query.filter_by(username=FULL_ADMIN_USERNAME).first()
    assert check_password_hash(admin.password_hash, "custom-changed-pw")


def test_migration_backfills_pre_existing_rows_to_default_tenant(app):
    # ensure_offense_columns is normally called by app.py before migration;
    # the in-memory test DB's fresh db.create_all() already includes the
    # tenant_id column since it's now defined on the model, but calling this
    # here mirrors the real app.py startup order and must stay a safe no-op.
    ensure_offense_columns(db.engine)

    rule = Rule(name="Pre-migration Rule", conditions_json="{}")
    db.session.add(rule)
    db.session.commit()

    event = Event(event_id="1", source="import", timestamp=datetime(2026, 1, 1))
    db.session.add(event)
    db.session.commit()

    offense = Offense(rule_id=rule.id, title="Pre-migration Offense", severity="High", status="OPEN")
    db.session.add(offense)
    db.session.commit()

    assert event.tenant_id is None
    assert rule.tenant_id is None
    assert offense.tenant_id is None

    ensure_default_tenant_and_migrate(db.engine)

    default_tenant = Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).first()
    assert default_tenant is not None
    assert default_tenant.name == "Default Tenant"

    db.session.refresh(event)
    db.session.refresh(rule)
    db.session.refresh(offense)
    assert event.tenant_id == default_tenant.id
    assert rule.tenant_id == default_tenant.id
    assert offense.tenant_id == default_tenant.id


def test_migration_is_a_no_op_when_nothing_is_pending(app):
    ensure_default_tenant_and_migrate(db.engine)
    assert Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).count() == 0


def test_tenant_rename_updates_in_place_without_disturbing_fk_data(app):
    # Simulate an older database still seeded under the original fictional-
    # company slug ("acme") rather than the new "tenant1". create_app() (via
    # the fixture above) already seeded "tenant1" once -- remove it first so
    # the rename below has a clean old-slug row to operate on, same setup
    # style as test_seed_backfills_newly_added_tenants_without_touching_existing_ones.
    new_tenant = Tenant.query.filter_by(slug="tenant1").first()
    assert new_tenant is not None
    User.query.filter_by(username="tenant1-admin").delete()
    db.session.delete(new_tenant)
    db.session.commit()

    old_tenant = Tenant(name="Acme Corp", slug="acme", enabled=True)
    db.session.add(old_tenant)
    db.session.flush()
    old_tenant_id = old_tenant.id
    db.session.add(User(
        username="acme-admin",
        password_hash=generate_password_hash("acme123"),
        role="tenant_admin",
        tenant_id=old_tenant.id,
    ))
    db.session.commit()

    # Existing data tied to this tenant via tenant_id (the FK) -- must
    # survive the rename completely unaffected.
    event = Event(event_id="1", source="import", timestamp=datetime(2026, 1, 1), tenant_id=old_tenant.id)
    rule = Rule(name="Pre-rename Rule", conditions_json="{}", tenant_id=old_tenant.id)
    db.session.add_all([event, rule])
    db.session.commit()
    offense = Offense(rule_id=rule.id, title="Pre-rename Offense", severity="High", status="OPEN", tenant_id=old_tenant.id)
    db.session.add(offense)
    db.session.commit()

    ensure_tenant_renames(db.engine)

    renamed = Tenant.query.filter_by(slug="tenant1").first()
    assert renamed is not None
    assert renamed.id == old_tenant_id  # same row, id never changes
    assert renamed.name == "Tenant1"
    assert Tenant.query.filter_by(slug="acme").first() is None  # old slug gone

    db.session.refresh(event)
    db.session.refresh(rule)
    db.session.refresh(offense)
    assert event.tenant_id == old_tenant_id
    assert rule.tenant_id == old_tenant_id
    assert offense.tenant_id == old_tenant_id

    assert User.query.filter_by(username="acme-admin").first() is None
    renamed_admin = User.query.filter_by(username="tenant1-admin").first()
    assert renamed_admin is not None
    assert renamed_admin.tenant_id == old_tenant_id
    assert check_password_hash(renamed_admin.password_hash, "tenant1123")


def test_tenant_rename_is_idempotent(app):
    # create_app() (via the fixture) already seeded under the new names --
    # no old slugs exist, so this must be a clean no-op both times.
    before = {t.slug for t in Tenant.query.all()}
    ensure_tenant_renames(db.engine)
    ensure_tenant_renames(db.engine)
    after = {t.slug for t in Tenant.query.all()}
    assert before == after


def test_tenant_rename_never_touches_default_tenant(app):
    ensure_offense_columns(db.engine)
    event = Event(event_id="1", source="import", timestamp=datetime(2026, 1, 1))
    db.session.add(event)
    db.session.commit()
    ensure_default_tenant_and_migrate(db.engine)

    default_tenant = Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).first()
    assert default_tenant is not None
    default_id = default_tenant.id

    ensure_tenant_renames(db.engine)

    default_tenant = Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).first()
    assert default_tenant is not None
    assert default_tenant.id == default_id
    assert default_tenant.name == "Default Tenant"


def test_migration_does_not_touch_rows_that_already_have_a_tenant(app):
    tenant = Tenant(name="Real Tenant", slug="real-tenant", enabled=True)
    db.session.add(tenant)
    db.session.commit()

    event = Event(event_id="1", source="import", timestamp=datetime(2026, 1, 1), tenant_id=tenant.id)
    db.session.add(event)
    db.session.commit()

    ensure_default_tenant_and_migrate(db.engine)

    db.session.refresh(event)
    assert event.tenant_id == tenant.id  # unchanged, not reassigned to Default Tenant
    assert Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).count() == 0  # never even created
