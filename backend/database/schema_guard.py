from sqlalchemy import text
from werkzeug.security import generate_password_hash

from backend.database.db import db

# Columns that may be missing from an `events` table created by an older
# build of this app (db.create_all() only creates missing TABLES, it never
# alters an existing table to add new columns).
EVENT_COLUMNS_TO_ENSURE = [
    ("source", "VARCHAR(20) NOT NULL DEFAULT 'import'"),
    ("device_type", "VARCHAR(50)"),
    ("log_format", "VARCHAR(20)"),
    ("tenant_id", "INTEGER"),
]

MITRE_TECHNIQUE_COLUMNS_TO_ENSURE = [
    ("description", "TEXT"),
]

RULE_COLUMNS_TO_ENSURE = [
    ("distinct_field", "VARCHAR(120)"),
    ("tenant_id", "INTEGER"),
    ("auto_pattern_type", "VARCHAR(50)"),
]

OFFENSE_COLUMNS_TO_ENSURE = [
    ("tenant_id", "INTEGER"),
]

# name/slug pairs for the out-of-the-box demo tenants seeded on startup.
SEED_TENANTS = [
    ("Tenant1", "tenant1"),
    ("Tenant2", "tenant2"),
    ("Tenant3", "tenant3"),
    ("Tenant4", "tenant4"),
    ("Tenant5", "tenant5"),
    ("Tenant6", "tenant6"),
    ("Tenant7", "tenant7"),
    ("Tenant8", "tenant8"),
    ("Tenant9", "tenant9"),
    ("Tenant10", "tenant10"),
]
DEFAULT_TENANT_SLUG = "default"
FULL_ADMIN_USERNAME = "admin"
FULL_ADMIN_PASSWORD = "admin123"

# One-time rename of the original fictional-company demo tenants to the
# generic Tenant1..Tenant10 scheme above. Keyed by the OLD slug so
# ensure_tenant_renames (below) can find any tenant still seeded under its
# old identity and rename it in place. Never touches "default" (Default
# Tenant, used for pre-multi-tenant data migration) -- it isn't in this map.
TENANT_RENAME_MAP = [
    ("acme", "Tenant1", "tenant1"),
    ("globex", "Tenant2", "tenant2"),
    ("initech", "Tenant3", "tenant3"),
    ("umbrella", "Tenant4", "tenant4"),
    ("stark", "Tenant5", "tenant5"),
    ("wayne", "Tenant6", "tenant6"),
    ("cyberdyne", "Tenant7", "tenant7"),
    ("hooli", "Tenant8", "tenant8"),
    ("weyland", "Tenant9", "tenant9"),
    ("aperture", "Tenant10", "tenant10"),
]


def ensure_event_columns(engine):
    """Adds any missing provenance columns to an existing `events` table.
    Safe to call on every startup: only issues ALTER TABLE for columns that
    are actually absent, and is a no-op on a table that already has them
    (including one freshly created by db.create_all()).
    """
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(events)"))}
        if not existing:
            return  # table doesn't exist yet (fresh DB); db.create_all() handles it
        for column_name, ddl_type in EVENT_COLUMNS_TO_ENSURE:
            if column_name not in existing:
                conn.execute(text(f"ALTER TABLE events ADD COLUMN {column_name} {ddl_type}"))
        conn.commit()


def ensure_mitre_technique_columns(engine):
    """Adds any missing columns to an existing `mitre_techniques` table --
    e.g. `description`, added after some users had already synced a catalog.
    Existing rows are preserved; their new column is simply NULL until the
    next Sync repopulates it (see mitre_sync_service._replace_domain_catalog,
    which already replaces a domain's rows wholesale on every sync)."""
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(mitre_techniques)"))}
        if not existing:
            return  # table doesn't exist yet (fresh DB); db.create_all() handles it
        for column_name, ddl_type in MITRE_TECHNIQUE_COLUMNS_TO_ENSURE:
            if column_name not in existing:
                conn.execute(text(f"ALTER TABLE mitre_techniques ADD COLUMN {column_name} {ddl_type}"))
        conn.commit()


def ensure_rule_columns(engine):
    """Adds any missing columns to an existing `rules` table -- e.g.
    `distinct_field`. Existing rules keep NULL, which preserves their
    original raw-event-count threshold behavior exactly (see
    time_window_engine.find_matching_windows)."""
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(rules)"))}
        if not existing:
            return  # table doesn't exist yet (fresh DB); db.create_all() handles it
        for column_name, ddl_type in RULE_COLUMNS_TO_ENSURE:
            if column_name not in existing:
                conn.execute(text(f"ALTER TABLE rules ADD COLUMN {column_name} {ddl_type}"))
        conn.commit()


def ensure_offense_columns(engine):
    """Adds any missing columns to an existing `offenses` table -- e.g.
    `tenant_id`. First schema guard for this table; existing rows get NULL
    until ensure_default_tenant_and_migrate backfills them."""
    with engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(offenses)"))}
        if not existing:
            return  # table doesn't exist yet (fresh DB); db.create_all() handles it
        for column_name, ddl_type in OFFENSE_COLUMNS_TO_ENSURE:
            if column_name not in existing:
                conn.execute(text(f"ALTER TABLE offenses ADD COLUMN {column_name} {ddl_type}"))
        conn.commit()


def ensure_default_tenant_and_migrate(engine):
    """One-time migration: any Event/Rule/Offense row written before this
    app supported multi-tenancy has tenant_id=NULL. Assigns them all to a
    single "Default Tenant" (slug="default") so pre-existing data isn't
    orphaned or hidden once tenant-scoped queries land everywhere. Safe to
    call on every startup: only touches rows that still have tenant_id IS
    NULL, and is a cheap no-op once migrated. Must run AFTER
    ensure_event_columns/ensure_rule_columns/ensure_offense_columns (the
    tenant_id column has to exist first)."""
    from backend.database.models import Tenant

    with engine.connect() as conn:
        pending = sum(
            conn.execute(text(f"SELECT COUNT(*) FROM {table} WHERE tenant_id IS NULL")).scalar()
            for table in ("events", "rules", "offenses")
        )
        if not pending:
            return

        default_tenant = Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).first()
        if not default_tenant:
            default_tenant = Tenant(name="Default Tenant", slug=DEFAULT_TENANT_SLUG, enabled=True)
            db.session.add(default_tenant)
            db.session.commit()

        for table in ("events", "rules", "offenses"):
            conn.execute(
                text(f"UPDATE {table} SET tenant_id = :tid WHERE tenant_id IS NULL"),
                {"tid": default_tenant.id},
            )
        conn.commit()


def ensure_tenant_renames(engine):
    """One-time, idempotent rename of the original fictional-company demo
    tenants (Acme Corp/acme, Globex/globex, ...) to the generic Tenant1..
    Tenant10/tenant1..tenant10 scheme (see TENANT_RENAME_MAP). Updates the
    Tenant row's name/slug IN PLACE -- Tenant.id never changes, so every
    Event/Rule/Offense that references it via tenant_id keeps working
    unmodified. Also renames the matching tenant_admin User's username and
    resets their password to the new {new_slug}123 scheme.

    Must run BEFORE ensure_seed_tenants_and_admin: that function creates any
    SEED_TENANTS entry that's "missing" by slug, so if it ran first against
    an old-slug database it would create 10 brand-new Tenant1..Tenant10 rows
    alongside the old, now-orphaned ones instead of renaming them.

    Safe to call on every startup: once a tenant's slug no longer matches
    its OLD entry in TENANT_RENAME_MAP, that entry is a no-op forever after.
    A fresh database (never seeded under the old names) is a no-op for every
    entry, and ensure_seed_tenants_and_admin seeds the new names directly.
    """
    from backend.database.models import Tenant, User

    changed = False
    for old_slug, new_name, new_slug in TENANT_RENAME_MAP:
        tenant = Tenant.query.filter_by(slug=old_slug).first()
        if not tenant:
            continue
        tenant.name = new_name
        tenant.slug = new_slug
        changed = True

        old_admin_username = f"{old_slug}-admin"
        admin_user = User.query.filter_by(username=old_admin_username).first()
        if admin_user:
            admin_user.username = f"{new_slug}-admin"
            admin_user.password_hash = generate_password_hash(f"{new_slug}123")

    if changed:
        db.session.commit()


def ensure_seed_tenants_and_admin(engine):
    """Safe to call on every startup, no-ops once fully done: (1) migrates
    the original hardcoded admin/admin123 login into the User table as a
    full_admin (role="full_admin", tenant_id=None) -- every existing
    test/doc that logs in with these exact credentials must keep working
    unchanged; (2) creates any SEED_TENANTS entry that doesn't exist yet
    (each checked individually by slug) plus one tenant_admin account per
    tenant, so the app is usable out of the box without manual setup (see
    docs/login_reference.html for credentials).

    Deliberately has NO "already fully seeded, skip everything" shortcut:
    growing SEED_TENANTS (e.g. 5 -> 10 demo tenants) must keep working on a
    database that already has the first batch, not silently stop adding
    the new ones. The per-tenant/per-user existence checks below already
    make every iteration a cheap no-op once seeded, so scanning the full
    list on every startup is safe and correct at this list's size."""
    from backend.database.models import Tenant, User

    if User.query.filter_by(username=FULL_ADMIN_USERNAME).first() is None:
        db.session.add(User(
            username=FULL_ADMIN_USERNAME,
            password_hash=generate_password_hash(FULL_ADMIN_PASSWORD),
            role="full_admin",
            tenant_id=None,
        ))
        db.session.commit()

    for name, slug in SEED_TENANTS:
        tenant = Tenant.query.filter_by(slug=slug).first()
        if not tenant:
            tenant = Tenant(name=name, slug=slug, enabled=True)
            db.session.add(tenant)
            db.session.flush()  # need tenant.id below before the outer commit

        admin_username = f"{slug}-admin"
        if User.query.filter_by(username=admin_username).first() is None:
            db.session.add(User(
                username=admin_username,
                password_hash=generate_password_hash(f"{slug}123"),
                role="tenant_admin",
                tenant_id=tenant.id,
            ))
    db.session.commit()
