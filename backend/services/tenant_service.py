from backend.database.db import db
from backend.database.models import Tenant


def list_tenants():
    # Ordered by id (creation order), not name -- a text sort would put
    # "Tenant10" right after "Tenant1" and before "Tenant2". Tenants are
    # never deleted/renumbered (only enabled/disabled, see update_tenant
    # below), so id order is a stable, always-correct proxy for creation
    # order without needing to parse any number out of the name/slug.
    return Tenant.query.order_by(Tenant.id).all()


def get_tenant(tenant_id):
    return Tenant.query.get(tenant_id)


def get_tenant_by_slug(slug):
    return Tenant.query.filter_by(slug=slug).first()


def create_tenant(name, slug):
    tenant = Tenant(name=name, slug=slug, enabled=True)
    db.session.add(tenant)
    db.session.commit()
    return tenant


def update_tenant(tenant_id, payload):
    # No real delete -- a tenant with existing Event/Rule/Offense/User rows
    # can only be disabled (enabled=False), never removed, per the Faz 1
    # scope decision (see plan). Disabling blocks new simulator starts
    # (simulator_routes checks Tenant.enabled) while preserving all data.
    tenant = Tenant.query.get(tenant_id)
    if not tenant:
        return None
    if "name" in payload:
        tenant.name = payload["name"]
    if "enabled" in payload:
        tenant.enabled = bool(payload["enabled"])
    db.session.commit()
    return tenant
