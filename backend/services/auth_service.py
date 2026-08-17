from functools import wraps

from flask import jsonify, session

from backend.database.models import User


def current_user():
    """Loads the logged-in User from the session, or None if there is no
    session or it references a since-deleted user."""
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return User.query.get(user_id)


def is_full_admin(user=None):
    user = user if user is not None else current_user()
    return user is not None and user.role == "full_admin"


def tenant_scope(requested_tenant_id=None, user=None):
    """Returns the tenant_id a query should be filtered to, or None to mean
    "every tenant" (no filter). A tenant_admin is always locked to their own
    tenant_id -- whatever requested_tenant_id says is ignored, this is the
    real security boundary, not just a UI default. A full_admin gets
    whatever tenant_id was explicitly requested (e.g. a ?tenant_id= query
    param), or None (every tenant) if nothing was requested."""
    user = user if user is not None else current_user()
    if user is None:
        return None
    if user.role == "tenant_admin":
        return user.tenant_id
    if requested_tenant_id in (None, ""):
        return None
    try:
        return int(requested_tenant_id)
    except (TypeError, ValueError):
        return None


def tenant_scope_multi(requested_tenant_ids, user=None):
    """Like tenant_scope(), but for filters that accept a MULTI-select list
    of tenants (e.g. Offenses' checkbox filter) instead of a single one.
    requested_tenant_ids is the raw query-string value -- a comma-separated
    string like "1,3,5", or None/empty for "no filter". Returns a list of
    ints to filter to, or None to mean "every tenant" (no filter -- the
    default, always-available "All Tenants" state, deliberately distinct
    from an empty list, which would filter to nothing).

    A tenant_admin is always locked to [own tenant_id] regardless of what
    was requested -- same security boundary as tenant_scope(). Malformed
    pieces (e.g. "1,,abc") are silently skipped rather than rejecting the
    whole list, consistent with tenant_scope()'s own "bad input -> no
    filter" leniency."""
    user = user if user is not None else current_user()
    if user is None:
        return None
    if user.role == "tenant_admin":
        return [user.tenant_id]
    if not requested_tenant_ids:
        return None
    ids = []
    for part in str(requested_tenant_ids).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.append(int(part))
        except ValueError:
            continue
    return ids or None


def resolve_write_tenant_id(requested_tenant_id, user=None):
    """Like tenant_scope(), but for writes (create a Rule/Event/etc.) where
    "no filter" isn't a valid outcome -- every write always belongs to
    exactly one concrete tenant (see the Rule tenant-scoping decision: no
    "global rule" concept exists). A tenant_admin is always forced onto
    their own tenant_id; a full_admin must explicitly specify one via
    requested_tenant_id, otherwise None is returned so the caller can reject
    the request (e.g. 400 "tenant_id is required")."""
    user = user if user is not None else current_user()
    if user is None:
        return None
    if user.role == "tenant_admin":
        return user.tenant_id
    try:
        return int(requested_tenant_id)
    except (TypeError, ValueError):
        return None


def can_access_tenant(resource_tenant_id, user=None):
    """Whether the current user is allowed to read/write a resource that
    belongs to resource_tenant_id. A full_admin can access everything; a
    tenant_admin only their own tenant. Used by routes to turn a
    cross-tenant GET/PUT/DELETE-by-id into a 404 (not found), not a 403
    (which would leak that the resource exists in another tenant)."""
    user = user if user is not None else current_user()
    if user is None:
        return False
    if user.role == "full_admin":
        return True
    return resource_tenant_id == user.tenant_id


def require_full_admin(view):
    """Route decorator for endpoints only a full_admin may call (tenant/user
    management). A tenant_admin hitting one of these gets a 403, not a
    silently-scoped response -- there is no partial/tenant-scoped view of
    these endpoints."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_full_admin():
            return jsonify({"error": "Full admin access required"}), 403
        return view(*args, **kwargs)
    return wrapper
