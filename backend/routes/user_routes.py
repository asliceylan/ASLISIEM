from flask import Blueprint, request, jsonify, session

from backend.database.models import User
from backend.services import auth_service, user_service

bp = Blueprint("users", __name__, url_prefix="/api/users")

VALID_ROLES = ("full_admin", "tenant_admin")


@bp.route("", methods=["GET"])
@auth_service.require_full_admin
def list_users():
    return jsonify([u.to_dict() for u in user_service.list_users()])


@bp.route("", methods=["POST"])
@auth_service.require_full_admin
def create_user():
    payload = request.get_json(force=True)
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    role = payload.get("role")
    tenant_id = payload.get("tenant_id")

    if not username or not password or role not in VALID_ROLES:
        return jsonify({"error": "username, password and a valid role are required"}), 400
    if role == "tenant_admin" and not tenant_id:
        return jsonify({"error": "tenant_id is required for a tenant_admin"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already in use"}), 400

    user = user_service.create_user(username, password, role, tenant_id=tenant_id)
    return jsonify(user.to_dict()), 201


@bp.route("/<int:user_id>/password", methods=["PUT"])
@auth_service.require_full_admin
def reset_password(user_id):
    payload = request.get_json(force=True)
    new_password = payload.get("password") or ""
    if not new_password:
        return jsonify({"error": "password is required"}), 400
    user = user_service.reset_password(user_id, new_password)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict())


@bp.route("/<int:user_id>", methods=["DELETE"])
@auth_service.require_full_admin
def delete_user(user_id):
    # A full_admin must never be able to delete their own account here --
    # that would lock everyone out with no recovery path short of a fresh
    # DB (ensure_seed_tenants_and_admin only re-seeds admin when the users
    # table is completely empty).
    if user_id == session.get("user_id"):
        return jsonify({"error": "Cannot delete your own account"}), 400
    if not user_service.delete_user(user_id):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"deleted": True})
