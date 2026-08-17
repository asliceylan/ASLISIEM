from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from backend.database.models import User
from backend.services import auth_service

bp = Blueprint("auth", __name__)


@bp.route("/api/session", methods=["GET"])
def session_info():
    # Lets the frontend learn its own role/tenant without duplicating that
    # logic client-side -- used to show/hide the Tenants nav page, default
    # the Rules/Simulator tenant pickers, etc. The /api/* before_request
    # gate already guarantees a user is logged in by the time this runs.
    user = auth_service.current_user()
    return jsonify(user.to_dict())


@bp.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        if auth_service.current_user():
            return redirect(url_for("index"))
        return render_template("login.html", error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        session["user_id"] = user.id
        return redirect(url_for("index"))
    return render_template("login.html", error="Geçersiz kullanıcı adı veya şifre."), 401


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login_page"))
