import os
import sys

# allow running as `python backend/app.py` from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, g, jsonify, redirect, render_template, request, url_for

from backend.config import Config
from backend.database.db import db, configure_sqlite
from backend.database.schema_guard import (
    ensure_event_columns, ensure_mitre_technique_columns, ensure_rule_columns,
    ensure_offense_columns, ensure_default_tenant_and_migrate, ensure_tenant_renames,
    ensure_seed_tenants_and_admin,
)
from backend.services import auth_service

from backend.routes import (
    dashboard_routes, import_routes, event_routes, rule_routes, offense_routes,
    mitre_routes, simulator_routes, asset_routes, log_source_routes, auth_routes,
    tenant_routes, user_routes,
)


def create_app():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        template_folder=os.path.join(root_dir, "frontend", "templates"),
        static_folder=os.path.join(root_dir, "frontend", "static"),
    )
    app.config.from_object(Config)

    db.init_app(app)

    app.register_blueprint(dashboard_routes.bp)
    app.register_blueprint(import_routes.bp)
    app.register_blueprint(event_routes.bp)
    app.register_blueprint(rule_routes.bp)
    app.register_blueprint(offense_routes.bp)
    app.register_blueprint(mitre_routes.bp)
    app.register_blueprint(simulator_routes.bp)
    app.register_blueprint(asset_routes.bp)
    app.register_blueprint(log_source_routes.bp)
    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(tenant_routes.bp)
    app.register_blueprint(user_routes.bp)

    with app.app_context():
        configure_sqlite(db)
        db.create_all()  # creates schema only -- never seeds any data
        ensure_event_columns(db.engine)  # backfills columns on pre-existing DBs
        ensure_mitre_technique_columns(db.engine)  # backfills columns on pre-existing DBs
        ensure_rule_columns(db.engine)  # backfills columns on pre-existing DBs
        ensure_offense_columns(db.engine)  # backfills columns on pre-existing DBs
        # Order matters: tenant_id columns must exist (above) before this
        # backfills pre-multi-tenant rows into a "Default Tenant".
        ensure_default_tenant_and_migrate(db.engine)
        # Renames any demo tenant still seeded under its old fictional-
        # company slug (acme, globex, ...) to the generic Tenant1..Tenant10
        # scheme. Must run BEFORE ensure_seed_tenants_and_admin below, or
        # that call would see the new slugs as "missing" and create fresh
        # duplicate tenants instead of renaming the existing ones.
        ensure_tenant_renames(db.engine)
        # Seeds the full_admin login (migrated from the old hardcoded
        # admin/admin123) plus the demo tenants + their tenant_admin accounts.
        ensure_seed_tenants_and_admin(db.engine)

    @app.before_request
    def require_login_for_api():
        # Loaded once per request so every route/service can read g.user
        # instead of re-querying the session -- second layer of the login
        # gate (the "/" route below is the first) so a request that reaches
        # an /api/* endpoint directly (bypassing index.html entirely, or
        # after a session expires while the SPA is still open) is rejected
        # too, not just the page load.
        g.user = auth_service.current_user()
        if request.path.startswith("/api/") and g.user is None:
            return jsonify({"error": "Authentication required"}), 401

    @app.route("/")
    def index():
        if auth_service.current_user() is None:
            return redirect(url_for("auth.login_page"))
        return render_template("index.html")

    @app.route("/simulators")
    def simulators_direct():
        # Deliberately not linked from the nav -- reachable only by typing
        # this URL directly. Reuses the same session/login and the same SPA
        # shell as "/"; app.js detects this path and shows the Simulators
        # page instead of the Dashboard default.
        if auth_service.current_user() is None:
            return redirect(url_for("auth.login_page"))
        return render_template("index.html")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5050)
