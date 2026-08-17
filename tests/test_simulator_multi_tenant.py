import time
import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event, Tenant, User
from backend.simulator import control, topology
from backend.simulator.scenario import generate_kill_chain_events
from werkzeug.security import generate_password_hash
import random


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        # Defensive: make sure no leftover background thread from a failed
        # assertion keeps running (and writing to a torn-down DB) past this
        # test's teardown.
        for tenant_id in list(control._threads.keys()):
            control.stop_simulator(tenant_id)
        db.session.remove()
        db.drop_all()


def _two_tenants():
    a = Tenant(name="Tenant A", slug="sim-a", enabled=True)
    b = Tenant(name="Tenant B", slug="sim-b", enabled=True)
    db.session.add_all([a, b])
    db.session.commit()
    return a, b


def test_build_devices_gives_each_tenant_a_distinct_ip_block(app):
    a, b = _two_tenants()
    devices_a = topology.build_devices(a)
    devices_b = topology.build_devices(b)

    assert devices_a["dmz_web"].ip != devices_b["dmz_web"].ip
    assert devices_a["firewall"].ip != devices_b["firewall"].ip
    # Default (no tenant) topology is untouched -- backward compatibility.
    assert topology.DEVICES["dmz_web"].ip == "198.51.100.10"


def test_generate_kill_chain_events_uses_the_given_devices_not_the_global_default(app):
    tenant = Tenant(name="Custom", slug="custom-net", enabled=True)
    db.session.add(tenant)
    db.session.commit()
    devices = topology.build_devices(tenant)

    gen = generate_kill_chain_events(random.Random(1), devices=devices)
    first_event = next(gen)
    assert first_event["device"].ip == devices["firewall"].ip
    assert first_event["device"].ip != topology.DEVICES["firewall"].ip


def test_control_tracks_independent_status_per_tenant(app):
    a, b = _two_tenants()
    assert control.get_status(a.id) == control._IDLE_STATUS
    assert control.is_running(a.id) is False

    result = control.start_simulator(app, tenant_id=a.id, devices=topology.build_devices(a), speed_multiplier=500)
    assert result["started"] is True
    try:
        assert control.is_running(a.id) is True
        assert control.is_running(b.id) is False  # untouched
    finally:
        control.stop_simulator(a.id)


def test_starting_one_tenant_does_not_start_another(app):
    a, b = _two_tenants()
    control.start_simulator(app, tenant_id=a.id, devices=topology.build_devices(a), speed_multiplier=500)
    try:
        result = control.get_all_statuses()
        assert a.id in result
        assert b.id not in result
    finally:
        control.stop_simulator(a.id)


def test_stopping_one_tenant_leaves_the_other_running(app):
    a, b = _two_tenants()
    control.start_simulator(app, tenant_id=a.id, devices=topology.build_devices(a), speed_multiplier=500)
    control.start_simulator(app, tenant_id=b.id, devices=topology.build_devices(b), speed_multiplier=500)
    try:
        control.stop_simulator(a.id)
        assert control.is_running(a.id) is False
        assert control.is_running(b.id) is True
    finally:
        control.stop_simulator(b.id)


def test_two_concurrent_tenant_simulators_tag_events_with_their_own_tenant_id(app):
    a, b = _two_tenants()
    control.start_simulator(app, tenant_id=a.id, devices=topology.build_devices(a), speed_multiplier=500)
    control.start_simulator(app, tenant_id=b.id, devices=topology.build_devices(b), speed_multiplier=500)
    try:
        time.sleep(0.4)  # let both threads ingest a handful of events
    finally:
        control.stop_simulator(a.id)
        control.stop_simulator(b.id)

    events_a = Event.query.filter_by(tenant_id=a.id).all()
    events_b = Event.query.filter_by(tenant_id=b.id).all()
    assert len(events_a) > 0
    assert len(events_b) > 0
    # Tenant A's and Tenant B's IP blocks never overlap, so any event whose
    # destination_ip lands in Tenant A's block could never be mistaken for
    # a Tenant B device (real cross-contamination would show up as a
    # Tenant-A-tagged event carrying a Tenant-B device IP or vice versa).
    devices_a_ips = {d.ip for d in topology.build_devices(a).values()}
    devices_b_ips = {d.ip for d in topology.build_devices(b).values()}
    assert devices_a_ips.isdisjoint(devices_b_ips)
    assert any(e.destination_ip in devices_a_ips for e in events_a)
    assert any(e.destination_ip in devices_b_ips for e in events_b)
    assert not any(e.destination_ip in devices_b_ips for e in events_a)
    assert not any(e.destination_ip in devices_a_ips for e in events_b)


def _login_as(client, username, password):
    client.post("/login", data={"username": username, "password": password})


def test_tenant_admin_cannot_start_another_tenants_simulator(app):
    a, b = _two_tenants()
    db.session.add(User(
        username="sim-a-login", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=a.id,
    ))
    db.session.commit()
    client = app.test_client()
    _login_as(client, "sim-a-login", "pw")

    response = client.post(f"/api/simulator/{b.id}/start", json={"speed_multiplier": 1})
    assert response.status_code == 403
    assert control.is_running(b.id) is False


def test_tenant_admin_can_start_and_stop_own_tenant_simulator(app):
    a, _ = _two_tenants()
    db.session.add(User(
        username="sim-a-login2", password_hash=generate_password_hash("pw"),
        role="tenant_admin", tenant_id=a.id,
    ))
    db.session.commit()
    client = app.test_client()
    _login_as(client, "sim-a-login2", "pw")

    try:
        response = client.post(f"/api/simulator/{a.id}/start", json={"speed_multiplier": 500})
        assert response.status_code == 200
        assert response.get_json()["started"] is True
    finally:
        client.post(f"/api/simulator/{a.id}/stop")


def test_running_simulator_auto_creates_a_rule_from_a_detected_pattern(app):
    # End-to-end proof that the fully-autonomous suggestion automation
    # (backend/services/suggestion_service.auto_apply_new_rule_suggestions,
    # wired into SimulatorThread.run() on its own suggestion_check_interval_
    # seconds cadence) actually fires from a real background thread, not
    # just when called directly. speed_multiplier=500 both paces events at
    # their floor (~0.05s apart) and collapses rule/suggestion check
    # intervals to their 0.5s floor, so the kill-chain's bruteforce phase
    # (BRUTE_FORCE_THRESHOLD=5+ consecutive failed logons for one actor)
    # comfortably completes within a few real seconds.
    from backend.database.models import Offense, Rule

    a, _ = _two_tenants()
    control.start_simulator(app, tenant_id=a.id, devices=topology.build_devices(a), speed_multiplier=500)
    try:
        deadline = time.monotonic() + 8
        found = False
        while time.monotonic() < deadline:
            if Rule.query.filter_by(tenant_id=a.id, auto_pattern_type="brute_force").count() > 0:
                found = True
                break
            time.sleep(0.25)
    finally:
        control.stop_simulator(a.id)

    assert found, "expected an auto-generated brute_force rule within the deadline"
    auto_rule = Rule.query.filter_by(tenant_id=a.id, auto_pattern_type="brute_force").first()
    assert auto_rule.enabled is True
    assert Offense.query.filter_by(rule_id=auto_rule.id).count() >= 1
