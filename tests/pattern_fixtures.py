"""Shared event-construction helpers and canonical per-pattern fixtures.

NOT a test file (no test_ prefix, not collected by pytest) -- imported by
test_pattern_detectors.py (per-detector unit tests) and
test_pattern_detector_isolation.py (the N-by-N cross-pattern regression
test). Centralizing these here means a new pattern only needs ONE new
fixture function, registered once in POSITIVE_FIXTURES, to be automatically
exercised against every other detector -- see test_pattern_detector_isolation.py
for why this exists.
"""
from datetime import datetime, timedelta

from backend.engine import pattern_detectors
from backend.services.ingest_service import ingest_raw_log
from backend.simulator import log_templates, topology

BASE_TS = datetime(2026, 1, 1, 12, 0, 0)


def winevent(ts, event_id, username, source_ip, message):
    mail = topology.DEVICES["dmz_mail"]
    raw = log_templates.render_winevent(mail, ts, event_id, message, username, source_ip, logon_type=3)
    return ingest_raw_log(raw, mail)


def port_scan_hit(ts, source_ip, port):
    fw = topology.DEVICES["firewall"]
    web = topology.DEVICES["dmz_web"]
    # spt (source_port) matches how the real simulator builds recon events
    # (scenario.py._recon_events) -- required so this event carries both
    # ends of the connection, same as detect_port_scan expects.
    ext = {"src": source_ip, "spt": "51000", "dst": web.ip, "dpt": str(port), "act": "deny"}
    raw = log_templates.render_cef(fw, ts, "5001", "Port Scan Detected", "7", ext)
    return ingest_raw_log(raw, fw)


def access_log_request(ts, source_ip, query):
    web = topology.DEVICES["dmz_web"]
    raw = log_templates.render_access_log(web, ts, source_ip, "GET", f"/product.php?{query}", 200, 512)
    return ingest_raw_log(raw, web)


def waf_blocked_hit(ts, source_ip):
    waf = topology.DEVICES["waf"]
    web = topology.DEVICES["dmz_web"]
    ext = {"src": source_ip, "spt": "51000", "dst": web.ip, "dpt": "443",
           "request": "/product.php?id=1", "act": "blocked"}
    raw = log_templates.render_cef(waf, ts, "9001", "SQL Injection Attack Detected", "9", ext, product="WAF")
    return ingest_raw_log(raw, waf)


def fw_intrusion_hit(ts, source_ip):
    fw = topology.DEVICES["firewall"]
    web = topology.DEVICES["dmz_web"]
    ext = {"src": source_ip, "spt": "51000", "dst": web.ip, "dpt": "443", "act": "deny"}
    raw = log_templates.render_cef(fw, ts, "5020", "Network Intrusion Detected", "9", ext)
    return ingest_raw_log(raw, fw)


def _brute_force_fixture():
    for i in range(pattern_detectors.BRUTE_FORCE_THRESHOLD):
        winevent(BASE_TS + timedelta(seconds=i * 10), 4625, "jsmith", "203.0.113.44",
                 "An account failed to log on.")


def _password_spray_fixture():
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        winevent(BASE_TS + timedelta(seconds=i * 10), 4625, user, "203.0.113.44",
                 "An account failed to log on.")


def _port_scan_fixture():
    for i, port in enumerate([22, 80, 443, 3389, 8080, 8443]):
        port_scan_hit(BASE_TS + timedelta(seconds=i * 2), "203.0.113.44", port)


def _sql_injection_fixture():
    payloads = [
        "id=1'%20OR%20'1'='1",
        "id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "id=1;%20DROP%20TABLE%20users;--",
    ]
    for i, payload in enumerate(payloads):
        access_log_request(BASE_TS + timedelta(seconds=i * 5), "203.0.113.44", payload)


def _waf_blocked_fixture():
    for i in range(pattern_detectors.WAF_BLOCKED_MIN_HITS):
        waf_blocked_hit(BASE_TS + timedelta(seconds=i * 5), "203.0.113.44")


def _fw_attack_detected_fixture():
    for i in range(pattern_detectors.FW_ATTACK_MIN_HITS):
        fw_intrusion_hit(BASE_TS + timedelta(seconds=i * 5), "203.0.113.44")


# pattern_type -> zero-arg callable that creates a minimal, canonical set of
# events which should trigger THAT pattern and no other. Must be called
# inside an active app/db context (i.e. from within a test using the `app`
# fixture). Keep these minimal: an over-built fixture risks accidentally
# also satisfying another pattern's threshold, producing a false failure in
# test_pattern_detector_isolation.py.
POSITIVE_FIXTURES = {
    "brute_force": _brute_force_fixture,
    "password_spray": _password_spray_fixture,
    "port_scan": _port_scan_fixture,
    "sql_injection": _sql_injection_fixture,
    "waf_blocked": _waf_blocked_fixture,
    "fw_attack_detected": _fw_attack_detected_fixture,
}
