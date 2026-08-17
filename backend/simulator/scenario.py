import random
from datetime import datetime, timedelta

from backend.simulator import topology, log_templates

BRUTEFORCE_USERNAME = "jsmith"
LINUX_USERNAMES = ("root", "admin", "ubuntu")


def _recon_events(rng, attacker_ip, ts, devices):
    events = []
    fw = devices["firewall"]
    targets = [devices["dmz_web"], devices["dmz_mail"]]
    ports = rng.sample(range(20, 1024), 8)
    for i, port in enumerate(ports):
        target = targets[i % len(targets)]
        ext = {
            "src": attacker_ip, "spt": str(rng.randint(1024, 65000)),
            "dst": target.ip, "dpt": str(port), "act": "deny",
            "cs1Label": "ScanSignature", "cs1": "Multiple Port Connection Attempts",
        }
        raw = log_templates.render_cef(fw, ts, "5001", "Port Scan Detected", "7", ext)
        events.append({"phase": "recon", "device": fw, "raw_text": raw})
        ts += timedelta(seconds=1)

    # The firewall's own IPS independently flags the scan burst as an
    # intrusion attempt -- a separate detection point from the per-port
    # "Port Scan Detected" lines above (see pattern_detectors.detect_
    # fw_attack_detected, which keys off this exact, deliberately distinct
    # signature name so it never overlaps with WAF-blocked detection).
    last_target = targets[(len(ports) - 1) % len(targets)]
    intrusion_ext = {
        "src": attacker_ip, "spt": str(rng.randint(1024, 65000)),
        "dst": last_target.ip, "dpt": str(ports[-1]), "act": "deny",
        "cs1Label": "ThreatSignature", "cs1": "Known Exploit Attempt",
    }
    raw = log_templates.render_cef(fw, ts, "5020", "Network Intrusion Detected", "9", intrusion_ext)
    events.append({"phase": "recon", "device": fw, "raw_text": raw})
    ts += timedelta(seconds=1)

    router = devices["router"]
    raw = log_templates.render_syslog(
        router, ts, "%SEC-6-IPACCESSLOGP", None,
        f"list 101 denied tcp {attacker_ip}({rng.randint(1024, 65000)}) -> {fw.ip}(23), 1 packet",
    )
    events.append({"phase": "recon", "device": router, "raw_text": raw})
    ts += timedelta(seconds=1)
    return events, ts


def _bruteforce_events(rng, attacker_ip, ts, devices):
    events = []
    mail = devices["dmz_mail"]
    db = devices["dmz_db"]

    # A parallel SSH brute-force burst against the Linux DB host, alongside
    # the Windows attack below -- must stay BEFORE the winevent block so the
    # phase's last event remains the single 4624 success (see
    # test_bruteforce_phase_ends_with_a_single_success_event).
    ssh_attempts = rng.randint(6, 10)
    for _ in range(ssh_attempts):
        username = rng.choice(LINUX_USERNAMES)
        port = rng.randint(1024, 65000)
        pid = rng.randint(1000, 9999)
        raw = log_templates.render_syslog(
            db, ts, "sshd", pid,
            f"Failed password for {username} from {attacker_ip} port {port} ssh2",
        )
        events.append({"phase": "bruteforce", "device": db, "raw_text": raw})
        ts += timedelta(seconds=1)

    attempts = rng.randint(8, 12)
    for _ in range(attempts):
        raw = log_templates.render_winevent(
            mail, ts, 4625, "An account failed to log on.",
            BRUTEFORCE_USERNAME, attacker_ip, logon_type=3,
        )
        events.append({"phase": "bruteforce", "device": mail, "raw_text": raw})
        ts += timedelta(seconds=1)

    # The attacker eventually guesses correctly -- exactly one success, last.
    raw = log_templates.render_winevent(
        mail, ts, 4624, "An account was successfully logged on.",
        BRUTEFORCE_USERNAME, attacker_ip, logon_type=3,
    )
    events.append({"phase": "bruteforce", "device": mail, "raw_text": raw})
    ts += timedelta(seconds=1)
    return events, ts


def _sqli_events(rng, attacker_ip, ts, devices):
    events = []
    web = devices["dmz_web"]
    waf = devices["waf"]
    fw = devices["firewall"]
    # Spaces are URL-encoded as %20, matching how a real browser/attack tool
    # would actually send these -- an access-log path never contains a
    # literal, unencoded space. The WAF's "request" extension value below
    # reuses the same encoded path for the same reason (CEF extension
    # parsing splits on whitespace, see cef_parser._EXT_RE).
    payloads = [
        "id=1'%20OR%20'1'='1",
        "id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "id=1;%20DROP%20TABLE%20users;--",
        "id=1'%20AND%20SLEEP(5)--",
    ]
    statuses = [200, 500, 403, 200]
    for _ in range(rng.randint(5, 8)):
        payload = rng.choice(payloads)
        status = rng.choice(statuses)
        path = f"/product.php?{payload}"
        raw = log_templates.render_access_log(
            web, ts, attacker_ip, "GET", path, status, rng.randint(200, 5000),
        )
        events.append({"phase": "sqli", "device": web, "raw_text": raw})
        ts += timedelta(seconds=1)

        # The WAF independently inspects and blocks the same malicious
        # request at the application layer -- a distinct signature name from
        # the firewall's network-layer signal below (see pattern_detectors.
        # detect_waf_blocked / detect_fw_attack_detected).
        waf_ext = {
            "src": attacker_ip, "spt": str(rng.randint(1024, 65000)),
            "dst": web.ip, "dpt": "443", "request": path, "act": "blocked",
            "cs1Label": "RuleID", "cs1": "942100",
        }
        raw = log_templates.render_cef(
            waf, ts, "9001", "SQL Injection Attack Detected", "9", waf_ext, product="WAF",
        )
        events.append({"phase": "sqli", "device": waf, "raw_text": raw})
        ts += timedelta(seconds=1)

    # The firewall/IPS also independently flags the network-layer traffic
    # pattern once for the phase (network-layer signal, complementing the
    # WAF's per-request application-layer blocks above).
    fw_ext = {
        "src": attacker_ip, "spt": str(rng.randint(1024, 65000)),
        "dst": web.ip, "dpt": "443", "act": "deny",
        "cs1Label": "ThreatSignature", "cs1": "Web Application Attack Detected",
    }
    raw = log_templates.render_cef(fw, ts, "5020", "Network Intrusion Detected", "9", fw_ext)
    events.append({"phase": "sqli", "device": fw, "raw_text": raw})
    ts += timedelta(seconds=1)

    return events, ts


def _lateral_movement_events(rng, attacker_ip, ts, devices):
    events = []
    fw = devices["firewall"]
    mail = devices["dmz_mail"]
    db = devices["dmz_db"]
    internal = devices["internal_host"]

    ext = {
        "src": mail.ip, "spt": str(rng.randint(1024, 65000)),
        "dst": internal.ip, "dpt": "445", "act": "allow",
    }
    raw = log_templates.render_cef(fw, ts, "5010", "New Internal Connection Allowed", "8", ext)
    events.append({"phase": "lateral_movement", "device": fw, "raw_text": raw})
    ts += timedelta(seconds=1)

    raw = log_templates.render_winevent(
        internal, ts, 4624, "An account was successfully logged on.",
        BRUTEFORCE_USERNAME, mail.ip, logon_type=3,
    )
    events.append({"phase": "lateral_movement", "device": internal, "raw_text": raw})
    ts += timedelta(seconds=1)

    pid = rng.randint(1000, 9999)
    raw = log_templates.render_syslog(
        db, ts, "postgres", pid,
        f'FATAL: password authentication failed for user "sa" from {mail.ip} port {rng.randint(1024, 65000)}',
    )
    events.append({"phase": "lateral_movement", "device": db, "raw_text": raw})
    ts += timedelta(seconds=1)

    raw = log_templates.render_syslog(
        db, ts, "postgres", pid + 1,
        f'LOG: unusually large result set returned for query "SELECT * FROM customers" '
        f'requested by role "sa" from {mail.ip}',
    )
    events.append({"phase": "lateral_movement", "device": db, "raw_text": raw})
    ts += timedelta(seconds=1)

    # Having pivoted onto the DB host, the attacker escalates privileges via
    # sudo -- appended last so it doesn't disturb db_events[0] in
    # test_lateral_movement_phase_includes_dmz_db_syslog_event.
    sudo_pid = rng.randint(1000, 9999)
    raw = log_templates.render_syslog(
        db, ts, "sudo", sudo_pid,
        f"{BRUTEFORCE_USERNAME} : TTY=pts/0 ; PWD=/home/{BRUTEFORCE_USERNAME} ; "
        f"USER=root ; COMMAND=/bin/cat /etc/shadow",
    )
    events.append({"phase": "lateral_movement", "device": db, "raw_text": raw})
    ts += timedelta(seconds=1)

    return events, ts


_PHASES = (_recon_events, _bruteforce_events, _sqli_events, _lateral_movement_events)


def generate_kill_chain_events(rng=None, devices=None):
    """Infinite generator yielding {"phase", "device", "raw_text"} dicts in a
    fixed order: recon -> bruteforce -> sqli -> lateral_movement, looping
    forever with a fresh random attacker IP drawn each time the chain
    restarts (continuous-stream requirement).

    devices defaults to the module-level single-tenant topology.DEVICES for
    backward compatibility. Multi-tenant callers (see
    backend/simulator/runner.py) pass their own tenant-specific dict built
    via topology.build_devices(tenant) instead -- this is always passed
    explicitly through every phase function rather than read from a shared
    global, since several tenants' generators run concurrently in different
    threads."""
    rng = rng or random.Random()
    devices = devices or topology.DEVICES
    ts = datetime.utcnow()
    while True:
        attacker_ip = topology.random_attacker_ip(rng)
        for phase_fn in _PHASES:
            events, ts = phase_fn(rng, attacker_ip, ts, devices)
            for event in events:
                yield event
