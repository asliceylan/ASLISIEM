from datetime import datetime

from urllib.parse import unquote

from backend.engine.condition_evaluator import get_field_value
from backend.engine.time_window_engine import find_matching_windows

# Windows Security failure codes recognized directly by event_id.
FAILURE_EVENT_IDS = {"4625"}
# Fallback for non-Windows sources (syslog/CEF) where the failure is only
# expressed in free text -- event_name carries the raw message for syslog
# (see syslog_parser.parse_syslog_line) and the CEF "Name" field otherwise.
FAILURE_KEYWORDS = ("fail", "denied", "authentication failed")

SQLI_KEYWORDS = (
    "union select", "' or ", "1'='1", "drop table", "sleep(", ";--",
)

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 300

SPRAY_MIN_USERNAMES = 4
SPRAY_WINDOW_SECONDS = 600

PORT_SCAN_MIN_PORTS = 6
PORT_SCAN_WINDOW_SECONDS = 60

SQLI_MIN_HITS = 3
SQLI_WINDOW_SECONDS = 300

WAF_BLOCKED_MIN_HITS = 3
WAF_BLOCKED_WINDOW_SECONDS = 300

FW_ATTACK_MIN_HITS = 2
FW_ATTACK_WINDOW_SECONDS = 300


def _ts(event):
    return event.timestamp or event.created_at or datetime.utcnow()


def is_failure_event(event):
    """Shared by the group-level brute_force/password_spray detectors below
    and by event_mitre_classifier's single-event heuristic."""
    event_id = get_field_value(event, "event_id")
    if event_id is not None and str(event_id) in FAILURE_EVENT_IDS:
        return True
    name = get_field_value(event, "event_name")
    if name:
        lowered = str(name).lower()
        return any(kw in lowered for kw in FAILURE_KEYWORDS)
    return False


def matches_sqli_keyword(path):
    """True if `path` (a request path, typically URL-encoded) contains any
    SQLI_KEYWORDS entry -- checked against both the literal value and its
    decoded form, since the rule engine's "contains" check never decodes
    (see condition_evaluator.evaluate_condition). Shared by
    detect_sql_injection below and event_mitre_classifier."""
    if not path:
        return False
    raw_lower = str(path).lower()
    decoded_lower = unquote(raw_lower)
    return any(kw.replace(" ", "%20") in raw_lower or kw in decoded_lower for kw in SQLI_KEYWORDS)


def _group_by(events, field):
    groups = {}
    for event in events:
        value = get_field_value(event, field)
        if value in (None, ""):
            continue
        groups.setdefault(str(value), []).append(event)
    return groups


BRUTE_FORCE_MITRE = [{
    "tactic_id": "TA0006", "tactic_name": "Credential Access",
    "technique_id": "T1110", "technique_name": "Brute Force",
}]
SPRAY_MITRE = [{
    "tactic_id": "TA0006", "tactic_name": "Credential Access",
    "technique_id": "T1110", "technique_name": "Brute Force",
    "subtechnique_id": "T1110.003", "subtechnique_name": "Password Spraying",
}]
PORT_SCAN_MITRE = [{
    "tactic_id": "TA0043", "tactic_name": "Reconnaissance",
    "technique_id": "T1595", "technique_name": "Active Scanning",
    "subtechnique_id": "T1595.001", "subtechnique_name": "Scanning IP Blocks",
}]
SQLI_MITRE = [{
    "tactic_id": "TA0001", "tactic_name": "Initial Access",
    "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
}]
WAF_BLOCKED_MITRE = [{
    "tactic_id": "TA0001", "tactic_name": "Initial Access",
    "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
}]
FW_ATTACK_MITRE = [{
    "tactic_id": "TA0001", "tactic_name": "Initial Access",
    "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
}]

# A failed logon is recognized either by its Windows event_id or, for
# non-Windows sources, by free text in event_name (see is_failure_event) --
# the suggested rule's conditions cover both signals with OR so it works
# regardless of which log source triggered the detection.
BRUTE_FORCE_CONDITIONS = {"logic": "OR", "groups": [
    {"logic": "AND", "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}]},
    {"logic": "AND", "conditions": [{"field": "event_name", "operator": "contains", "value": "fail"}]},
]}
SPRAY_CONDITIONS = {"logic": "OR", "groups": [
    {"logic": "AND", "conditions": [{"field": "event_name", "operator": "contains", "value": "fail"}]},
]}
# destination_port alone is too broad -- access_log events also carry one
# (e.g. 443 for web traffic; see access_log_parser.py), so a burst of normal
# HTTP requests would satisfy this by itself. source_port narrows this to
# events that actually report both ends of a network connection: only the
# CEF parser populates it (cef_parser.py's ext.get("spt")) -- winevent/
# syslog/access_log all hardcode source_port to None.
PORT_SCAN_CONDITIONS = {"logic": "OR", "groups": [
    {"logic": "AND", "conditions": [
        {"field": "destination_port", "operator": "exists", "value": ""},
        {"field": "source_port", "operator": "exists", "value": ""},
    ]},
]}


def _sqli_conditions():
    """One OR'd group per SQLI_KEYWORDS entry, in both plain and "%20"-space-
    encoded form (request paths are typically URL-encoded, and the rule
    engine's "contains" check does no decoding -- see
    condition_evaluator.evaluate_condition), so the generic template detects
    real-world encoded and already-decoded payloads alike."""
    groups = []
    seen = set()
    for kw in SQLI_KEYWORDS:
        for variant in (kw, kw.replace(" ", "%20")):
            if variant in seen:
                continue
            seen.add(variant)
            groups.append({"logic": "AND", "conditions": [
                {"field": "Path", "operator": "contains", "value": variant},
            ]})
    return {"logic": "OR", "groups": groups}


SQLI_CONDITIONS = _sqli_conditions()

# Deliberately distinct, specific signature text from the firewall's own
# "Network Intrusion Detected" signal below -- if these two ever shared
# wording, their detectors' candidate sets (and any rule created from these
# conditions) would collide, corrupting each other's coverage accounting.
WAF_BLOCKED_CONDITIONS = {"logic": "OR", "groups": [
    {"logic": "AND", "conditions": [
        {"field": "event_name", "operator": "contains", "value": "SQL Injection Attack Detected"},
    ]},
]}
FW_ATTACK_CONDITIONS = {"logic": "OR", "groups": [
    {"logic": "AND", "conditions": [
        {"field": "event_name", "operator": "contains", "value": "Network Intrusion Detected"},
    ]},
]}


def _hit(pattern_type, group_key, matched_events, suggested_rule):
    matched_events = sorted(matched_events, key=_ts)
    return {
        "pattern_type": pattern_type,
        "group_key": group_key,
        "matched_event_ids": [e.id for e in matched_events],
        "first_seen": _ts(matched_events[0]),
        "last_seen": _ts(matched_events[-1]),
        "suggested_rule": suggested_rule,
    }


def detect_brute_force(events):
    """Repeated failed-authentication events from the same (source_ip,
    username) pair, bursting within BRUTE_FORCE_WINDOW_SECONDS. The
    suggested_rule is a fixed, attack-type-level template (not tied to any
    one source IP) -- grouping:["source_ip","username"] is what makes the
    rule itself apply per-actor once created."""
    suggested_rule = {
        "name": "Brute Force: Repeated Failed Logons",
        "description": (
            f"{BRUTE_FORCE_THRESHOLD}+ failed authentication attempts against the same account from "
            f"the same source IP within {BRUTE_FORCE_WINDOW_SECONDS // 60} minutes."
        ),
        "conditions": BRUTE_FORCE_CONDITIONS,
        "grouping": ["source_ip", "username"],
        "threshold_count": BRUTE_FORCE_THRESHOLD,
        "time_window_value": BRUTE_FORCE_WINDOW_SECONDS // 60,
        "time_window_unit": "minutes",
        "severity": "High",
        "mitre": BRUTE_FORCE_MITRE,
        "response": "CREATE_OFFENSE",
    }
    failures = [e for e in events if is_failure_event(e) and get_field_value(e, "username")]
    hits = []
    by_ip = _group_by(failures, "source_ip")
    for source_ip, ip_events in by_ip.items():
        by_user = _group_by(ip_events, "username")
        for username, group in by_user.items():
            windows = find_matching_windows(group, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS)
            for window in windows:
                hits.append(_hit("brute_force", f"{source_ip}|{username}", window, suggested_rule))
    return hits


def detect_password_spray(events):
    """A single source_ip failing authentication against many distinct
    usernames within SPRAY_WINDOW_SECONDS (breadth-first credential attack,
    as opposed to depth-first brute_force against one account)."""
    suggested_rule = {
        "name": "Password Spray: Credential Attempts Across Multiple Accounts",
        "description": (
            f"A single source IP attempting authentication against {SPRAY_MIN_USERNAMES}+ distinct "
            f"usernames within {SPRAY_WINDOW_SECONDS // 60} minutes."
        ),
        "conditions": SPRAY_CONDITIONS,
        "grouping": ["source_ip"],
        "threshold_count": SPRAY_MIN_USERNAMES,
        "time_window_value": SPRAY_WINDOW_SECONDS // 60,
        "time_window_unit": "minutes",
        "severity": "High",
        "mitre": SPRAY_MITRE,
        "response": "CREATE_OFFENSE",
    }
    failures = [e for e in events if is_failure_event(e) and get_field_value(e, "username")]
    hits = []
    by_ip = _group_by(failures, "source_ip")
    for source_ip, group in by_ip.items():
        group_sorted = sorted(group, key=_ts)
        n = len(group_sorted)
        i = 0
        while i < n:
            j = i
            usernames_seen = set()
            while j < n and (_ts(group_sorted[j]) - _ts(group_sorted[i])).total_seconds() <= SPRAY_WINDOW_SECONDS:
                usernames_seen.add(get_field_value(group_sorted[j], "username"))
                j += 1
            if len(usernames_seen) >= SPRAY_MIN_USERNAMES:
                window = group_sorted[i:j]
                hits.append(_hit("password_spray", source_ip, window, suggested_rule))
                i = j
            else:
                i += 1
    return hits


def detect_port_scan(events):
    """A single source_ip touching many distinct destination ports within
    PORT_SCAN_WINDOW_SECONDS."""
    suggested_rule = {
        "name": "Port Scan: Multiple Destination Ports Probed",
        "description": (
            f"A single source IP connecting to {PORT_SCAN_MIN_PORTS}+ distinct destination ports "
            f"within {PORT_SCAN_WINDOW_SECONDS} seconds."
        ),
        "conditions": PORT_SCAN_CONDITIONS,
        "grouping": ["source_ip"],
        "threshold_count": PORT_SCAN_MIN_PORTS,
        # Makes threshold_count mean "N DISTINCT destination_port values",
        # not "N events" -- once saved, this is what actually stops a burst
        # of same-port WAF/firewall-attack events (fixed dpt=443) from
        # satisfying this rule (see time_window_engine.find_matching_windows).
        # destination_port/source_port "exists" above stay as a defense-in-
        # depth pre-filter, not the primary guard anymore.
        "distinct_field": "destination_port",
        "time_window_value": PORT_SCAN_WINDOW_SECONDS,
        "time_window_unit": "seconds",
        "severity": "Medium",
        "mitre": PORT_SCAN_MITRE,
        "response": "CREATE_OFFENSE",
    }
    candidates = [e for e in events if get_field_value(e, "destination_port") not in (None, "")
                  and get_field_value(e, "source_port") not in (None, "")
                  and get_field_value(e, "source_ip")]
    hits = []
    by_ip = _group_by(candidates, "source_ip")
    for source_ip, group in by_ip.items():
        group_sorted = sorted(group, key=_ts)
        n = len(group_sorted)
        i = 0
        while i < n:
            j = i
            ports_seen = set()
            while j < n and (_ts(group_sorted[j]) - _ts(group_sorted[i])).total_seconds() <= PORT_SCAN_WINDOW_SECONDS:
                ports_seen.add(get_field_value(group_sorted[j], "destination_port"))
                j += 1
            if len(ports_seen) >= PORT_SCAN_MIN_PORTS:
                window = group_sorted[i:j]
                hits.append(_hit("port_scan", source_ip, window, suggested_rule))
                i = j
            else:
                i += 1
    return hits


def detect_sql_injection(events):
    """Access-log requests whose path contains a known SQL-injection
    signature, bursting from the same source_ip."""
    suggested_rule = {
        "name": "SQL Injection: Malicious Query Patterns Detected",
        "description": (
            f"{SQLI_MIN_HITS}+ requests from the same source IP containing SQL-injection-like payloads "
            f"within {SQLI_WINDOW_SECONDS // 60} minutes."
        ),
        "conditions": SQLI_CONDITIONS,
        "grouping": ["source_ip"],
        "threshold_count": SQLI_MIN_HITS,
        "time_window_value": SQLI_WINDOW_SECONDS // 60,
        "time_window_unit": "minutes",
        "severity": "Critical",
        "mitre": SQLI_MITRE,
        "response": "CREATE_OFFENSE",
    }
    candidates = []
    for event in events:
        # log_format is a real Event column, not one of EVENT_COLUMNS/derived
        # fields that get_field_value resolves -- read it directly.
        if event.log_format != "access_log":
            continue
        if matches_sqli_keyword(get_field_value(event, "Path")):
            candidates.append(event)

    hits = []
    by_ip = _group_by(candidates, "source_ip")
    for source_ip, group in by_ip.items():
        windows = find_matching_windows(group, SQLI_MIN_HITS, SQLI_WINDOW_SECONDS)
        for window in windows:
            hits.append(_hit("sql_injection", source_ip, window, suggested_rule))
    return hits


def detect_waf_blocked(events):
    """A burst of WAF-blocked requests from the same source_ip. The
    candidate filter uses event.device_type directly (a real Event column,
    not resolvable via get_field_value/EVENT_COLUMNS -- see the port_scan
    source_port fix for why that distinction matters), while the suggested
    rule's own conditions reference event_name instead, since that's what
    the rule engine can actually evaluate once the rule is saved."""
    suggested_rule = {
        "name": "WAF Blocked: SQL Injection Attempts",
        "description": (
            f"{WAF_BLOCKED_MIN_HITS}+ requests from the same source IP blocked by the WAF as SQL "
            f"injection attempts within {WAF_BLOCKED_WINDOW_SECONDS // 60} minutes."
        ),
        "conditions": WAF_BLOCKED_CONDITIONS,
        "grouping": ["source_ip"],
        "threshold_count": WAF_BLOCKED_MIN_HITS,
        "time_window_value": WAF_BLOCKED_WINDOW_SECONDS // 60,
        "time_window_unit": "minutes",
        "severity": "Critical",
        "mitre": WAF_BLOCKED_MITRE,
        "response": "CREATE_OFFENSE",
    }
    candidates = [e for e in events if e.device_type == "waf"]
    hits = []
    by_ip = _group_by(candidates, "source_ip")
    for source_ip, group in by_ip.items():
        windows = find_matching_windows(group, WAF_BLOCKED_MIN_HITS, WAF_BLOCKED_WINDOW_SECONDS)
        for window in windows:
            hits.append(_hit("waf_blocked", source_ip, window, suggested_rule))
    return hits


def detect_fw_attack_detected(events):
    """A burst of firewall/IPS "Network Intrusion Detected" signatures from
    the same source_ip -- a network-layer signal distinct from both
    port_scan (which never mentions "intrusion") and waf_blocked (a
    different device/signature entirely)."""
    suggested_rule = {
        "name": "Firewall: Network Intrusion Signatures Detected",
        "description": (
            f"{FW_ATTACK_MIN_HITS}+ firewall/IPS 'Network Intrusion Detected' signatures from the same "
            f"source IP within {FW_ATTACK_WINDOW_SECONDS // 60} minutes."
        ),
        "conditions": FW_ATTACK_CONDITIONS,
        "grouping": ["source_ip"],
        "threshold_count": FW_ATTACK_MIN_HITS,
        "time_window_value": FW_ATTACK_WINDOW_SECONDS // 60,
        "time_window_unit": "minutes",
        "severity": "High",
        "mitre": FW_ATTACK_MITRE,
        "response": "CREATE_OFFENSE",
    }
    candidates = [e for e in events
                  if e.event_name and "network intrusion detected" in e.event_name.lower()]
    hits = []
    by_ip = _group_by(candidates, "source_ip")
    for source_ip, group in by_ip.items():
        windows = find_matching_windows(group, FW_ATTACK_MIN_HITS, FW_ATTACK_WINDOW_SECONDS)
        for window in windows:
            hits.append(_hit("fw_attack_detected", source_ip, window, suggested_rule))
    return hits


# Single source of truth for "what detectors exist" -- detect_all() below
# iterates this instead of hand-listing calls, and tests/
# test_pattern_detector_isolation.py reads it to make sure every detector
# has a registered cross-pattern isolation fixture (see that file's
# docstring for why this exists: three separate incidents of one
# detector's suggested rule matching another pattern's events).
DETECTORS = {
    "brute_force": detect_brute_force,
    "password_spray": detect_password_spray,
    "port_scan": detect_port_scan,
    "sql_injection": detect_sql_injection,
    "waf_blocked": detect_waf_blocked,
    "fw_attack_detected": detect_fw_attack_detected,
}


def detect_all(events):
    hits = []
    for detect_fn in DETECTORS.values():
        hits.extend(detect_fn(events))
    return hits
