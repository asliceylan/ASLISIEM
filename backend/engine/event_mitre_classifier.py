from backend.engine import pattern_detectors
from backend.engine.condition_evaluator import get_field_value

# Well-known, uncontroversial Windows Security event IDs whose presence is
# widely cited (MITRE ATT&CK data sources, Sigma/Elastic detection rules) as
# a technique-level signal on its own -- deliberately short and conservative,
# not an attempt at exhaustive coverage. 4625 is intentionally absent: it is
# already covered by the is_failure_event() check below, mapping to the same
# T1110 as pattern_detectors.BRUTE_FORCE_MITRE.
EVENT_ID_MITRE_MAP = {
    "4688": {"tactic_id": "TA0002", "tactic_name": "Execution",
             "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"},
    "4672": {"tactic_id": "TA0004", "tactic_name": "Privilege Escalation",
             "technique_id": "T1078", "technique_name": "Valid Accounts"},
    "4720": {"tactic_id": "TA0003", "tactic_name": "Persistence",
             "technique_id": "T1136", "technique_name": "Create Account"},
    "1102": {"tactic_id": "TA0005", "tactic_name": "Defense Evasion",
             "technique_id": "T1070.001", "technique_name": "Indicator Removal: Clear Windows Event Logs"},
}

DOMAIN = "enterprise"


def classify_event(event):
    """Best-effort, single-event MITRE ATT&CK guess -- NOT the same kind of
    evidence as pattern_detectors.py's group/time-window detectors, which
    only tag a pattern after seeing repeated behavior. A single event is
    inherently more ambiguous (see event_mitre_classifier's caller for the
    "heuristic" UI labeling this drives). Returns a list of
    {"technique_id": str, "domain": "enterprise"} -- no name/tactics here,
    that's the caller's job via mitre_catalog_service (may be unsynced).
    Deduplicated by technique_id: multiple signals pointing at the same
    technique produce one entry, not repeats."""
    technique_ids = []

    if pattern_detectors.is_failure_event(event):
        technique_ids.append(pattern_detectors.BRUTE_FORCE_MITRE[0]["technique_id"])

    # Deliberately narrower than pattern_detectors.detect_port_scan: that
    # detector flags any burst of distinct destination_port values, which is
    # meaningless for one event (every network event has a destination
    # port). Here we only trust an event that the reporting device itself
    # already labeled as a scan (e.g. the simulator's CEF "Port Scan
    # Detected" signature, or a real IDS/firewall alert name).
    event_name = get_field_value(event, "event_name")
    if event_name and "port scan" in str(event_name).lower():
        technique_ids.append(pattern_detectors.PORT_SCAN_MITRE[0]["technique_id"])

    if event.log_format == "access_log" and pattern_detectors.matches_sqli_keyword(get_field_value(event, "Path")):
        technique_ids.append(pattern_detectors.SQLI_MITRE[0]["technique_id"])

    if event.device_type == "waf":
        technique_ids.append(pattern_detectors.WAF_BLOCKED_MITRE[0]["technique_id"])

    if event_name and "network intrusion detected" in str(event_name).lower():
        technique_ids.append(pattern_detectors.FW_ATTACK_MITRE[0]["technique_id"])

    event_id = get_field_value(event, "event_id")
    mapped = EVENT_ID_MITRE_MAP.get(str(event_id)) if event_id is not None else None
    if mapped:
        technique_ids.append(mapped["technique_id"])

    seen = set()
    deduped = []
    for tid in technique_ids:
        if tid in seen:
            continue
        seen.add(tid)
        deduped.append(tid)

    return [{"technique_id": tid, "domain": DOMAIN} for tid in deduped]
