import json
import re

from backend.parsers import syslog_parser, cef_parser, access_log_parser, winevent_parser
from backend.parsers.normalizer import TARGET_FIELDS

_PRI_RE = re.compile(r"^<\d{1,3}>")
_RFC3164_HEADER_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+")
_ACCESS_LOG_SIG_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ \S+ \S+" \d{3} \S+')
_WINEVENT_EVENTID_RE = re.compile(r"^Event ID:\s*\d+", re.MULTILINE)
_WINEVENT_TIMECREATED_RE = re.compile(r"^TimeCreated:", re.MULTILINE)

_PARSERS = {
    "cef": cef_parser.parse_cef_line,
    "syslog": syslog_parser.parse_syslog_line,
    "access_log": access_log_parser.parse_access_log_line,
    "winevent": winevent_parser.parse_winevent_block,
}


def detect_format(raw_text):
    """Classifies a raw log line/block into one of the 4 supported formats
    using ordered signature checks. A syslog envelope is always peeled first,
    which is what correctly resolves CEF-wrapped-in-syslog (real firewalls
    emit CEF this way) as "cef" rather than falling through to "syslog"."""
    text = raw_text.strip()

    pri_match = _PRI_RE.match(text)
    remainder = text[pri_match.end():] if pri_match else text
    header_match = _RFC3164_HEADER_RE.match(remainder)
    body = remainder[header_match.end():] if header_match else remainder

    if body.startswith("CEF:0|"):
        return "cef"
    if text.startswith("CEF:0|"):
        return "cef"
    if pri_match or header_match:
        return "syslog"
    if _ACCESS_LOG_SIG_RE.match(text):
        return "access_log"
    if _WINEVENT_EVENTID_RE.search(text) and _WINEVENT_TIMECREATED_RE.search(text):
        return "winevent"
    return "unknown"


def _degraded_record(raw_text, reason):
    return {
        "event_id": None, "event_name": "UNPARSED_LOG", "source_ip": None,
        "source_port": None, "destination_ip": None, "destination_port": None,
        "username": None, "process_name": None, "timestamp": None,
        "derived_fields": {"__parse_error__": reason},
        "raw_line": raw_text,
        "_detected_format": "unknown",
    }


def parse_and_normalize(raw_text, device=None):
    """Detects the format purely from raw_text (no hint from the caller) and
    parses it into the 9 normalized TARGET_FIELDS + a raw_data JSON blob.
    Never raises: any detection/parsing failure degrades to a safe,
    fully-preserved 'unknown' record instead of dropping the log."""
    fmt = detect_format(raw_text)
    if fmt == "unknown":
        parsed = _degraded_record(raw_text, "no known format signature matched")
    else:
        try:
            parsed = _PARSERS[fmt](raw_text, device=device)
            parsed["raw_line"] = raw_text
            parsed["_detected_format"] = fmt
        except Exception as exc:
            parsed = _degraded_record(raw_text, str(exc))

    normalized = {target: parsed.get(target) for target in TARGET_FIELDS}
    normalized["raw_data"] = json.dumps({
        "raw_line": parsed["raw_line"],
        "__derived_fields__": parsed.get("derived_fields", {}),
    }, ensure_ascii=False, default=str)
    normalized["_detected_format"] = parsed["_detected_format"]
    return normalized
