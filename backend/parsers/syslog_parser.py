import re
from datetime import datetime

# <PRI>Mon DD HH:MM:SS host tag[pid]: message   (RFC3164-style, no year in the timestamp)
_HEADER_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<remainder>.*)$"
)
_TAG_RE = re.compile(r"^(?P<tag>[\w.\-/%]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MNEMONIC_RE = re.compile(r"%[\w-]+-\d+-[\w]+")


def _parse_rfc3164_timestamp(ts_text, year=None):
    year = year or datetime.utcnow().year
    try:
        return datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def strip_syslog_header(text):
    """Peels an optional <PRI>Mon DD HH:MM:SS host  envelope off the front of
    a line. Returns (pri:int|None, timestamp:datetime|None, hostname:str|None,
    remainder:str). If there is no syslog envelope, remainder is the original
    text unchanged and the other three values are None."""
    match = _HEADER_RE.match(text.strip())
    if not match:
        return None, None, None, text.strip()
    pri = int(match.group("pri"))
    timestamp = _parse_rfc3164_timestamp(match.group("ts"))
    hostname = match.group("host")
    remainder = match.group("remainder")
    return pri, timestamp, hostname, remainder


def parse_syslog_line(line, device=None):
    """Parses a generic (non-CEF) syslog line into the normalized field shape
    used by ingest_service. `device` (optional) supplies the reporting
    device's own IP for destination_ip when the message doesn't make that
    explicit itself."""
    pri, timestamp, hostname, remainder = strip_syslog_header(line)

    tag_match = _TAG_RE.match(remainder)
    if tag_match:
        tag = tag_match.group("tag")
        pid = tag_match.group("pid")
        message = tag_match.group("message")
    else:
        tag, pid, message = None, None, remainder

    ip_match = _IPV4_RE.search(message)
    # Cisco-style "%FACILITY-SEVERITY-MNEMONIC" codes land in the tag portion
    # (before the first ":"), not in the message remainder, so search the
    # whole post-header text rather than just `message`.
    mnemonic_match = _MNEMONIC_RE.search(remainder)

    facility = pri // 8 if pri is not None else None
    severity = pri % 8 if pri is not None else None

    return {
        "event_id": mnemonic_match.group(0) if mnemonic_match else None,
        "event_name": message.strip() or None,
        "source_ip": ip_match.group(0) if ip_match else None,
        "source_port": None,
        "destination_ip": (device.ip if device else None),
        "destination_port": None,
        "username": None,
        "process_name": tag,
        "timestamp": timestamp,
        "derived_fields": {
            "Hostname": hostname,
            "Process": tag,
            "PID": pid,
            "Message": message.strip() or None,
            "Facility": facility,
            "Severity": severity,
            "PRI": pri,
        },
    }
