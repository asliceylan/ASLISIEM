import re

from backend.parsers.normalizer import parse_timestamp

# Apache/Nginx Combined Log Format:
# IP - authuser [DD/Mon/YYYY:HH:MM:SS +0000] "METHOD path HTTP/1.1" status size "referrer" "user-agent"
_ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<authuser>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<useragent>[^"]*)")?'
)


def parse_access_log_line(line, device=None):
    match = _ACCESS_LOG_RE.match(line.strip())
    if not match:
        raise ValueError("Not an access-log line")
    g = match.groupdict()

    timestamp = parse_timestamp(g["ts"])
    username = None if g["authuser"] in (None, "-") else g["authuser"]

    return {
        "event_id": g["status"],
        "event_name": f'{g["method"]} {g["path"]} {g["status"]}',
        "source_ip": g["ip"],
        "source_port": None,
        "destination_ip": device.ip if device else None,
        "destination_port": str(getattr(device, "port", None) or 443),
        "username": username,
        "process_name": None,
        "timestamp": timestamp,
        "derived_fields": {
            "Method": g["method"],
            "Path": g["path"],
            "Protocol": g["protocol"],
            "Status": g["status"],
            "BytesSent": g["size"],
            "Referrer": g.get("referrer"),
            "UserAgent": g.get("useragent"),
        },
    }
