import re

from backend.parsers.syslog_parser import strip_syslog_header
from backend.parsers.normalizer import parse_timestamp

# Standard CEF extension key=value idiom: a value runs until the next
# " word=" boundary (or end of string), so values may contain spaces.
_EXT_RE = re.compile(r"(\w+)=((?:(?!\s\w+=).)*)")


def parse_cef_line(line, device=None):
    """Parses a CEF line, which in real deployments (Check Point, Palo Alto,
    Fortinet, ...) is almost always wrapped in a syslog envelope. Peels that
    envelope first, then parses CEF:0|Vendor|Product|Version|SigID|Name|Sev|ext.
    Raises ValueError if the (unwrapped) body isn't actually CEF."""
    text = line.strip()
    pri, header_ts, hostname, remainder = strip_syslog_header(text)
    body = remainder if pri is not None else text

    if not body.startswith("CEF:0|"):
        raise ValueError("Not a CEF line")

    parts = body.split("|", 7)
    if len(parts) < 8:
        raise ValueError("Malformed CEF line: expected 8 pipe-delimited fields")
    _, vendor, product, version, signature_id, name, severity, extension = parts

    ext = {key: value.strip() for key, value in _EXT_RE.findall(extension)}

    timestamp = header_ts
    if timestamp is None and ext.get("rt"):
        timestamp = parse_timestamp(ext["rt"])

    return {
        "event_id": signature_id or None,
        "event_name": name or None,
        "source_ip": ext.get("src"),
        "source_port": ext.get("spt"),
        "destination_ip": ext.get("dst") or (device.ip if device else None),
        "destination_port": ext.get("dpt"),
        "username": ext.get("suser") or ext.get("duser"),
        "process_name": None,
        "timestamp": timestamp,
        "derived_fields": {
            "Vendor": vendor,
            "Product": product,
            "Version": version,
            "SignatureID": signature_id,
            "Name": name,
            "Severity": severity,
            "Hostname": hostname,
            **ext,
        },
    }
