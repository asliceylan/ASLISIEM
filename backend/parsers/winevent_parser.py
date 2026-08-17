import re

from backend.parsers.normalizer import parse_timestamp

# A simplified textual approximation of a Windows Security event -- a small
# "Key: Value" block, NOT real binary/XML EVTX (explicit scope simplification).
_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _/]*):\s*(.*)$")


def parse_winevent_block(text, device=None):
    fields = {}
    for line in text.strip().splitlines():
        match = _LINE_RE.match(line.strip())
        if match:
            fields[match.group(1).strip()] = match.group(2).strip()

    if "Event ID" not in fields or "TimeCreated" not in fields:
        raise ValueError("Not a winevent block")

    event_id = fields.get("Event ID")
    message = fields.get("Message")

    return {
        "event_id": event_id,
        "event_name": message or f"Windows Event {event_id}",
        "source_ip": fields.get("Source Network Address"),
        "source_port": None,
        "destination_ip": device.ip if device else None,
        "destination_port": None,
        "username": fields.get("Account Name"),
        "process_name": None,
        "timestamp": parse_timestamp(fields.get("TimeCreated")),
        "derived_fields": dict(fields),
    }
