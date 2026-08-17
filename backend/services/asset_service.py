import ipaddress
from collections import Counter

from backend.database.models import Event, Offense

# RFC1918 private ranges (the general "internal network" convention, so this
# also works for real imported enterprise data) plus 198.51.100.0/24
# (TEST-NET-2), which THIS app's simulator topology.py uses for its DMZ
# servers (dmz_web/waf/dmz_mail/dmz_db). "internal" here means
# "infrastructure we own/manage" (DMZ included), not strictly RFC1918.
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.51.100.0/24"),
]

# Formats whose parser sets destination_ip to the reporting device's own IP
# (see winevent_parser.py/access_log_parser.py/syslog_parser.py). CEF is
# deliberately excluded: neither its source_ip nor destination_ip is the
# reporting firewall/WAF itself -- it's a third-party observer of traffic
# between two OTHER hosts, so device_type must not be assigned from it.
SELF_REPORTING_FORMATS = {"winevent", "access_log", "syslog"}


def classify_ip_scope(ip_str):
    """"internal" (known owned/managed ranges), "external" (everything
    else -- the standard "not a private range, so it's on the public
    internet" default), or "unknown" (unparseable/malformed input)."""
    if not ip_str:
        return "unknown"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    return "internal" if any(ip in net for net in INTERNAL_NETWORKS) else "external"


def _touch(assets, ip, ts, log_format=None, device_type=None):
    if not ip:
        return
    asset = assets.setdefault(ip, {
        "ip": ip,
        "scope": classify_ip_scope(ip),
        "device_type": None,
        "log_formats": set(),
        "first_seen": ts,
        "last_seen": ts,
        "log_count": 0,
    })
    asset["log_count"] += 1
    if ts:
        if not asset["first_seen"] or ts < asset["first_seen"]:
            asset["first_seen"] = ts
        if not asset["last_seen"] or ts > asset["last_seen"]:
            asset["last_seen"] = ts
    if device_type:
        asset["device_type"] = device_type
    if log_format:
        asset["log_formats"].add(log_format)


def list_assets(tenant_id=None):
    """Computed live from Event/Offense on every call -- no persisted Asset
    table, consistent with this app's dashboard/suggestion_engine
    architecture (see backend/routes/dashboard_routes.py). tenant_id=None
    means unscoped (every tenant), matching the tenant_scope() convention
    used throughout the route layer."""
    events_q = Event.query
    offenses_q = Offense.query
    if tenant_id is not None:
        events_q = events_q.filter_by(tenant_id=tenant_id)
        offenses_q = offenses_q.filter_by(tenant_id=tenant_id)

    assets = {}
    for event in events_q.all():
        ts = event.timestamp or event.created_at
        _touch(assets, event.source_ip, ts, log_format=event.log_format)
        self_reporting = event.log_format in SELF_REPORTING_FORMATS
        _touch(
            assets, event.destination_ip, ts, log_format=event.log_format,
            device_type=event.device_type if self_reporting else None,
        )

    offense_counts = Counter(o.source_ip for o in offenses_q.all() if o.source_ip)
    result = []
    for ip, asset in assets.items():
        asset["offense_count"] = offense_counts.get(ip, 0)
        asset["first_seen"] = asset["first_seen"].isoformat() if asset["first_seen"] else None
        asset["last_seen"] = asset["last_seen"].isoformat() if asset["last_seen"] else None
        asset["log_formats"] = ", ".join(sorted(asset["log_formats"]))
        result.append(asset)

    return sorted(result, key=lambda a: a["last_seen"] or "", reverse=True)
