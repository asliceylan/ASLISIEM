import json
import re
from datetime import datetime, timezone

TARGET_FIELDS = [
    "event_id", "event_name", "source_ip", "source_port",
    "destination_ip", "destination_port", "username",
    "process_name", "timestamp",
]

# Header aliases are suggestions only. Nothing is invented.
ALIASES = {
    "event_id": ["eventid", "event_id", "event id", "qid", "qidname", "eventidcode", "event id code"],
    "event_name": ["eventname", "event_name", "event name", "event description", "category", "name"],
    "source_ip": ["sourceip", "source_ip", "source ip", "srcip", "src_ip", "sourceaddress", "source address"],
    "source_port": ["sourceport", "source_port", "source port", "srcport", "src_port"],
    "destination_ip": ["destinationip", "destination_ip", "destination ip", "dstip", "dst_ip", "destinationaddress"],
    "destination_port": ["destinationport", "destination_port", "destination port", "dstport", "dst_port"],
    "username": ["username", "user", "user_name", "user name", "identityusername", "account", "account name", "target username"],
    "process_name": ["processname", "process_name", "process name", "process", "image"],
    "timestamp": ["starttime", "start_time", "start time", "timestamp", "device time", "devicetime", "time", "eventtime", "event time", "datetime", "date"],
}

KEY_ALIASES = {
    "event_id": ["eventid", "event_id", "event id", "eventidcode", "event id code"],
    "event_name": ["eventname", "event_name", "event name", "category"],
    "source_ip": ["sourceip", "source_ip", "source ip", "srcip", "src_ip", "sourceaddress"],
    "username": ["username", "user", "user_name", "user name", "account", "account name", "target username"],
    "process_name": ["processname", "process_name", "process name", "process", "image"],
    "timestamp": ["timestamp", "starttime", "start time", "eventtime", "event time", "datetime"],
}

def _clean(name):
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())

def _value(record, field):
    if not field:
        return None
    value = record.get(field)
    if value is None:
        return None
    return str(value).strip()

def _looks_like_ip(value):
    return bool(value and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value.strip()))

def _extract_key_value(text, key):
    if not text or not key:
        return None
    # key=value, key: value, or quoted value. Stops at common delimiters.
    pattern = rf"(?i)(?:^|[\s,;|]){re.escape(key)}\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^,\s;|]+)"
    match = re.search(pattern, str(text))
    if not match:
        return None
    value = match.group(1).strip().strip("\"'")
    return value or None

def suggest_mapping(fields, records=None):
    """Suggest mappings for ordinary CSVs and the observed QRadar AQL export layout.

    The uploaded QRadar export has 84 physical columns whose first row contains
    non-semantic/repeated values. Therefore positional detection is used only
    when the observed data matches the known QRadar shape; otherwise aliases
    remain the fallback.
    """
    records = records or []
    mapping = {target: {"source_field": None, "mode": "direct", "key": ""}
               for target in TARGET_FIELDS}

    # Known structure of the user's QRadar AQL export (0-based physical columns).
    # These are suggestions only and can still be changed in the UI.
    if len(fields) >= 84 and records:
        sample = records[0]
        def val(i):
            return _value(sample, f"column_{i:03d}")
        # Event ID: dedicated numeric field at column 56.
        if val(56) and re.fullmatch(r"\d+", val(56)):
            mapping["event_id"] = {"source_field": "column_056", "mode": "direct", "key": ""}
        # Event name: Process Creation Success in column 22.
        if val(22) and val(22) not in {"N/A", "null"}:
            mapping["event_name"] = {"source_field": "column_022", "mode": "direct", "key": ""}
        # Source IP: the observed QRadar export has it in column 50.
        if _looks_like_ip(val(50)):
            mapping["source_ip"] = {"source_field": "column_050", "mode": "direct", "key": ""}
        # Process name is embedded in the structured payload at column 6.
        if _extract_key_value(val(6), "Process Name"):
            mapping["process_name"] = {"source_field": "column_006", "mode": "key_value", "key": "Process Name"}
        # The human-readable event time is in column 67.
        if parse_timestamp(val(67)):
            mapping["timestamp"] = {"source_field": "column_067", "mode": "direct", "key": ""}
        return mapping

    cleaned = {f: _clean(f) for f in fields}
    for target, aliases in ALIASES.items():
        alias_clean = {_clean(a) for a in aliases}
        match = next((original for original, c in cleaned.items() if c in alias_clean), None)
        mapping[target] = {"source_field": match, "mode": "direct", "key": ""}
    return mapping


def suggest_extraction(fields, records=None):
    """Suggest key=value extraction only when the key is actually observed."""
    records = records or []
    suggestions = {}
    for target, keys in KEY_ALIASES.items():
        found = None
        for field in fields:
            for row in records[:20]:
                text = _value(row, field)
                if not text:
                    continue
                for key in keys:
                    if _extract_key_value(text, key) is not None:
                        found = {"source_field": field, "mode": "key_value", "key": key}
                        break
                if found:
                    break
            if found:
                break
        suggestions[target] = found
    return suggestions

def parse_timestamp(value):
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            v = float(value)
            if v > 1e12:
                v /= 1000.0
            return datetime.utcfromtimestamp(v)
        except Exception:
            return None
    value = str(value).strip()
    # QRadar exports in the user's Turkish locale can contain month names such
    # as "22 Tem 2026 15:57:53". Normalize Turkish month names before parsing.
    tr_months = {
        "Oca": "Jan", "Şub": "Feb", "Mar": "Mar", "Nis": "Apr",
        "May": "May", "Haz": "Jun", "Tem": "Jul", "Ağu": "Aug",
        "Eyl": "Sep", "Eki": "Oct", "Kas": "Nov", "Ara": "Dec",
    }
    parts = value.split()
    if len(parts) >= 4 and parts[1] in tr_months:
        parts[1] = tr_months[parts[1]]
        value = " ".join(parts)
    fmts = [
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S",
        "%b %d, %Y, %H:%M:%S", "%Y-%m-%d",
        "%d %b %Y %H:%M:%S", "%d %B %Y %H:%M:%S",
        "%d %b %Y %H:%M:%S", "%d %B %Y %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",  # Apache/Nginx combined log format
    ]
    for fmt in fmts:
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is not None:
                # Keep every stored timestamp naive-UTC so comparisons/sorts
                # elsewhere (e.g. time_window_engine) never mix naive and
                # timezone-aware datetimes.
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except Exception:
            pass
    try:
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        return datetime.utcfromtimestamp(v)
    except Exception:
        return None

def resolve_mapping_value(record, spec):
    if not spec:
        return None
    if isinstance(spec, str):
        source_field, mode, key = spec, "direct", ""
    else:
        source_field = spec.get("source_field") or spec.get("field")
        mode = spec.get("mode", "direct")
        key = spec.get("key", "")
    raw = _value(record, source_field)
    if raw is None:
        return None
    if mode == "key_value":
        return _extract_key_value(raw, key)
    return raw

def _extract_structured_fields(text):
    """Extract common key=value fields from QRadar structured payloads."""
    if not text:
        return {}
    text = str(text)
    result = {}
    # Handles comma-separated structured payloads such as:
    # {Process Path=C:\\Windows\\System32\\x.exe, Event ID=4688, ...}
    for match in re.finditer(r"(?:^|[,{]\s*|,\s+)([A-Za-z][A-Za-z0-9 _()/.-]*?)\s*=\s*(.*?)(?=,\s+[A-Za-z][A-Za-z0-9 _()/.-]*?\s*=|}\s*$|$)", text):
        key = match.group(1).strip()
        value = match.group(2).strip().strip("{} ")
        if key and value:
            result[key] = value
    # Handles Windows event key=value data separated by tabs.
    for part in re.split(r"\t+", text):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            result[key] = value
    return result


def build_derived_fields(record):
    """Create a searchable semantic view while preserving the original row."""
    derived = {}
    for field in ("column_006", "column_021"):
        derived.update(_extract_structured_fields(record.get(field)))
    # Common aliases used by QRadar rules and Windows event data.
    aliases = {
        "EventID": "Event ID",
        "EventIDCode": "Event ID Code",
        "Computer": "Computer",
        "Source": "Source",
        "ProcessName": "Process Name",
        "Process Path": "Process Path",
        "Command": "Command",
        "Process Command Line": "Process Command Line",
        "New Process Name": "New Process Name",
        "Account Name": "Account Name",
        "User": "User",
        "Domain": "Domain",
        "Message": "Message",
    }
    for source_key, target_key in aliases.items():
        if source_key in derived and target_key not in derived:
            derived[target_key] = derived[source_key]
    return derived


def normalize_record(record, mapping=None):
    """Normalize an imported row without requiring manual field mapping.

    The complete source row is always preserved. If an explicit mapping is
    supplied it is honored; otherwise the row is normalized using the same
    reliable QRadar/alias suggestions used by the preview.
    """
    mapping = mapping or {}
    normalized = {}
    for target in TARGET_FIELDS:
        value = resolve_mapping_value(record, mapping.get(target)) if mapping.get(target) else None
        normalized[target] = parse_timestamp(value) if target == "timestamp" else (str(value) if value is not None else None)

    # Preserve the full physical row, original headers, and a header-based view.
    # This makes every imported value available to future rule conditions.
    raw_record = {k: v for k, v in record.items() if not k.startswith("__")}
    raw_record["__source_headers__"] = record.get("__source_headers__", [])
    raw_record["__source_by_header__"] = record.get("__source_by_header__", {})
    raw_record["__derived_fields__"] = build_derived_fields(record)
    normalized["raw_data"] = json.dumps(raw_record, ensure_ascii=False, default=str)
    return normalized
