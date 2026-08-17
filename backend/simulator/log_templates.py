"""Pure string-rendering functions: given a Device and event parameters,
produce the exact raw text a real device would emit in its native format.
No DB/network/randomness here -- callers (scenario.py) supply all values."""


def render_cef(device, timestamp, signature_id, name, severity, extension, product="VirtualFirewall"):
    ts = timestamp.strftime("%b %d %H:%M:%S")
    ext_str = " ".join(f"{k}={v}" for k, v in extension.items())
    return (
        f"<134>{ts} {device.hostname} "
        f"CEF:0|ASLISIEM-Sim|{product}|1.0|{signature_id}|{name}|{severity}|{ext_str}"
    )


def render_syslog(device, timestamp, tag, pid, message):
    ts = timestamp.strftime("%b %d %H:%M:%S")
    pid_part = f"[{pid}]" if pid else ""
    return f"<134>{ts} {device.hostname} {tag}{pid_part}: {message}"


def render_access_log(device, timestamp, client_ip, method, path, status, size, user_agent="Mozilla/5.0"):
    ts = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{client_ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'


def render_winevent(device, timestamp, event_id, message, account_name, source_ip, logon_type=None):
    ts = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "Log Name: Security",
        f"Event ID: {event_id}",
        f"TimeCreated: {ts}",
        f"Computer: {device.hostname}",
        f"Account Name: {account_name}",
        f"Source Network Address: {source_ip}",
    ]
    if logon_type is not None:
        lines.append(f"Logon Type: {logon_type}")
    lines.append(f"Message: {message}")
    return "\n".join(lines)
