from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Device:
    name: str
    ip: str
    hostname: str
    device_type: str
    log_format: str  # which native format this device type renders -- NOT used
                      # for classification (format_detector re-detects blindly
                      # from the raw text), only for choosing a template to render.
    port: Optional[int] = None


def build_devices(tenant=None):
    """Builds a fresh, independent set of Devices for one tenant's simulated
    network. Each tenant gets its own IP block (derived from tenant.id) and
    hostname prefix so its topology visibly looks like a separate customer
    network, not a shared one: internal hosts move to 10.{10+id}.x.x, and
    the DMZ block (198.51.100.0/24, RFC 5737 TEST-NET-2) is split into
    4-address slices per tenant. tenant=None (or id=0) reproduces the
    original single-tenant addresses exactly, for backward compatibility.

    Returns a fresh dict every call -- callers must never share/mutate one
    globally, since multiple tenants' SimulatorThreads run concurrently
    (see backend/simulator/scenario.py, which takes this dict as a
    parameter instead of reading a module-level global for that reason)."""
    tenant_id = getattr(tenant, "id", None) or 0
    prefix = f"{tenant.slug}-" if tenant is not None else ""
    internal_octet = 10 + tenant_id
    # Block width 20 keeps each tenant's 4 DMZ addresses (spread across
    # offsets 0/1/5/10, matching the original single-tenant layout exactly
    # at tenant_id=0) from ever colliding with the next tenant's block.
    dmz_base = 10 + (tenant_id * 20) % 220

    firewall = Device("firewall", f"10.{internal_octet}.0.254", f"{prefix}fw-edge-01", "firewall", "cef")
    router = Device("router", f"10.{internal_octet}.0.1", f"{prefix}edge-rtr-01", "router", "syslog")
    switch = Device("switch", f"10.{internal_octet}.0.2", f"{prefix}core-sw-01", "switch", "syslog")
    dmz_web = Device("dmz_web", f"198.51.100.{dmz_base}", f"{prefix}dmz-web-01", "dmz_web", "access_log", port=443)
    waf = Device("waf", f"198.51.100.{dmz_base + 1}", f"{prefix}waf-edge-01", "waf", "cef")
    # Real Postgres/MySQL deployments commonly ship auth/query logs via
    # syslog (log_destination=syslog / log-syslog) -- no new parser needed.
    dmz_db = Device("dmz_db", f"198.51.100.{dmz_base + 5}", f"{prefix}dmz-db-01", "dmz_db", "syslog")
    dmz_mail = Device("dmz_mail", f"198.51.100.{dmz_base + 10}", f"{prefix}dmz-mail-01", "dmz_mail", "winevent")
    internal_host = Device("internal_host", f"10.{internal_octet}.5.50", f"{prefix}corp-fs-01", "internal_host", "winevent")

    devices = [firewall, router, switch, dmz_web, waf, dmz_mail, dmz_db, internal_host]
    return {d.name: d for d in devices}


# Module-level default -- the original single-tenant topology, unchanged.
# Existing code/tests that reference topology.DEVICES directly keep working;
# multi-tenant callers build their own via build_devices(tenant) instead.
DEVICES = build_devices(None)

# RFC 5737 TEST-NET-3 -- reserved for documentation, safe/realistic-looking
# "external attacker" address space.
_ATTACKER_NET_PREFIX = "203.0.113."


def random_attacker_ip(rng):
    return f"{_ATTACKER_NET_PREFIX}{rng.randint(2, 254)}"
