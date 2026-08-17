# ASLISIEM

A lightweight, self-hosted **SIEM (Security Information and Event
Management)** platform, built as a compact, QRadar-inspired clone: it
ingests security log data, normalizes it into searchable events, evaluates
correlation rules against it, and raises offenses when a rule's conditions
are met -- all behind a multi-tenant access model.

## What it is

ASLISIEM centralizes log data from multiple sources (firewalls, routers,
switches, web/DB/mail servers, endpoints) into one searchable event store,
then applies detection logic on top of it. It is built around the same
core workflow real SIEM products use:

**Log Activity** (raw/normalized events) → **Rules** (detection logic) →
**Offenses** (the alerts a rule produces) → **Dashboard** (the aggregate view).

## Why it's used

Security teams need a single place to collect logs from many different
devices, ask "did anything matching this attack pattern happen?", and get
notified when it does -- without hand-searching every device's own logs.
ASLISIEM exists to:

- **Demonstrate/practice SIEM concepts** (event normalization, correlation
  rules, offenses, MITRE ATT&CK mapping) in an environment that's realistic
  enough to be useful for learning or a demo, without the cost/complexity
  of running a commercial SIEM.
- **Support multi-tenant MSSP-style setups**, where one Full Admin oversees
  several isolated customer ("tenant") environments, and each tenant only
  ever sees their own data.
- **Generate realistic traffic to test against**, via a built-in log
  simulator that plays out a full kill-chain (recon → bruteforce → SQL
  injection → lateral movement) per tenant, so rules and dashboards have
  something real to react to even without a live network feeding them.

## What it does

- **Import**: ingests QRadar-style AQL CSV/JSON exports, previews the raw
  data, and persists every source record as an Event (append-only --
  nothing is overwritten or deleted on a new import). See "Import model"
  below for the full pipeline.
- **Log Activity**: lets you search/filter the full event store, including
  a QRadar-style "Add Filter" query builder.
- **Rules**: lets you define correlation rules (conditions, grouping,
  threshold count, time window, MITRE ATT&CK tagging) that are evaluated
  against persisted events; a match creates or updates an Offense.
- **Offenses**: the alert/incident view -- one entry per rule match,
  filterable and searchable the same way Log Activity is.
- **Assets & Log Sources**: tracks the devices/hosts events are seen
  coming from.
- **MITRE ATT&CK integration**: syncs technique/tactic data so rules and
  offenses can be tagged against the standard framework.
- **Simulator**: per-tenant background threads that generate a continuous,
  realistic stream of kill-chain log events (see
  `backend/simulator/scenario.py` / `topology.py`) so the rest of the
  system has live data to detect and correlate against.
- **Multi-tenancy & auth**: Full Admin vs. Tenant Admin roles, with
  tenant isolation enforced at the query layer (see `tenant_scope()` in
  `backend/services/auth_service.py` and the tenant-filtered event lookups
  in `backend/engine/rule_engine.py`) -- a tenant admin can never see or
  act on another tenant's data.

## Import model

CSV/JSON imports are append-only. Uploading a new file adds all source records to the persistent database; it does not replace or delete earlier events.

The import flow is:

1. Upload a QRadar AQL CSV/JSON export.
2. Preview the real source data.
3. Click **Import X Events**.
4. Every source record is stored as an Event.
5. The complete original row is preserved in `raw_data`.
6. Common fields are auto-detected when possible.
7. QRadar key=value fields are extracted into a searchable semantic view.
8. Rules are evaluated against all persisted events.

Manual field mapping is not required for import.

## Persistent data

The database and uploaded source files are stored outside the extracted application folder:

```text
~/.aslisiem_data/
├── aslisiem.db
└── uploads/
```

This allows the application code to be replaced without deleting imported events, rules, or offenses.

## Run on macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 backend/app.py
```

Open:

```text
http://127.0.0.1:5050
```

## Login credentials

On first startup the app seeds one Full Admin account (sees/manages every
tenant) plus one Tenant Admin account per demo tenant (sees/manages only
that tenant). These are demo-grade credentials, not meant for real
production use -- see also `docs/login_reference.html`.

| Username | Password | Role | Tenant |
|---|---|---|---|
| `admin` | `admin123` | Full Admin | (all tenants) |
| `tenant1-admin` | `tenant1123` | Tenant Admin | Tenant1 |
| `tenant2-admin` | `tenant2123` | Tenant Admin | Tenant2 |
| `tenant3-admin` | `tenant3123` | Tenant Admin | Tenant3 |
| `tenant4-admin` | `tenant4123` | Tenant Admin | Tenant4 |
| `tenant5-admin` | `tenant5123` | Tenant Admin | Tenant5 |
| `tenant6-admin` | `tenant6123` | Tenant Admin | Tenant6 |
| `tenant7-admin` | `tenant7123` | Tenant Admin | Tenant7 |
| `tenant8-admin` | `tenant8123` | Tenant Admin | Tenant8 |
| `tenant9-admin` | `tenant9123` | Tenant Admin | Tenant9 |
| `tenant10-admin` | `tenant10123` | Tenant Admin | Tenant10 |
