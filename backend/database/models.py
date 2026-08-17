import json
import re
from datetime import datetime
from backend.database.db import db


def now():
    return datetime.utcnow()


class Tenant(db.Model):
    __tablename__ = "tenants"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(50), nullable=False, unique=True)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # "full_admin" | "tenant_admin"
    # NULL for full_admin (sees every tenant); always set for tenant_admin.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=now)

    tenant = db.relationship("Tenant")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant.name if self.tenant else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Import(db.Model):
    __tablename__ = "imports"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    event_count = db.Column(db.Integer, default=0)
    imported_at = db.Column(db.DateTime, default=now)
    status = db.Column(db.String(20), default="IMPORTED")

    events = db.relationship("Event", backref="import_ref", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "event_count": self.event_count,
            "imported_at": self.imported_at.isoformat() if self.imported_at else None,
            "status": self.status,
        }


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)
    import_id = db.Column(db.Integer, db.ForeignKey("imports.id"))
    event_id = db.Column(db.String(64))
    event_name = db.Column(db.String(255))
    source_ip = db.Column(db.String(64))
    source_port = db.Column(db.String(16))
    destination_ip = db.Column(db.String(64))
    destination_port = db.Column(db.String(16))
    username = db.Column(db.String(128))
    process_name = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime)
    raw_data = db.Column(db.Text)  # JSON string of the original imported row
    created_at = db.Column(db.DateTime, default=now)
    # Provenance: "import" (CSV/JSON upload, default) or "simulator" (live log
    # generator). server_default (not just default=) so the literal DEFAULT
    # also lands in CREATE TABLE DDL, matching what schema_guard's ALTER TABLE
    # produces for pre-existing databases.
    source = db.Column(db.String(20), nullable=False, default="import", server_default=db.text("'import'"))
    device_type = db.Column(db.String(50))  # e.g. firewall/switch/router/dmz_web/dmz_mail/dmz_db/internal_host
    log_format = db.Column(db.String(20))  # e.g. syslog/cef/access_log/winevent
    # Nullable at the DB level (SQLite ALTER TABLE can't add NOT NULL+FK to an
    # existing table -- see schema_guard.ensure_event_columns). The
    # application layer guarantees every newly-written row always sets this;
    # pre-migration rows are backfilled to the "default" tenant.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"))

    def get_raw(self):
        try:
            return json.loads(self.raw_data) if self.raw_data else {}
        except Exception:
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "import_id": self.import_id,
            "event_id": self.event_id,
            "event_name": self.event_name,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "username": self.username,
            "process_name": self.process_name,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_data": self.get_raw(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "source": self.source,
            "device_type": self.device_type,
            "log_format": self.log_format,
            "tenant_id": self.tenant_id,
        }


class Rule(db.Model):
    __tablename__ = "rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    severity = db.Column(db.String(20), default="Medium")  # Low/Medium/High/Critical
    created_at = db.Column(db.DateTime, default=now)
    updated_at = db.Column(db.DateTime, default=now, onupdate=now)

    # Structured rule configuration, stored as JSON text.
    # conditions_json shape:
    # {"logic": "OR", "groups": [{"logic":"AND","conditions":[{"field":"event_id","operator":"equals","value":"4625"}]}]}
    conditions_json = db.Column(db.Text, default="{}")
    # grouping_json: list of field names used as the correlation key, e.g. ["source_ip","username"]
    grouping_json = db.Column(db.Text, default="[]")
    threshold_count = db.Column(db.Integer, default=1)
    # Optional: when set, threshold_count is compared against the count of
    # DISTINCT values of this field within the window, not the raw event
    # count (e.g. "6 distinct destination_port values" instead of "6
    # events"). NULL preserves the original raw-count behavior exactly.
    distinct_field = db.Column(db.String(120))
    time_window_value = db.Column(db.Integer, default=0)
    time_window_unit = db.Column(db.String(10), default="minutes")  # seconds/minutes/hours
    # mitre_json: list of {tactic_id,tactic_name,technique_id,technique_name,subtechnique_id,subtechnique_name}
    mitre_json = db.Column(db.Text, default="[]")
    response = db.Column(db.String(50), default="CREATE_OFFENSE")
    # See Event.tenant_id docstring -- same nullable-at-DB-level, always-set-
    # at-application-level contract. A rule only ever evaluates events that
    # share its tenant_id (see rule_engine.run_rule).
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"))
    # NULL for a manually-created rule. Set to the pattern_type (e.g.
    # "brute_force") when this rule was created automatically by
    # suggestion_service.auto_apply_new_rule_suggestions -- doubles as both
    # the "is this auto-generated" marker (frontend badge) and the dedup
    # key that stops the same pattern from ever spawning a second
    # automatic rule for the same tenant (see suggestion_service.py).
    auto_pattern_type = db.Column(db.String(50))

    match_groups = db.relationship("RuleMatchGroup", backref="rule", cascade="all, delete-orphan")
    offenses = db.relationship("Offense", backref="rule", cascade="all, delete-orphan")

    def conditions(self):
        try:
            return json.loads(self.conditions_json) if self.conditions_json else {}
        except Exception:
            return {}

    def grouping(self):
        try:
            return json.loads(self.grouping_json) if self.grouping_json else []
        except Exception:
            return []

    def mitre(self):
        try:
            return json.loads(self.mitre_json) if self.mitre_json else []
        except Exception:
            return []

    def time_window_seconds(self):
        unit_map = {"seconds": 1, "minutes": 60, "hours": 3600}
        return (self.time_window_value or 0) * unit_map.get(self.time_window_unit, 60)

    def to_dict(self, include_stats=False):
        d = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "severity": self.severity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "conditions": self.conditions(),
            "grouping": self.grouping(),
            "threshold_count": self.threshold_count,
            "distinct_field": self.distinct_field,
            "time_window_value": self.time_window_value,
            "time_window_unit": self.time_window_unit,
            "mitre": self.mitre(),
            "response": self.response,
            "tenant_id": self.tenant_id,
            "auto_pattern_type": self.auto_pattern_type,
        }
        if include_stats:
            d["match_count"] = len(self.offenses)
        return d


class RuleMatchGroup(db.Model):
    """Tracks a correlation-key group that has already produced an offense,
    used to avoid creating unlimited duplicate offenses for the same activity."""
    __tablename__ = "rule_match_groups"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id"))
    correlation_key = db.Column(db.String(512))
    offense_id = db.Column(db.Integer, db.ForeignKey("offenses.id"))
    last_event_time = db.Column(db.DateTime)

    __table_args__ = (db.UniqueConstraint("rule_id", "correlation_key", name="uq_rule_corrkey"),)


class RuleMatchWindow(db.Model):
    """A durable fingerprint of one matched event window.

    This prevents re-evaluating the same historical events from creating
    duplicate offenses, while allowing a later import with new events to
    create a new offense for the same rule/correlation key.
    """
    __tablename__ = "rule_match_windows"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id"), nullable=False)
    correlation_key = db.Column(db.String(512), nullable=False)
    event_fingerprint = db.Column(db.String(1024), nullable=False)
    offense_id = db.Column(db.Integer, db.ForeignKey("offenses.id"), nullable=False)
    first_event_time = db.Column(db.DateTime)
    last_event_time = db.Column(db.DateTime)

    __table_args__ = (db.UniqueConstraint("rule_id", "event_fingerprint", name="uq_rule_window_fingerprint"),)


class Offense(db.Model):
    __tablename__ = "offenses"

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id"))
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(20), default="OPEN")  # OPEN/CLOSED
    source_ip = db.Column(db.String(64))
    username = db.Column(db.String(128))
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    event_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=now)
    # Denormalized copy of rule.tenant_id at creation time -- avoids a join
    # for every tenant-scoped offense query, matching the no-join philosophy
    # already used elsewhere (see asset_service). See Event.tenant_id
    # docstring for the same nullable-at-DB-level contract.
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id"))

    linked_events = db.relationship("OffenseEvent", backref="offense", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule.name if self.rule else None,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "source_ip": self.source_ip,
            "username": self.username,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "event_count": self.event_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "mitre": self.rule.mitre() if self.rule else [],
            "tenant_id": self.tenant_id,
        }


class OffenseEvent(db.Model):
    __tablename__ = "offense_events"

    id = db.Column(db.Integer, primary_key=True)
    offense_id = db.Column(db.Integer, db.ForeignKey("offenses.id"))
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"))

    event = db.relationship("Event")

    __table_args__ = (db.UniqueConstraint("offense_id", "event_id", name="uq_offense_event"),)


class MitreTactic(db.Model):
    """A tactic from the official MITRE ATT&CK STIX catalog, synced from
    attack-stix-data. One row per (domain, tactic_id)."""
    __tablename__ = "mitre_tactics"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(20), nullable=False)  # enterprise/mobile/ics
    stix_id = db.Column(db.String(80), nullable=False)
    tactic_id = db.Column(db.String(16), nullable=False)  # e.g. TA0006
    name = db.Column(db.String(255), nullable=False)
    shortname = db.Column(db.String(100), nullable=False)  # matches kill_chain_phases.phase_name
    created_at = db.Column(db.DateTime, default=now)
    updated_at = db.Column(db.DateTime, default=now, onupdate=now)

    __table_args__ = (
        db.UniqueConstraint("domain", "stix_id", name="uq_tactic_domain_stixid"),
        db.UniqueConstraint("domain", "tactic_id", name="uq_tactic_domain_tacticid"),
    )

    def to_dict(self):
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.name,
            "domain": self.domain,
        }


_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")


def _strip_citations(text):
    """Removes MITRE's inline "(Citation: ...)" reference markers from a raw
    STIX description and collapses the whitespace left behind, so the result
    reads as plain paragraphs. Not a full markdown cleanup -- just the one
    well-known, consistently-formatted pattern MITRE uses."""
    if not text:
        return None
    cleaned = _CITATION_RE.sub("", text)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = "\n".join(line.strip() for line in cleaned.split("\n"))
    return cleaned.strip()


class MitreTechnique(db.Model):
    """A technique or sub-technique from the official MITRE ATT&CK STIX
    catalog, synced from attack-stix-data. One row per (domain, technique_id).
    Sub-techniques point back to their parent technique via parent_id."""
    __tablename__ = "mitre_techniques"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(20), nullable=False)
    stix_id = db.Column(db.String(80), nullable=False)
    technique_id = db.Column(db.String(16), nullable=False)  # e.g. T1110 or T1110.001
    name = db.Column(db.String(255), nullable=False)
    is_subtechnique = db.Column(db.Boolean, default=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("mitre_techniques.id"), nullable=True)
    # Raw STIX description, stored unmodified -- citation cleanup happens at
    # to_dict() presentation time (see _strip_citations), not here, so the
    # cleanup logic can change without requiring a re-sync.
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=now)
    updated_at = db.Column(db.DateTime, default=now, onupdate=now)

    parent = db.relationship("MitreTechnique", remote_side=[id])
    tactic_links = db.relationship(
        "MitreTechniqueTactic", backref="technique", cascade="all, delete-orphan"
    )

    __table_args__ = (
        db.UniqueConstraint("domain", "stix_id", name="uq_technique_domain_stixid"),
        db.UniqueConstraint("domain", "technique_id", name="uq_technique_domain_techid"),
    )

    def to_dict(self, include_tactics=False, include_description=False):
        d = {
            "domain": self.domain,
            "technique_id": self.technique_id,
            "technique_name": self.name,
            "is_subtechnique": self.is_subtechnique,
            "parent_technique_id": self.parent.technique_id if self.parent else None,
        }
        if include_tactics:
            d["tactics"] = [
                {"tactic_id": link.tactic.tactic_id, "tactic_name": link.tactic.name}
                for link in self.tactic_links
            ]
        if include_description:
            d["description"] = _strip_citations(self.description)
        return d


class MitreTechniqueTactic(db.Model):
    """Many-to-many link: one technique can belong to several tactics."""
    __tablename__ = "mitre_technique_tactics"

    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.Integer, db.ForeignKey("mitre_techniques.id"), nullable=False)
    tactic_id = db.Column(db.Integer, db.ForeignKey("mitre_tactics.id"), nullable=False)

    tactic = db.relationship("MitreTactic")

    __table_args__ = (db.UniqueConstraint("technique_id", "tactic_id", name="uq_technique_tactic"),)


class MitreSyncStatus(db.Model):
    """Tracks the outcome of the last catalog sync attempt per ATT&CK domain.
    Rows are created lazily on first sync attempt, never pre-seeded, so that
    db.create_all() continues to only create schema and never data."""
    __tablename__ = "mitre_sync_status"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(20), nullable=False, unique=True)
    status = db.Column(db.String(20), default="NEVER_RUN")  # NEVER_RUN/IN_PROGRESS/SUCCESS/FAILED
    source_url = db.Column(db.String(512))
    attack_version = db.Column(db.String(20))
    tactic_count = db.Column(db.Integer, default=0)
    technique_count = db.Column(db.Integer, default=0)
    last_attempt_at = db.Column(db.DateTime)
    last_success_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

    def to_dict(self):
        return {
            "domain": self.domain,
            "status": self.status,
            "source_url": self.source_url,
            "attack_version": self.attack_version,
            "tactic_count": self.tactic_count,
            "technique_count": self.technique_count,
            "last_attempt_at": self.last_attempt_at.isoformat() if self.last_attempt_at else None,
            "last_success_at": self.last_success_at.isoformat() if self.last_success_at else None,
            "error_message": self.error_message,
        }
