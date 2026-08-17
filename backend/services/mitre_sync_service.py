from datetime import datetime

import requests

from backend.config import Config
from backend.database.db import db
from backend.database.models import MitreTactic, MitreTechnique, MitreTechniqueTactic, MitreSyncStatus


class MitreSyncError(Exception):
    """Raised when fetching or parsing a domain's STIX bundle fails."""


def _now():
    return datetime.utcnow()


def fetch_stix_bundle(domain):
    """Downloads the pinned-version STIX bundle for one ATT&CK domain.
    Pure network I/O -- no DB access, no parsing beyond JSON decoding."""
    url = Config.MITRE_DOMAIN_URLS[domain]
    try:
        resp = requests.get(url, timeout=Config.MITRE_FETCH_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise MitreSyncError(f"Failed to fetch {domain} STIX bundle from {url}: {e}") from e
    try:
        return resp.json()
    except ValueError as e:
        raise MitreSyncError(f"Failed to parse {domain} STIX bundle as JSON: {e}") from e


def _mitre_external_id(stix_obj):
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def parse_stix_bundle(domain, bundle, kill_chain_name):
    """Pure function: extracts tactics, techniques, technique-tactic links,
    and sub-technique parent relationships from a raw STIX bundle dict.
    No DB or network access, so this is fully unit-testable in isolation.

    Returns a dict:
      {
        "tactics": [{"stix_id","tactic_id","name","shortname"}, ...],
        "techniques": [{"stix_id","technique_id","name","is_subtechnique","shortnames":[...]}, ...],
        "subtechnique_parents": {child_stix_id: parent_stix_id, ...},
        "warnings": [str, ...],
      }
    """
    objects = bundle.get("objects", [])
    warnings = []

    tactics = []
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked"):
            continue
        tactic_id = _mitre_external_id(obj)
        shortname = obj.get("x_mitre_shortname")
        if not tactic_id or not shortname:
            continue
        tactics.append({
            "stix_id": obj["id"],
            "tactic_id": tactic_id,
            "name": obj.get("name", ""),
            "shortname": shortname,
        })

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = _mitre_external_id(obj)
        if not technique_id:
            continue
        shortnames = [
            kc.get("phase_name")
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == kill_chain_name and kc.get("phase_name")
        ]
        techniques.append({
            "stix_id": obj["id"],
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "shortnames": shortnames,
            # Raw STIX description, stored unmodified -- citation cleanup
            # happens at MitreTechnique.to_dict() presentation time.
            "description": obj.get("description"),
        })

    subtechnique_parents = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("revoked"):
            continue
        if obj.get("relationship_type") != "subtechnique-of":
            continue
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        if source_ref and target_ref:
            subtechnique_parents[source_ref] = target_ref

    if techniques and not any(t["shortnames"] for t in techniques):
        warnings.append(
            f"{domain}: {len(techniques)} techniques parsed but none produced a tactic link -- "
            f"kill_chain_name '{kill_chain_name}' may be wrong for this domain."
        )

    return {
        "tactics": tactics,
        "techniques": techniques,
        "subtechnique_parents": subtechnique_parents,
        "warnings": warnings,
    }


def _replace_domain_catalog(domain, parsed):
    """Deletes this domain's existing catalog rows and inserts the newly
    parsed ones inside the caller's transaction. Raises on any integrity
    problem so the caller can roll back and leave prior data untouched."""
    existing_technique_ids = [
        tid for (tid,) in db.session.query(MitreTechnique.id).filter_by(domain=domain).all()
    ]
    if existing_technique_ids:
        MitreTechniqueTactic.query.filter(
            MitreTechniqueTactic.technique_id.in_(existing_technique_ids)
        ).delete(synchronize_session=False)
    MitreTechnique.query.filter_by(domain=domain).delete(synchronize_session=False)
    MitreTactic.query.filter_by(domain=domain).delete(synchronize_session=False)
    db.session.flush()

    shortname_to_pk = {}
    for t in parsed["tactics"]:
        row = MitreTactic(
            domain=domain,
            stix_id=t["stix_id"],
            tactic_id=t["tactic_id"],
            name=t["name"],
            shortname=t["shortname"],
        )
        db.session.add(row)
        db.session.flush()
        shortname_to_pk[t["shortname"]] = row.id

    stix_id_to_pk = {}
    for tech in parsed["techniques"]:
        row = MitreTechnique(
            domain=domain,
            stix_id=tech["stix_id"],
            technique_id=tech["technique_id"],
            name=tech["name"],
            is_subtechnique=tech["is_subtechnique"],
            description=tech.get("description"),
        )
        db.session.add(row)
        db.session.flush()
        stix_id_to_pk[tech["stix_id"]] = row

    for tech in parsed["techniques"]:
        parent_stix_id = parsed["subtechnique_parents"].get(tech["stix_id"])
        if parent_stix_id and parent_stix_id in stix_id_to_pk:
            stix_id_to_pk[tech["stix_id"]].parent_id = stix_id_to_pk[parent_stix_id].id
        for shortname in tech["shortnames"]:
            tactic_pk = shortname_to_pk.get(shortname)
            if tactic_pk is None:
                continue
            db.session.add(MitreTechniqueTactic(
                technique_id=stix_id_to_pk[tech["stix_id"]].id,
                tactic_id=tactic_pk,
            ))


def _get_or_create_status(domain):
    status = MitreSyncStatus.query.filter_by(domain=domain).first()
    if not status:
        status = MitreSyncStatus(domain=domain, status="NEVER_RUN")
        db.session.add(status)
        db.session.flush()
    return status


def sync_domain(domain):
    """Fetches, parses, and replaces the catalog for a single ATT&CK domain.
    A failure at any stage (network, parse, or DB write) leaves the
    previously-synced catalog for this domain completely untouched -- only
    the MitreSyncStatus row changes to FAILED."""
    status = _get_or_create_status(domain)
    status.status = "IN_PROGRESS"
    status.last_attempt_at = _now()
    db.session.commit()

    try:
        bundle = fetch_stix_bundle(domain)
        kill_chain_name = Config.MITRE_KILL_CHAIN_NAME_BY_DOMAIN[domain]
        parsed = parse_stix_bundle(domain, bundle, kill_chain_name)
    except Exception as e:
        status.status = "FAILED"
        status.error_message = str(e)
        db.session.commit()
        return {"domain": domain, "ok": False, "error": str(e)}

    try:
        _replace_domain_catalog(domain, parsed)
    except Exception as e:
        db.session.rollback()
        status = _get_or_create_status(domain)
        status.status = "FAILED"
        status.error_message = f"DB write failed: {e}"
        status.last_attempt_at = _now()
        db.session.commit()
        return {"domain": domain, "ok": False, "error": str(e)}

    status.status = "SUCCESS"
    status.source_url = Config.MITRE_DOMAIN_URLS[domain]
    status.attack_version = Config.MITRE_ATTACK_VERSION
    status.tactic_count = len(parsed["tactics"])
    status.technique_count = len(parsed["techniques"])
    status.last_success_at = _now()
    status.error_message = None
    db.session.commit()

    return {
        "domain": domain,
        "ok": True,
        "tactic_count": len(parsed["tactics"]),
        "technique_count": len(parsed["techniques"]),
        "warnings": parsed["warnings"],
    }


def sync_all_domains():
    """Syncs every configured domain independently -- one domain's failure
    never blocks or rolls back another domain's successful sync."""
    results = {}
    for domain in Config.MITRE_DOMAINS:
        try:
            results[domain] = sync_domain(domain)
        except Exception as e:
            db.session.rollback()
            results[domain] = {"domain": domain, "ok": False, "error": str(e)}
    return results
