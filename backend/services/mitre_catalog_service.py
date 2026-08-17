from sqlalchemy import or_

from backend.config import Config
from backend.database.models import MitreTechnique, MitreSyncStatus


def list_sync_status():
    """One dict per configured domain -- a domain with no sync row yet
    (never synced) is synthesized as NEVER_RUN rather than omitted, so the
    admin panel always has a row to show for every domain."""
    rows = {row.domain: row for row in MitreSyncStatus.query.all()}
    result = []
    for domain in Config.MITRE_DOMAINS:
        row = rows.get(domain)
        if row:
            result.append(row.to_dict())
        else:
            result.append({
                "domain": domain,
                "status": "NEVER_RUN",
                "source_url": Config.MITRE_DOMAIN_URLS.get(domain),
                "attack_version": Config.MITRE_ATTACK_VERSION,
                "tactic_count": 0,
                "technique_count": 0,
                "last_attempt_at": None,
                "last_success_at": None,
                "error_message": None,
            })
    return result


def search_techniques(query="", domain=None, limit=25):
    q = MitreTechnique.query
    if domain:
        q = q.filter_by(domain=domain)
    query = (query or "").strip()
    if query:
        like = f"%{query}%"
        q = q.filter(or_(MitreTechnique.name.ilike(like), MitreTechnique.technique_id.ilike(like)))
    rows = q.order_by(MitreTechnique.technique_id.asc()).limit(limit).all()
    return [r.to_dict(include_tactics=True) for r in rows]


def get_technique(domain, technique_id):
    row = MitreTechnique.query.filter_by(domain=domain, technique_id=technique_id).first()
    return row.to_dict(include_tactics=True, include_description=True) if row else None
