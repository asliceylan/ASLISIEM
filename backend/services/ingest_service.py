import random
import time

from sqlalchemy.exc import OperationalError

from backend.database.db import db
from backend.database.models import Event
from backend.parsers.format_detector import parse_and_normalize


def ingest_raw_log(raw_text, device, source="simulator", tenant_id=None, max_retries=3):
    """Parses one raw log line/block (auto-detecting its format), persists it
    as an Event with no Import row involved (import_id stays None -- this is
    the live-ingest counterpart to the file-upload flow), and tags it with
    provenance (source/device_type/log_format) so it can be told apart from
    manually-imported events and bulk-deleted later.

    tenant_id defaults to None for backward compatibility with callers that
    don't (yet) run in a multi-tenant context (e.g. most existing tests) --
    the multi-tenant simulator (see backend/simulator/runner.py) always
    passes its own tenant_id explicitly.

    Commits are wrapped in a short retry/backoff loop: at this app's "a few
    logs per minute" pace a real collision with a concurrent UI-triggered
    write should be exceedingly rare, but SQLite can still occasionally raise
    "database is locked" -- this is defense-in-depth alongside the WAL/
    busy_timeout pragmas set once at startup (see backend/database/db.py).
    """
    normalized = parse_and_normalize(raw_text, device=device)
    detected_format = normalized.pop("_detected_format")

    event = Event(
        import_id=None,
        source=source,
        device_type=getattr(device, "device_type", None),
        log_format=detected_format,
        tenant_id=tenant_id,
        **normalized,
    )
    db.session.add(event)

    attempt = 0
    while True:
        try:
            db.session.commit()
            return event
        except OperationalError as exc:
            db.session.rollback()
            if "database is locked" not in str(exc).lower() or attempt >= max_retries:
                raise
            time.sleep(0.05 * (2 ** attempt) + random.uniform(0, 0.02))
            db.session.add(event)
            attempt += 1
