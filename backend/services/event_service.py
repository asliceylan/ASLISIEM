from backend.database.models import Event
from backend.engine import event_mitre_classifier
from backend.services import mitre_catalog_service, filter_service

# Safety cap on how many SQL-matched rows are pulled into Python when a
# filter targets a non-real-column (derived) field, e.g. "Path" -- see
# query_events below. Keeps a broad/unfiltered "Path" condition from
# loading the entire table into memory on a large deployment.
POST_FILTER_FETCH_CAP = 5000


def build_mitre_guess(event):
    """Enriches event_mitre_classifier's bare {technique_id, domain} guesses
    with the official name/tactics from the synced MITRE catalog when
    available; if the catalog hasn't been synced (get_technique returns
    None), silently falls back to just the technique_id -- no error, no
    fabricated name."""
    guesses = event_mitre_classifier.classify_event(event)
    enriched = []
    for guess in guesses:
        technique = mitre_catalog_service.get_technique(guess["domain"], guess["technique_id"])
        enriched.append(technique if technique else {"technique_id": guess["technique_id"]})
    return enriched


def query_events(args, tenant_id=None, filters=None):
    # filters: raw (unvalidated) list of {field,operator,value} from the
    # "Add Filter" builder -- validate_filters raises filter_service.
    # InvalidFilterError on an unknown field/operator, which the route
    # layer turns into a 400.
    filters = filter_service.validate_filters(filters, filter_service.EVENT_FILTERABLE_FIELDS)
    sql_filters, post_filters = filter_service.split_sql_and_post_filters(filters, filter_service.EVENT_FILTERABLE_FIELDS)

    q = Event.query
    if tenant_id is not None:
        q = q.filter(Event.tenant_id == tenant_id)

    event_id = args.get("event_id")
    source_ip = args.get("source_ip")
    username = args.get("username")
    ts_from = args.get("from")
    ts_to = args.get("to")
    search = args.get("search")
    source = args.get("source")

    if source:
        q = q.filter(Event.source == source)
    if event_id:
        q = q.filter(Event.event_id == event_id)
    if source_ip:
        q = q.filter(Event.source_ip == source_ip)
    if username:
        q = q.filter(Event.username == username)
    if ts_from:
        q = q.filter(Event.timestamp >= ts_from)
    if ts_to:
        q = q.filter(Event.timestamp <= ts_to)
    if search:
        like = f"%{search}%"
        q = q.filter(
            db_or(
                Event.event_name.ilike(like),
                Event.username.ilike(like),
                Event.source_ip.ilike(like),
                Event.destination_ip.ilike(like),
                Event.process_name.ilike(like),
            )
        )
    q = filter_service.apply_sql_filters(q, Event, sql_filters, filter_service.EVENT_FILTERABLE_FIELDS)

    page = int(args.get("page", 1))
    per_page = min(int(args.get("per_page", 50)), 500)
    q = q.order_by(Event.timestamp.desc().nullslast(), Event.id.desc())

    if post_filters:
        # A derived-field condition (e.g. "Path") can't be translated to
        # SQL, so exact DB-side pagination isn't possible once one is
        # present: pull a bounded superset of the already SQL-filtered/
        # tenant-scoped rows, filter it in Python, then paginate the
        # filtered list in memory. Without any post_filters, the fast path
        # below runs instead and pagination stays fully DB-side.
        candidates = q.limit(POST_FILTER_FETCH_CAP).all()
        truncated = len(candidates) == POST_FILTER_FETCH_CAP
        filtered = filter_service.apply_post_filters(candidates, post_filters)
        total = len(filtered)
        start = (page - 1) * per_page
        items = filtered[start:start + per_page]
        return items, total, page, per_page, truncated

    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, page, per_page, False


def db_or(*clauses):
    from sqlalchemy import or_
    return or_(*clauses)
