from backend.database.db import db
from backend.database.models import Offense, OffenseEvent
from backend.services import filter_service


def list_offenses(tenant_ids=None, filters=None):
    # filters: validated list of {field,operator,value} from the "Add
    # Filter" builder (see filter_service.OFFENSE_FILTERABLE_FIELDS) --
    # every field there maps to a real column, so this is pure SQL, no
    # post-filter hybrid needed (unlike query_events, Offense has no
    # raw_data/derived-field concept).
    query = Offense.query
    if tenant_ids is not None:
        query = query.filter(Offense.tenant_id.in_(tenant_ids))
    filters = filter_service.validate_filters(filters, filter_service.OFFENSE_FILTERABLE_FIELDS)
    query = filter_service.apply_sql_filters(query, Offense, filters, filter_service.OFFENSE_FILTERABLE_FIELDS)
    return query.order_by(Offense.created_at.desc()).all()


def get_offense(offense_id):
    return Offense.query.get(offense_id)


def get_offense_events(offense_id):
    links = OffenseEvent.query.filter_by(offense_id=offense_id).all()
    return [l.event for l in links if l.event]


def update_status(offense_id, status):
    offense = Offense.query.get(offense_id)
    if not offense:
        return None
    offense.status = status
    db.session.commit()
    return offense
