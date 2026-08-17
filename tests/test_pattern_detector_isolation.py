"""General, permanent guard against the recurring bug class where one
detector's suggested rule/candidate filter also matches another pattern's
events (destination_port-alone catching web traffic; the SQLi "Path" field
being lost by the rule builder; Port Scan catching WAF/firewall-attack
events). Each prior fix was a one-off regression test for the SPECIFIC pair
just discovered -- this file instead tests every registered pattern's
canonical fixture against every OTHER registered detector, so a NEW
detector is automatically checked against all EXISTING ones (and vice
versa) the moment its fixture is registered in pattern_fixtures.py.
"""
import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import Event
from backend.engine import pattern_detectors
from tests.pattern_fixtures import POSITIVE_FIXTURES


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_every_detector_has_a_registered_isolation_fixture():
    """Tripwire: catches a new detect_* function added to DETECTORS without
    a matching fixture here -- otherwise it would silently sit outside the
    matrix below and this whole safety net would miss it."""
    assert set(pattern_detectors.DETECTORS.keys()) == set(POSITIVE_FIXTURES.keys())


@pytest.mark.parametrize("pattern_type", sorted(POSITIVE_FIXTURES.keys()))
def test_fixture_triggers_only_its_own_pattern(app, pattern_type):
    POSITIVE_FIXTURES[pattern_type]()
    hits = pattern_detectors.detect_all(Event.query.all())
    triggered = {h["pattern_type"] for h in hits}
    assert triggered == {pattern_type}, (
        f"{pattern_type}'s fixture also triggered {triggered - {pattern_type}} -- "
        f"a detector's candidate filter/conditions overlap with another pattern's events."
    )
