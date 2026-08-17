import pytest

from backend.app import create_app
from backend.database.db import db
from backend.database.models import MitreTechnique
from backend.services import mitre_catalog_service
from backend.services.mitre_sync_service import _replace_domain_catalog


@pytest.fixture
def app():
    app = create_app()
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _make_technique(description=None):
    row = MitreTechnique(
        domain="enterprise", stix_id="attack-pattern--fake-t1110", technique_id="T1110",
        name="Brute Force", is_subtechnique=False, description=description,
    )
    db.session.add(row)
    db.session.commit()
    return row


def test_to_dict_include_description_strips_citation_markers(app):
    row = _make_technique(description="Adversaries may guess passwords (Citation: FireEye APT29) to gain access.")
    d = row.to_dict(include_description=True)
    assert "Citation" not in d["description"]
    assert "Adversaries may guess passwords" in d["description"]
    assert "to gain access." in d["description"]


def test_to_dict_include_description_none_when_description_is_none(app):
    row = _make_technique(description=None)
    d = row.to_dict(include_description=True)
    assert d["description"] is None


def test_to_dict_omits_description_key_by_default(app):
    row = _make_technique(description="Some text.")
    d = row.to_dict()
    assert "description" not in d


def test_get_technique_returns_cleaned_description(app):
    _make_technique(description="Uses valid accounts (Citation: Some Source) for persistence.")
    result = mitre_catalog_service.get_technique("enterprise", "T1110")
    assert result["description"] == "Uses valid accounts for persistence."


def test_get_technique_returns_none_when_description_not_synced(app):
    _make_technique(description=None)
    result = mitre_catalog_service.get_technique("enterprise", "T1110")
    assert result["description"] is None


def test_get_technique_returns_none_when_technique_not_found(app):
    assert mitre_catalog_service.get_technique("enterprise", "T9999") is None


def test_replace_domain_catalog_stores_description(app):
    parsed = {
        "tactics": [],
        "techniques": [{
            "stix_id": "attack-pattern--t1", "technique_id": "T9001", "name": "Fake Technique",
            "is_subtechnique": False, "shortnames": [],
            "description": "Fake description (Citation: Foo) for testing.",
        }],
        "subtechnique_parents": {},
        "warnings": [],
    }
    _replace_domain_catalog("enterprise", parsed)
    db.session.commit()

    row = MitreTechnique.query.filter_by(domain="enterprise", technique_id="T9001").first()
    assert row.description == "Fake description (Citation: Foo) for testing."
