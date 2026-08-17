from backend.services.mitre_sync_service import parse_stix_bundle

KILL_CHAIN = "mitre-attack"


def _tactic(stix_id, tactic_id, name, shortname):
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "name": name,
        "x_mitre_shortname": shortname,
        "external_references": [{"source_name": "mitre-attack", "external_id": tactic_id}],
    }


def _technique(stix_id, technique_id, name, shortnames, is_subtechnique=False, revoked=False,
                deprecated=False, description=None):
    obj = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "x_mitre_is_subtechnique": is_subtechnique,
        "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
        "kill_chain_phases": [{"kill_chain_name": KILL_CHAIN, "phase_name": s} for s in shortnames],
    }
    if description is not None:
        obj["description"] = description
    return obj


def _relationship(source_ref, target_ref, revoked=False):
    return {
        "type": "relationship",
        "relationship_type": "subtechnique-of",
        "source_ref": source_ref,
        "target_ref": target_ref,
        "revoked": revoked,
    }


def _sample_bundle():
    return {
        "objects": [
            _tactic("x-mitre-tactic--a", "TA0001", "Initial Access", "initial-access"),
            _tactic("x-mitre-tactic--b", "TA0003", "Persistence", "persistence"),
            _technique(
                "attack-pattern--t1", "T9001", "Fake Technique One",
                shortnames=["initial-access", "persistence"],
            ),
            _technique(
                "attack-pattern--t2", "T9001.001", "Fake Sub One",
                shortnames=["initial-access"], is_subtechnique=True,
            ),
            _technique(
                "attack-pattern--t3", "T9002", "Revoked Technique",
                shortnames=["persistence"], revoked=True,
            ),
            _technique(
                "attack-pattern--t4", "T9003", "Deprecated Technique",
                shortnames=["persistence"], deprecated=True,
            ),
            _relationship("attack-pattern--t2", "attack-pattern--t1"),
            _relationship("attack-pattern--t4", "attack-pattern--t1", revoked=True),
        ]
    }


def test_parse_stix_bundle_filters_revoked_and_deprecated():
    parsed = parse_stix_bundle("test", _sample_bundle(), KILL_CHAIN)
    technique_ids = {t["technique_id"] for t in parsed["techniques"]}
    assert technique_ids == {"T9001", "T9001.001"}


def test_parse_stix_bundle_resolves_subtechnique_parent():
    parsed = parse_stix_bundle("test", _sample_bundle(), KILL_CHAIN)
    assert parsed["subtechnique_parents"] == {"attack-pattern--t2": "attack-pattern--t1"}


def test_parse_stix_bundle_links_multiple_tactics_to_one_technique():
    parsed = parse_stix_bundle("test", _sample_bundle(), KILL_CHAIN)
    t1 = next(t for t in parsed["techniques"] if t["technique_id"] == "T9001")
    assert t1["shortnames"] == ["initial-access", "persistence"]
    assert len(parsed["tactics"]) == 2


def test_parse_stix_bundle_empty_bundle_returns_empty_lists():
    parsed = parse_stix_bundle("test", {"objects": []}, KILL_CHAIN)
    assert parsed == {
        "tactics": [],
        "techniques": [],
        "subtechnique_parents": {},
        "warnings": [],
    }


def test_parse_stix_bundle_carries_raw_description_through_unmodified():
    # Cleanup (citation stripping) happens at MitreTechnique.to_dict() time,
    # not here -- parse_stix_bundle must pass the description through as-is.
    raw_description = "Adversaries may abuse this (Citation: FireEye APT29) to gain access."
    bundle = {"objects": [
        _technique("attack-pattern--t1", "T9001", "Fake Technique One",
                   shortnames=[], description=raw_description),
    ]}
    parsed = parse_stix_bundle("test", bundle, KILL_CHAIN)
    assert parsed["techniques"][0]["description"] == raw_description


def test_parse_stix_bundle_missing_description_is_none():
    bundle = {"objects": [
        _technique("attack-pattern--t1", "T9001", "Fake Technique One", shortnames=[]),
    ]}
    parsed = parse_stix_bundle("test", bundle, KILL_CHAIN)
    assert parsed["techniques"][0]["description"] is None
