import itertools
import random

from backend.simulator.scenario import generate_kill_chain_events
from backend.parsers.format_detector import parse_and_normalize


def _take(gen, n):
    return list(itertools.islice(gen, n))


def test_phase_order_is_recon_bruteforce_sqli_lateral_and_then_loops():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    phases_in_order = []
    for e in events:
        if not phases_in_order or phases_in_order[-1] != e["phase"]:
            phases_in_order.append(e["phase"])
    assert phases_in_order[:8] == [
        "recon", "bruteforce", "sqli", "lateral_movement",
        "recon", "bruteforce", "sqli", "lateral_movement",
    ]


def test_bruteforce_phase_ends_with_a_single_success_event():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    bruteforce = [e for e in events if e["phase"] == "bruteforce"]
    # first full bruteforce block only (up to the point it changes phase again)
    first_block = list(itertools.takewhile(lambda e: e["phase"] == "bruteforce",
                                            itertools.dropwhile(lambda e: e["phase"] != "bruteforce", events)))
    parsed = [parse_and_normalize(e["raw_text"], device=e["device"]) for e in first_block]
    success_ids = [p["event_id"] for p in parsed if p["event_id"] == "4624"]
    failed_ids = [p["event_id"] for p in parsed if p["event_id"] == "4625"]
    assert len(success_ids) == 1
    assert len(failed_ids) >= 5
    assert parsed[-1]["event_id"] == "4624"  # success is the last event in the block


def test_lateral_movement_phase_includes_dmz_db_syslog_event():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    lateral = [e for e in events if e["phase"] == "lateral_movement"]
    db_events = [e for e in lateral if e["device"].name == "dmz_db"]
    assert len(db_events) >= 1
    parsed = parse_and_normalize(db_events[0]["raw_text"], device=db_events[0]["device"])
    assert parsed["_detected_format"] == "syslog"
    # source is the already-compromised dmz_mail host, not the external attacker
    mail_ip = "198.51.100.20"
    assert parsed["source_ip"] is None or mail_ip in db_events[0]["raw_text"]


def test_attacker_ip_changes_between_consecutive_recon_phases():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 400)
    recon_blocks = []
    current = []
    for e in events:
        if e["phase"] == "recon":
            current.append(e)
        elif current:
            recon_blocks.append(current)
            current = []
    assert len(recon_blocks) >= 2
    ip_of_block = lambda block: parse_and_normalize(block[0]["raw_text"], device=block[0]["device"])["source_ip"]
    assert ip_of_block(recon_blocks[0]) != ip_of_block(recon_blocks[1])


def test_every_generated_event_is_recognized_by_the_format_detector():
    # Regression test: an earlier version of the SQLi payloads used literal
    # spaces (e.g. "id=1' OR '1'='1"), which broke the access-log "METHOD
    # path PROTOCOL" 3-token assumption and made those lines silently fall
    # back to "unknown". Every line the simulator renders must actually be
    # classified as its real format, never "unknown".
    gen = generate_kill_chain_events(random.Random(7))
    events = _take(gen, 300)
    for e in events:
        parsed = parse_and_normalize(e["raw_text"], device=e["device"])
        assert parsed["_detected_format"] != "unknown", (
            f"phase={e['phase']} device={e['device'].name} raw_text={e['raw_text']!r}"
        )


def test_generator_is_deterministic_given_same_seed():
    gen1 = generate_kill_chain_events(random.Random(42))
    gen2 = generate_kill_chain_events(random.Random(42))
    events1 = _take(gen1, 50)
    events2 = _take(gen2, 50)
    assert [e["raw_text"] for e in events1] == [e["raw_text"] for e in events2]


def test_bruteforce_phase_includes_ssh_failures_from_dmz_db():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    bruteforce = list(itertools.takewhile(lambda e: e["phase"] == "bruteforce",
                                           itertools.dropwhile(lambda e: e["phase"] != "bruteforce", events)))
    ssh_events = [e for e in bruteforce if e["device"].name == "dmz_db"]
    assert len(ssh_events) >= 6
    for e in ssh_events:
        assert "failed password" in e["raw_text"].lower()
    usernames_seen = {e["raw_text"].split("for ")[1].split(" from")[0] for e in ssh_events}
    assert usernames_seen <= {"root", "admin", "ubuntu"}


def test_recon_phase_includes_firewall_intrusion_signature():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    recon = list(itertools.takewhile(lambda e: e["phase"] == "recon", events))
    intrusion = [e for e in recon if "Network Intrusion Detected" in e["raw_text"]]
    assert len(intrusion) >= 1


def test_sqli_phase_includes_waf_and_firewall_signals():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    sqli = list(itertools.takewhile(lambda e: e["phase"] == "sqli",
                                     itertools.dropwhile(lambda e: e["phase"] != "sqli", events)))
    waf_events = [e for e in sqli if e["device"].name == "waf"]
    assert len(waf_events) >= 5
    for e in waf_events:
        assert "SQL Injection Attack Detected" in e["raw_text"]
    fw_intrusion = [e for e in sqli if e["device"].name == "firewall"
                    and "Network Intrusion Detected" in e["raw_text"]]
    assert len(fw_intrusion) >= 1


def test_lateral_movement_phase_includes_sudo_usage():
    gen = generate_kill_chain_events(random.Random(1234))
    events = _take(gen, 200)
    lateral = list(itertools.takewhile(lambda e: e["phase"] == "lateral_movement",
                                        itertools.dropwhile(lambda e: e["phase"] != "lateral_movement", events)))
    sudo_events = [e for e in lateral if "COMMAND=" in e["raw_text"]]
    assert len(sudo_events) >= 1
