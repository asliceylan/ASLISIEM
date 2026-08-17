from types import SimpleNamespace

import pytest

from backend.parsers.winevent_parser import parse_winevent_block

DEVICE = SimpleNamespace(ip="198.51.100.20")

SAMPLE_BLOCK = """Log Name: Security
Event ID: 4625
TimeCreated: 2026-07-31 14:22:03
Computer: dmz-mail-01
Account Name: jsmith
Source Network Address: 203.0.113.44
Logon Type: 3
Message: An account failed to log on."""


def test_parse_winevent_block_extracts_fields():
    result = parse_winevent_block(SAMPLE_BLOCK, device=DEVICE)
    assert result["event_id"] == "4625"
    assert result["username"] == "jsmith"
    assert result["source_ip"] == "203.0.113.44"
    assert result["destination_ip"] == "198.51.100.20"
    assert result["timestamp"].year == 2026 and result["timestamp"].month == 7
    assert result["event_name"] == "An account failed to log on."
    assert result["derived_fields"]["Logon Type"] == "3"


def test_parse_winevent_block_rejects_non_winevent_text():
    with pytest.raises(ValueError):
        parse_winevent_block("just some random text\nwith no key value pairs", device=DEVICE)
