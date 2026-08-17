from types import SimpleNamespace

import pytest

from backend.parsers.cef_parser import parse_cef_line

DEVICE = SimpleNamespace(ip="10.10.0.254")


def test_parse_cef_wrapped_in_syslog_envelope():
    line = (
        "<134>Jul 31 14:22:03 fw-edge-01 CEF:0|CheckPoint|VPN-1|R81|5001|"
        "Port Scan Detected|7|src=203.0.113.44 spt=51422 dst=198.51.100.10 dpt=22 act=deny"
    )
    result = parse_cef_line(line, device=DEVICE)
    assert result["event_id"] == "5001"
    assert result["event_name"] == "Port Scan Detected"
    assert result["source_ip"] == "203.0.113.44"
    assert result["source_port"] == "51422"
    assert result["destination_ip"] == "198.51.100.10"
    assert result["destination_port"] == "22"
    assert result["derived_fields"]["Vendor"] == "CheckPoint"
    assert result["derived_fields"]["act"] == "deny"
    assert result["timestamp"] is not None


def test_parse_bare_cef_without_syslog_wrapper():
    line = "CEF:0|CheckPoint|VPN-1|R81|5001|Port Scan Detected|7|src=203.0.113.44 dst=198.51.100.10"
    result = parse_cef_line(line, device=DEVICE)
    assert result["source_ip"] == "203.0.113.44"
    assert result["destination_ip"] == "198.51.100.10"


def test_parse_cef_multi_word_extension_value():
    line = "CEF:0|Vendor|Product|1.0|100|Name|5|cs1Label=ScanSignature cs1=Multi Port TCP Scan src=203.0.113.44"
    result = parse_cef_line(line, device=DEVICE)
    assert result["derived_fields"]["cs1"] == "Multi Port TCP Scan"
    assert result["derived_fields"]["cs1Label"] == "ScanSignature"


def test_parse_cef_rejects_non_cef_line():
    with pytest.raises(ValueError):
        parse_cef_line("<134>Jul 31 14:22:03 core-sw-01 sshd[1]: not cef at all", device=DEVICE)
