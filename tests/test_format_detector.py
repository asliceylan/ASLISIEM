from types import SimpleNamespace

from backend.parsers.format_detector import detect_format, parse_and_normalize

DEVICE = SimpleNamespace(ip="10.10.0.254", port=443)


def test_cef_wrapped_in_syslog_is_classified_as_cef():
    line = (
        "<134>Jul 31 14:22:03 fw-edge-01 CEF:0|CheckPoint|VPN-1|R81|5001|"
        "Port Scan Detected|7|src=203.0.113.44 dst=198.51.100.10 dpt=22 act=deny"
    )
    assert detect_format(line) == "cef"


def test_plain_syslog_with_pri_header_is_not_misclassified_as_cef():
    line = (
        "<134>Jul 31 14:22:05 core-sw-01 sshd[1234]: Failed password for "
        "invalid user admin from 203.0.113.44 port 51422 ssh2"
    )
    assert detect_format(line) == "syslog"


def test_bare_cef_without_syslog_wrapper_is_still_cef():
    line = "CEF:0|CheckPoint|VPN-1|R81|5001|Port Scan Detected|7|src=203.0.113.44 dst=198.51.100.10"
    assert detect_format(line) == "cef"


def test_access_log_line_classified_correctly():
    line = '203.0.113.44 - - [31/Jul/2026:14:35:20 +0000] "GET /login.php HTTP/1.1" 401 512'
    assert detect_format(line) == "access_log"


def test_winevent_block_classified_correctly():
    block = "Log Name: Security\nEvent ID: 4625\nTimeCreated: 2026-07-31 14:22:03\nComputer: dmz-mail-01"
    assert detect_format(block) == "winevent"


def test_unrecognized_garbage_returns_unknown_not_a_crash():
    assert detect_format("###not a real log line###") == "unknown"


def test_parse_and_normalize_unknown_line_never_raises_and_preserves_raw():
    result = parse_and_normalize("###garbage###", device=DEVICE)
    assert result["event_name"] == "UNPARSED_LOG"
    assert result["_detected_format"] == "unknown"
    assert "###garbage###" in result["raw_data"]


def test_parse_and_normalize_malformed_cef_degrades_safely_instead_of_raising():
    # detected as "cef" (starts with CEF:0|) but has too few pipe-delimited fields
    result = parse_and_normalize("CEF:0|OnlyThreeFields", device=DEVICE)
    assert result["event_name"] == "UNPARSED_LOG"
    assert result["_detected_format"] == "unknown"


def test_parse_and_normalize_cef_produces_expected_shape():
    line = "CEF:0|CheckPoint|VPN-1|R81|5001|Port Scan Detected|7|src=203.0.113.44 dst=198.51.100.10 dpt=22"
    result = parse_and_normalize(line, device=DEVICE)
    assert result["_detected_format"] == "cef"
    assert result["event_id"] == "5001"
    assert result["source_ip"] == "203.0.113.44"
    assert "dpt" in result["raw_data"]
