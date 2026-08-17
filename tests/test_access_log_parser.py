from types import SimpleNamespace

import pytest

from backend.parsers.access_log_parser import parse_access_log_line

DEVICE = SimpleNamespace(ip="198.51.100.10", port=443)


def test_parse_access_log_sqli_attempt():
    line = (
        '203.0.113.44 - - [31/Jul/2026:14:35:20 +0000] '
        '"GET /product.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 5321 '
        '"-" "Mozilla/5.0"'
    )
    result = parse_access_log_line(line, device=DEVICE)
    assert result["source_ip"] == "203.0.113.44"
    assert result["event_id"] == "200"
    assert result["destination_ip"] == "198.51.100.10"
    assert result["destination_port"] == "443"
    assert result["timestamp"] is not None
    assert result["timestamp"].tzinfo is None
    assert result["derived_fields"]["Method"] == "GET"
    assert "product.php" in result["derived_fields"]["Path"]


def test_parse_access_log_dash_authuser_is_no_username():
    line = '203.0.113.44 - - [31/Jul/2026:14:35:20 +0000] "GET / HTTP/1.1" 200 100'
    result = parse_access_log_line(line, device=DEVICE)
    assert result["username"] is None


def test_parse_access_log_rejects_garbage():
    with pytest.raises(ValueError):
        parse_access_log_line("not an access log line at all", device=DEVICE)
