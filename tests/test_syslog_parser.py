from types import SimpleNamespace

from backend.parsers.syslog_parser import parse_syslog_line, strip_syslog_header

DEVICE = SimpleNamespace(ip="10.10.0.2")


def test_strip_syslog_header_extracts_pri_timestamp_hostname():
    pri, ts, host, remainder = strip_syslog_header(
        "<134>Jul 31 14:22:05 core-sw-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.44 port 51422 ssh2"
    )
    assert pri == 134
    assert host == "core-sw-01"
    assert ts.month == 7 and ts.day == 31 and ts.hour == 14
    assert remainder.startswith("sshd[1234]:")


def test_strip_syslog_header_no_envelope_returns_original_text():
    pri, ts, host, remainder = strip_syslog_header("just a plain message, no envelope")
    assert pri is None and ts is None and host is None
    assert remainder == "just a plain message, no envelope"


def test_parse_syslog_line_extracts_process_and_embedded_ip():
    line = "<134>Jul 31 14:22:05 core-sw-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.44 port 51422 ssh2"
    result = parse_syslog_line(line, device=DEVICE)
    assert result["process_name"] == "sshd"
    assert result["source_ip"] == "203.0.113.44"
    assert result["destination_ip"] == "10.10.0.2"
    assert result["timestamp"] is not None
    assert result["derived_fields"]["PID"] == "1234"


def test_parse_syslog_line_extracts_cisco_style_mnemonic_as_event_id():
    line = "<166>Jul 31 14:22:07 edge-rtr-01 %SEC-6-IPACCESSLOGP: list 101 denied tcp 203.0.113.44(51422) -> 198.51.100.10(22), 1 packet"
    result = parse_syslog_line(line, device=DEVICE)
    assert result["event_id"] == "%SEC-6-IPACCESSLOGP"
    assert result["source_ip"] == "203.0.113.44"
