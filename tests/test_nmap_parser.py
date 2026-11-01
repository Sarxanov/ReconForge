
from pathlib import Path

import pytest

from reconforge.nmap_parser import NmapParseError, parse_nmap_xml


FIXTURE = Path(__file__).parent / "fixtures" / "sample_scan.xml"


def test_parses_multiple_hosts_and_services():
    result = parse_nmap_xml(FIXTURE)
    assert len(result.hosts) == 2
    assert result.hosts[0].address == "192.0.2.10"
    assert result.hosts[0].hostnames == ["app.example.test"]
    assert result.hosts[0].ports[0].service == "ssh"
    assert result.hosts[0].ports[0].extra_info == "protocol 2.0"
    assert result.hosts[1].ports == []


def test_missing_attributes_are_safe(tmp_path):
    path = tmp_path / "minimal.xml"
    path.write_text("<nmaprun><host><address/><ports><port><state/></port></ports></host></nmaprun>")
    host = parse_nmap_xml(path).hosts[0]
    assert host.address == "unknown"
    assert host.state == "unknown"
    assert host.ports[0].number is None


def test_missing_file_and_invalid_xml(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml(tmp_path / "missing.xml")
    malformed = tmp_path / "bad.xml"
    malformed.write_text("<nmaprun>")
    with pytest.raises(NmapParseError):
        parse_nmap_xml(malformed)


def test_empty_scan_is_valid(tmp_path):
    path = tmp_path / "empty.xml"
    path.write_text("<nmaprun/>")
    assert parse_nmap_xml(path).hosts == []
