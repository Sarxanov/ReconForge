from pathlib import Path

import pytest

from reconforge.nmap_parser import Host, Port, ScanResult
from reconforge.reporter import generate_report, write_report


def test_report_contains_hosts_services_and_safe_special_characters():
    scan = ScanResult(
        hosts=[Host("192.0.2.1", ["host.test"], "up", [Port(80, "tcp", "open", "http", "A|B", "1", "")])]
    )
    report = generate_report(scan)
    assert "192.0.2.1" in report
    assert "A\\|B" in report
    assert "No HTTP inspection was requested." in report


def test_report_write_refuses_overwrite(tmp_path: Path):
    target = tmp_path / "reports"
    write_report("first", target)
    with pytest.raises(FileExistsError):
        write_report("second", target)
    write_report("second", target, overwrite=True)
    assert (target / "reconforge-report.md").read_text() == "second"
