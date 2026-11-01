
"""Generate Markdown reports from ReconForge data."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from xml.sax.saxutils import escape

from .http_inspector import HttpInspectionResult
from .nmap_parser import Host, ScanResult


def _cell(value: object) -> str:
    return escape(str(value).replace("|", "\\|").replace("\n", " "))


def generate_report(
    scan: ScanResult,
    http_results: Iterable[HttpInspectionResult] = (),
    generated_at: datetime | None = None,
) -> str:
    """Return a Markdown report without writing to disk."""

    timestamp = generated_at or datetime.now(timezone.utc)
    results = list(http_results)
    lines = [
        "# ReconForge Report",
        "",
        f"**Generated:** {timestamp.astimezone(timezone.utc).isoformat()}",
        f"**Input:** `{_cell(scan.input_path or 'not specified')}`",
        "",
        "## Summary",
        "",
        f"- Hosts discovered: **{len(scan.hosts)}**",
        f"- Hosts with open ports: **{sum(bool(host.ports) for host in scan.hosts)}**",
        f"- HTTP inspections: **{len(results)}**",
        "",
        "## Host Analysis",
        "",
    ]
    if not scan.hosts:
        lines.append("No hosts were discovered.")
    for host in scan.hosts:
        lines.extend(_render_host(host))
    if results:
        lines.extend(["## HTTP Inspection Results", ""])
        for result in results:
            lines.extend(_render_http_result(result))
    else:
        lines.extend(["## HTTP Inspection Results", "", "No HTTP inspection was requested.", ""])
    lines.extend(
        [
            "## Conclusion",
            "",
            "This report contains observations from the supplied Nmap XML and any explicitly requested HTTP inspections. "
            "Missing security headers are informational findings and are not, by themselves, proof of a vulnerability.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_host(host: Host) -> list[str]:
    title = _cell(host.address)
    if host.hostnames:
        title += f" ({_cell(', '.join(host.hostnames))})"
    lines = [f"### {title}", "", f"**State:** {_cell(host.state)}", ""]
    if not host.ports:
        return lines + ["No ports were reported.", ""]
    lines += [
        "| Port | Protocol | State | Service | Product | Version | Extra information |",
        "| ---: | --- | --- | --- | --- | --- | --- |",
    ]
    for port in host.ports:
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (
                    port.number if port.number is not None else "",
                    port.protocol,
                    port.state,
                    port.service,
                    port.product,
                    port.version,
                    port.extra_info,
                )
            )
            + " |"
        )
    return lines + [""]


def _render_http_result(result: HttpInspectionResult) -> list[str]:
    lines = [f"### {_cell(result.url)}", ""]
    if result.status_code is not None:
        lines.append(f"- Status: **{result.status_code}**")
    if result.final_url and result.final_url != result.url:
        lines.append(f"- Final URL: `{_cell(result.final_url)}`")
    if result.error:
        lines.append(f"- Error: {_cell(result.error)}")
    if result.missing_security_headers:
        lines.append(
            "- Missing security headers: "
            + ", ".join(f"`{_cell(header)}`" for header in result.missing_security_headers)
        )
    else:
        lines.append("- Missing security headers: none observed")
    lines.append("")
    return lines


def write_report(
    report: str,
    output_directory: str | Path = "reports",
    filename: str = "reconforge-report.md",
    overwrite: bool = False,
) -> Path:
    """Write a report, refusing to overwrite an existing file by default."""

    if Path(filename).name != filename:
        raise ValueError("Report filename must not contain directory components")
    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / filename
    if destination.exists() and not overwrite:
        raise FileExistsError(
            f"Report already exists: {destination}. Use --force to overwrite it."
        )
    destination.write_text(report, encoding="utf-8")
    return destination
