
"""Parse Nmap XML output into typed, report-friendly data."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET


class NmapParseError(ValueError):
    """Raised when an Nmap XML file cannot be read or parsed."""


@dataclass
class Port:
    """A port and its observed service details."""

    number: Optional[int]
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


@dataclass
class Host:
    """A host discovered in an Nmap scan."""

    address: str
    hostnames: list[str] = field(default_factory=list)
    state: str = "unknown"
    ports: list[Port] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete parsed Nmap scan result."""

    hosts: list[Host] = field(default_factory=list)
    scanner: str = ""
    args: str = ""
    start_time: str = ""
    input_path: str = ""


def _attribute(element: Optional[ET.Element], name: str) -> str:
    return element.get(name, "") if element is not None else ""


def parse_nmap_xml(input_path: str | Path) -> ScanResult:
    """Parse an Nmap XML file.

    The parser only reads XML data and never executes values found in the file.
    """

    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Nmap XML file does not exist: {path}")
    if not path.is_file():
        raise NmapParseError(f"Nmap XML input is not a regular file: {path}")
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError) as exc:
        raise NmapParseError(f"Unable to parse Nmap XML file '{path}': {exc}") from exc

    root = tree.getroot()
    result = ScanResult(
        scanner=_attribute(root, "scanner"),
        args=_attribute(root, "args"),
        start_time=_attribute(root, "start"),
        input_path=str(path),
    )
    for host_element in root.findall("host"):
        address_element = host_element.find("address")
        address = _attribute(address_element, "addr") or "unknown"
        hostnames = [
            name
            for name in (
                _attribute(item, "name")
                for item in host_element.findall("./hostnames/hostname")
            )
            if name
        ]
        state = _attribute(host_element.find("./status"), "state") or "unknown"
        ports: list[Port] = []
        for port_element in host_element.findall("./ports/port"):
            service_element = port_element.find("service")
            number_text = port_element.get("portid")
            try:
                number = int(number_text) if number_text else None
            except ValueError:
                number = None
            ports.append(
                Port(
                    number=number,
                    protocol=_attribute(port_element, "protocol") or "unknown",
                    state=_attribute(port_element.find("state"), "state") or "unknown",
                    service=_attribute(service_element, "name"),
                    product=_attribute(service_element, "product"),
                    version=_attribute(service_element, "version"),
                    extra_info=_attribute(service_element, "extrainfo"),
                )
            )
        result.hosts.append(
            Host(address=address, hostnames=hostnames, state=state, ports=ports)
        )
    return result


parse_nmap_file = parse_nmap_xml
