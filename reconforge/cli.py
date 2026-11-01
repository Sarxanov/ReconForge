
"""Command-line interface for ReconForge."""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from .http_inspector import HttpInspectionError, inspect_http_url
from .nmap_parser import NmapParseError, parse_nmap_xml
from .reporter import generate_report, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="Parse Nmap XML and generate authorized reconnaissance reports.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable diagnostic logging.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze an Nmap XML scan.")
    analyze.add_argument("-i", "--input", required=True, help="Path to Nmap XML input.")
    analyze.add_argument("-o", "--output", default="reports", help="Report output directory.")
    analyze.add_argument("--url", action="append", default=[], help="Explicit authorized HTTP(S) URL to inspect.")
    analyze.add_argument("--http", action="store_true", help="Opt in to inspection of the supplied --url values.")
    analyze.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10).")
    analyze.add_argument("--force", action="store_true", help="Overwrite an existing report.")

    inspect = subparsers.add_parser("inspect-http", help="Inspect one explicitly supplied HTTP(S) URL.")
    inspect.add_argument("--url", required=True, help="Explicit authorized HTTP(S) URL.")
    inspect.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds.")
    return parser


def _run(args: argparse.Namespace) -> int:
    if args.command == "inspect-http":
        result = inspect_http_url(args.url, timeout=args.timeout)
        if result.status_code is not None:
            print(f"URL: {result.url}\nStatus: {result.status_code}")
        if result.missing_security_headers:
            print("Missing headers: " + ", ".join(result.missing_security_headers))
        if result.error:
            print(f"Error: {result.error}", file=sys.stderr)
            return 1
        return 0

    if args.http and not args.url:
        raise HttpInspectionError("--http requires at least one explicit --url")
    scan = parse_nmap_xml(args.input)
    http_results = (
        [inspect_http_url(url, timeout=args.timeout) for url in args.url]
        if args.http
        else []
    )
    report = generate_report(scan, http_results)
    destination = write_report(report, args.output, overwrite=args.force)
    print(f"Report written to {destination}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    try:
        return _run(args)
    except (FileNotFoundError, NmapParseError, HttpInspectionError, FileExistsError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
