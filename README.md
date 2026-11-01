# ReconForge

ReconForge is a modular Python and Bash toolkit for parsing Nmap XML results, optionally inspecting HTTP security headers on explicitly authorized URLs, and producing Markdown reports.

**Status:** Functional initial release. Runtime code uses only the Python standard library.

## Features

- Typed Nmap XML parsing for multiple hosts, states, ports, protocols, and service metadata.
- Explicit opt-in HTTP/HTTPS inspection with conservative timeouts and same-host redirect checks.
- Informational security-header findings for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Markdown report generation with safe table escaping and no-overwrite protection.
- Argparse CLI and a working Linux launcher.

## Structure

```text
reconforge/       Parser, HTTP inspector, reporter, and CLI
scripts/          Linux launcher
tests/            Unit tests and Nmap fixture
examples/         Example generated report
```

## Requirements and installation

Python 3.10+ is required. Nmap is needed only to create XML input files; ReconForge does not run Nmap.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The package can also be installed locally:

```bash
python -m pip install .
```

## Usage

Create an XML scan in an authorized environment, then generate a report:

```bash
nmap -sV -oX scan.xml <AUTHORIZED_TARGET>
python -m reconforge.cli analyze --input scan.xml --output reports
```

HTTP inspection is never automatic. Supply each explicitly authorized URL and opt in:

```bash
python -m reconforge.cli inspect-http --url https://authorized.example
python -m reconforge.cli analyze --input scan.xml --http \
  --url https://authorized.example --output reports
```

Use `--force` to replace an existing report and `--help` for complete CLI help. The launcher works from any directory:

```bash
./scripts/reconforge.sh analyze --input scan.xml
```

Output is written to `reports/reconforge-report.md` by default. See `examples/sample_report.md` for a representative report.

## Testing

```bash
python -m pytest
bash -n scripts/reconforge.sh
```

HTTP tests use mocks and do not send network traffic.

## Security and limitations

Use ReconForge only against systems you own or are explicitly authorized to test. Missing headers are observations, not proof of vulnerabilities. The tool does not exploit services, bypass authentication, brute-force credentials, or automatically discover HTTP targets. Redirects to a different host are blocked. The current report format does not compare multiple scans or execute Nmap itself.

## Roadmap

- Add optional scan comparison and richer report summaries.
- Add packaging and CI checks for supported Python versions.
- Expand protocol-aware inspection without increasing request volume.

## License and author

Released under the MIT License; see `LICENSE`.

**Author:** Tuncay Sarxanlı
