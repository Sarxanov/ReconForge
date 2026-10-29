# ReconForge

**A modular network reconnaissance and reporting toolkit built with Python and Bash.**

ReconForge is a cybersecurity learning project designed to organize network reconnaissance results, inspect HTTP security headers, and generate readable assessment reports in authorized testing environments.

> **Project status:** Early development. Features are being implemented incrementally.

## Features

### Planned and in development

- **Nmap XML Analyzer** — Parse Nmap XML output to extract hosts, ports, states, and service information.
- **HTTP Inspector** — Inspect HTTP response status codes and selected security headers.
- **Report Generator** — Generate Markdown reports from collected findings.
- **Bash Launcher** — Simplify local execution on Linux.
- **Automated Tests** — Validate parsing, HTTP inspection, and error handling.

Features will be marked as implemented after they have been developed and tested.

## Project Structure

```text
ReconForge/
├── reconforge/
│   ├── __init__.py
│   ├── cli.py
│   ├── nmap_parser.py
│   ├── http_inspector.py
│   └── reporter.py
├── scripts/
│   └── reconforge.sh
├── tests/
│   ├── test_nmap_parser.py
│   ├── test_http_inspector.py
│   └── fixtures/
│       └── sample_scan.xml
├── examples/
│   └── sample_report.md
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Requirements

- Python 3.10 or newer
- Nmap installed on your system for scan generation
- Git (optional, for cloning and version control)
- Linux is the primary development environment

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/ReconForge.git
cd ReconForge
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Replace `YOUR-USERNAME` with your GitHub username.

## Usage

ReconForge is under development, so the complete command-line workflow is not available yet.

The intended workflow is:

1. Run Nmap against an authorized lab target.
2. Save the scan results in XML format.
3. Provide the XML file to the Nmap Analyzer.
4. Inspect HTTP services where appropriate.
5. Generate a Markdown report.

Example Nmap command for an authorized lab:

```bash
nmap -sV -oX scan.xml <AUTHORIZED_TARGET>
```

`<AUTHORIZED_TARGET>` is a placeholder. Replace it with a host you own or have explicit permission to test.

The command above generates an XML file; it does not invoke ReconForge itself.

## Example Output

The following is illustrative output, not the result of an actual scan:

```text
ReconForge - Reconnaissance Summary

Target: lab.example
Open ports: 2

PORT    STATE   SERVICE
22/tcp  open    ssh
80/tcp  open    http

Report: reports/recon_report.md
```

## Testing

Automated tests will be added as modules are implemented.

The planned test coverage includes:

- Valid and malformed XML input
- Missing files and incomplete service information
- HTTP timeouts and connection errors
- Missing security headers
- Markdown report generation

## Roadmap

- [ ] Build the Nmap XML parser
- [ ] Add unit tests for XML parsing
- [ ] Implement HTTP security-header inspection
- [ ] Generate Markdown reports
- [ ] Add a Bash launcher
- [ ] Compare results from multiple scans
- [ ] Improve CLI usability and error handling
- [ ] Document tested examples and limitations

## Authorized Use

ReconForge is intended for cybersecurity education and authorized security assessments.

- Only scan systems you own or have explicit permission to test.
- Follow the rules of engagement for any lab or engagement.
- Do not treat missing HTTP headers or exposed services as proof of a vulnerability without further validation.
- You are responsible for complying with applicable laws and policies.

## Contributing

Suggestions, bug reports, and improvements are welcome. Please include reproducible steps and test results when reporting issues.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author

**Tuncay Sarxanlı**

Cybersecurity student exploring network reconnaissance, Python automation, and practical security tooling.
