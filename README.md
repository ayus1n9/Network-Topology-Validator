# Topology Validator

[![tests](https://github.com/ayus1n9/topology-validator/actions/workflows/tests.yml/badge.svg)](https://github.com/ayus1n9/topology-validator/actions/workflows/tests.yml)
[![security](https://github.com/ayus1n9/topology-validator/actions/workflows/security.yml/badge.svg)](https://github.com/ayus1n9/topology-validator/actions/workflows/security.yml)
[![CodeQL](https://github.com/ayus1n9/topology-validator/actions/workflows/codeql.yml/badge.svg)](https://github.com/ayus1n9/topology-validator/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Validate network topologies for security design flaws — with an interactive PBQ-style simulator.

A Python tool that reads network topologies (JSON or plain text) and flags common
security design flaws — databases exposed to the DMZ, missing firewall layers,
single points of failure, and more. Includes a `--interactive` mode that acts
like a CompTIA/Cisco-style PBQ: build a topology command by command, validate
on demand, and watch your security score change.

## Features

- 📄 **Two input formats** — JSON (structured) or plain text (PBQ-style)
- 🛡️ **Six security rules** — edge checks + BFS-based path analysis
- 📊 **Security score** — 0–100 with letter grade (A–F)
- 🖼️ **Visualization** — color-coded PNG of the topology
- 📤 **Multiple report formats** — terminal, JSON, self-contained HTML
- ⚡ **Interactive REPL** — build, modify, validate topologies live
- 🧪 **Tested** — unit tests for parsers, rules, and scoring

## Installation

```bash
git clone https://github.com/ayus1n9/topology-validator.git
cd topology-validator
pip install -e .
```

This installs a `topology-validator` command on your PATH.

## Quick start

Validate a JSON topology:

```bash
topology-validator secure.json
```

Output:

```
============================================================
  NETWORK TOPOLOGY SECURITY REPORT
============================================================

  Total findings: 1
    MEDIUM   : 1

  Security Score: 96 / 100   (Grade: A)
  ...
```

## Input formats

### JSON

```json
{
  "devices": [
    {"id": "internet", "type": "internet", "zone": "external"},
    {"id": "fw1",      "type": "firewall", "zone": "dmz"},
    {"id": "web1",     "type": "web_server", "zone": "dmz"},
    {"id": "db1",      "type": "database", "zone": "internal"}
  ],
  "connections": [
    {"from": "internet", "to": "fw1"},
    {"from": "fw1", "to": "web1"},
    {"from": "web1", "to": "db1"}
  ]
}
```

### Text (PBQ-style)

```
device internet internet external
device fw1      firewall dmz
device web1     web_server dmz
device db1      database internal

internet -- fw1
fw1 -- web1
web1 -- db1
```

## Rules

| Rule | What it detects |
|---|---|
| `rule_database_exposed` | Database directly connected to external/DMZ device |
| `rule_internet_to_internal` | Direct link between internet and internal zones |
| `rule_dmz_to_internal` | DMZ host directly connected to internal (no firewall) |
| `rule_web_to_database` | Web server directly connected to database (missing app tier) |
| `rule_no_firewall_path` | Any path from internet to DB bypassing all firewalls |
| `rule_single_point_of_failure` | Devices whose failure disconnects internet from DB |

## Scoring

| Severity | Penalty |
|---|---|
| Critical | 25 |
| High     | 10 |
| Medium   | 4  |
| Low      | 1  |

Score = max(0, 100 − total penalties). Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60.

## CLI options

| Flag | Description |
|---|---|
| `topology_file` | Path to `.json` or `.txt` topology |
| `-i`, `--interactive` | Launch the PBQ-style REPL |
| `-v`, `--visualize` | Render the topology to a PNG |
| `-f`, `--format` | `text` (default), `json`, or `html` |
| `-o`, `--output` | Output path for json/html reports |
| `-q`, `--quiet` | Suppress terminal report; only set exit code |

Exit codes: `0` = clean, `1` = findings present, `2` = error.

## Interactive mode

```bash
topology-validator -i
```

```
> add internet internet external
> add fw1 firewall dmz
> add db1 database internal
> connect internet fw1
> connect fw1 db1
> check
```

Available commands: `add`, `remove`, `connect`, `disconnect`, `show`, `check`,
`score`, `render`, `save`, `load`, `clear`, `help`, `quit`.

## Examples

### Visualize a topology

```bash
topology-validator insecure.json --visualize
```

Generates `insecure.png` — a color-coded diagram with flagged nodes outlined in red.

### Generate an HTML report

```bash
topology-validator insecure.json -f html --visualize
```

Produces a self-contained `insecure.report.html` with the diagram and findings embedded.

### Machine-readable output for CI

```bash
topology-validator insecure.json -f json -o report.json || echo "Topology has flaws!"
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).