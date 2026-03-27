# SurfaceLens

SurfaceLens is a local-first attack surface intelligence workbench for external pentests and bug bounty workflows. It ingests common recon outputs, correlates them into a single asset view, ranks likely-interesting targets, and exports analyst-facing reports.

## What It Solves

Recon collection is easy. Recon reduction is still messy.

SurfaceLens is built for the middle of the workflow:

- ingest the outputs teams already use
- normalize hosts, ports, services, findings, and certificates into one asset view
- rank likely-high-value targets with explainable reasons
- preserve analyst annotations so context survives across reruns and handoffs
- detect drift between two recon snapshots without diffing raw tool output by hand

This repository is intentionally opinionated:

- it does not try to replace `subfinder`, `httpx`, `naabu`, `katana`, or `nuclei`
- it reduces noise after collection
- it preserves analyst judgment instead of hiding everything behind a black-box score

## Why This Exists

Most recon pipelines produce too much raw data and too little usable direction. SurfaceLens focuses on the painful middle:

- normalizing domains, hosts, IPs, URLs, technologies, ports, and findings
- correlating assets across tool outputs
- ranking likely-high-value targets such as auth surfaces, admin panels, exposed dashboards, APIs, and hosts with known findings
- exporting evidence a pentester can actually use in notes or reports

## MVP Scope

The current MVP supports:

- `subfinder` style subdomain inputs from text or JSONL
- `httpx` style URL metadata from JSONL
- `nuclei` style findings from JSONL
- `katana` style URLs from text or JSONL
- `naabu` style port data from text or JSONL
- `nmap` style service and TLS metadata from JSONL
- asset graph generation
- heuristic target ranking
- snapshot diffing between two recon runs
- analyst annotations and config-driven scoring/tagging
- lightweight HTML dashboard export
- Markdown, JSON, and CSV exports

## Example Workflow

Quick start:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

surfacelens analyze \
  --input-dir sample_data \
  --output-dir output
```

Or without installation:

```bash
PYTHONPATH=src python3 -m surfacelens.cli analyze \
  --input-dir sample_data \
  --output-dir output \
  --config sample_data/example-config.json \
  --annotations sample_data/example-annotations.json \
  --print-summary
```

Compare two runs:

```bash
PYTHONPATH=src python3 -m surfacelens.cli diff \
  --old-input-dir sample_data/baseline \
  --new-input-dir sample_data \
  --output-dir diff-output \
  --print-summary
```

Artifacts:

- `output/summary.json`
- `output/assets.csv`
- `output/interesting_targets.md`
- `output/findings_candidates.md`
- `output/asset_graph.json`
- `output/dashboard.html`
- `diff-output/diff_summary.json`
- `diff-output/diff_report.md`

Recommended first demo:

```bash
PYTHONPATH=src python3 -m surfacelens.cli analyze \
  --input-dir sample_data \
  --output-dir demo-output \
  --config sample_data/example-config.json \
  --annotations sample_data/example-annotations.json
open demo-output/dashboard.html
```

## Supported Input Conventions

SurfaceLens scans an input directory recursively and detects files by name:

- `*subfinder*.jsonl`, `*subfinder*.txt`
- `*httpx*.jsonl`
- `*nuclei*.jsonl`
- `*katana*.jsonl`, `*katana*.txt`
- `*naabu*.jsonl`, `*naabu*.txt`
- `*nmap*.jsonl`

This keeps the tool compatible with real recon folders instead of forcing a new scanner workflow.

## Analyst Controls

SurfaceLens can take two optional JSON files:

- a config file for host ignores, tag rules, and score rules
- an annotations file for analyst labels and notes keyed by host

This makes the tool usable for repeated client work where context matters and noisy assets need to be suppressed.

## Ranking Model

The score is intentionally heuristic and explainable. It currently increases based on:

- auth, admin, dashboard, and API indicators
- access-controlled responses
- known findings from `nuclei`
- unusual open ports and high-value services
- service fingerprinting and TLS certificate evidence
- path density and technology richness
- environment naming such as `dev`, `staging`, or `internal`

Every ranked target includes human-readable reasons in the Markdown and JSON outputs.
Priority and confidence are exported separately so score is not the only decision signal.

## Design Principles

- local-first by default
- standard library only for the MVP
- structured outputs suitable for reporting or future UI layers
- transparent heuristics that can be challenged and improved

## Demo

Run the bundled sample:

```bash
surfacelens analyze --input-dir sample_data --output-dir demo-output
cat demo-output/interesting_targets.md
```

And for drift detection:

```bash
PYTHONPATH=src python3 -m surfacelens.cli diff \
  --old-input-dir sample_data/baseline \
  --new-input-dir sample_data \
  --output-dir diff-output
cat diff-output/diff_report.md
```

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m compileall src
```

## Repository Guide

- Contribution workflow and standards: [CONTRIBUTING.md](/Users/cyberkareem/pentest/surfacelens/CONTRIBUTING.md)
- Planned work and milestones: [docs/BACKLOG.md](/Users/cyberkareem/pentest/surfacelens/docs/BACKLOG.md)
- Release notes: [CHANGELOG.md](/Users/cyberkareem/pentest/surfacelens/CHANGELOG.md)

## Roadmap

Near-term improvements are tracked in [ROADMAP.md](/Users/cyberkareem/pentest/surfacelens/ROADMAP.md).

## Interview Positioning

If you use this in job applications, the signal is not "I built another scanner." The signal is:

- I understand real pentest workflow pain
- I can design around analyst usability, not just raw collection
- I can turn recon into evidence and prioritization
- I know how to ship an extensible security tool, not only scripts

## License

MIT
