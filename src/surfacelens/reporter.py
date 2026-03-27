from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import Asset, SnapshotDiff


def export_reports(assets: dict[str, Asset], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    sorted_assets = sorted(assets.values(), key=lambda asset: asset.score, reverse=True)

    summary = {
        "schema_version": "0.1",
        "asset_count": len(sorted_assets),
        "top_targets": [asset.host for asset in sorted_assets[:10]],
        "finding_count": sum(len(asset.findings) for asset in sorted_assets),
        "open_port_count": sum(len(asset.ports) for asset in sorted_assets),
        "certificate_count": sum(len(asset.certificates) for asset in sorted_assets),
        "priority_breakdown": _count_values(asset.priority for asset in sorted_assets),
        "confidence_breakdown": _count_values(asset.confidence for asset in sorted_assets),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (output_dir / "asset_graph.json").write_text(
        json.dumps({"assets": [asset.to_dict() for asset in sorted_assets]}, indent=2),
        encoding="utf-8",
    )

    with (output_dir / "assets.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "host",
                "root_domain",
                "score",
                "priority",
                "confidence",
                "tags",
                "analyst_labels",
                "status_codes",
                "tech",
                "services",
                "certificates",
                "urls",
                "findings",
            ],
        )
        writer.writeheader()
        for asset in sorted_assets:
            writer.writerow(
                {
                    "host": asset.host,
                    "root_domain": asset.root_domain,
                    "score": asset.score,
                    "priority": asset.priority,
                    "confidence": asset.confidence,
                    "tags": ",".join(sorted(asset.tags)),
                    "analyst_labels": ",".join(sorted(asset.analyst_labels)),
                    "status_codes": ",".join(map(str, sorted(asset.status_codes))),
                    "tech": ",".join(sorted(asset.tech)),
                    "services": ",".join(
                        sorted(f"{service.port}/{service.protocol}:{service.service or service.product or 'unknown'}" for service in asset.services)
                    ),
                    "certificates": ",".join(
                        sorted(certificate.subject_cn or certificate.issuer_cn or "unknown" for certificate in asset.certificates)
                    ),
                    "urls": ",".join(sorted(asset.urls)),
                    "findings": ",".join(finding.name for finding in asset.findings),
                }
            )

    interesting_lines = ["# Interesting Targets", ""]
    for index, asset in enumerate(sorted_assets[:15], start=1):
        interesting_lines.append(
            f"## {index}. {asset.host} (score: {asset.score}, priority: {asset.priority}, confidence: {asset.confidence})"
        )
        interesting_lines.append(f"- Root domain: `{asset.root_domain}`")
        if asset.tags:
            interesting_lines.append(f"- Tags: {', '.join(sorted(asset.tags))}")
        if asset.analyst_labels:
            interesting_lines.append(f"- Analyst labels: {', '.join(sorted(asset.analyst_labels))}")
        if asset.analyst_notes:
            interesting_lines.append(f"- Analyst notes: {' | '.join(asset.analyst_notes[:3])}")
        if asset.urls:
            interesting_lines.append(f"- URLs: {', '.join(sorted(asset.urls)[:5])}")
        if asset.tech:
            interesting_lines.append(f"- Tech: {', '.join(sorted(asset.tech))}")
        if asset.services:
            interesting_lines.append(
                f"- Services: {', '.join(sorted(f'{service.port}/{service.protocol}:{service.service or service.product or 'unknown'}' for service in asset.services)[:5])}"
            )
        if asset.certificates:
            interesting_lines.append(
                f"- Certificates: {', '.join(sorted(certificate.subject_cn or certificate.issuer_cn or 'unknown' for certificate in asset.certificates)[:3])}"
            )
        if asset.findings:
            interesting_lines.append(
                f"- Findings: {', '.join(f'{finding.severity}:{finding.name}' for finding in asset.findings[:5])}"
            )
        if asset.reasons:
            interesting_lines.append(f"- Reasons: {', '.join(asset.reasons)}")
        interesting_lines.append("")
    (output_dir / "interesting_targets.md").write_text("\n".join(interesting_lines), encoding="utf-8")

    findings_lines = ["# Finding Candidates", ""]
    for asset in sorted_assets:
        if not asset.findings:
            continue
        findings_lines.append(f"## {asset.host}")
        for finding in asset.findings:
            findings_lines.append(
                f"- `{finding.severity}` {finding.name} via `{finding.tool}` at `{finding.matched_at or asset.host}`"
            )
        findings_lines.append("")
    (output_dir / "findings_candidates.md").write_text("\n".join(findings_lines), encoding="utf-8")
    (output_dir / "dashboard.html").write_text(build_html_dashboard(sorted_assets, summary), encoding="utf-8")


def export_diff_report(diff: SnapshotDiff, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "diff_summary.json").write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")

    lines = ["# Snapshot Diff", ""]
    lines.append(f"- New assets: {len(diff.new_assets)}")
    lines.append(f"- Removed assets: {len(diff.removed_assets)}")
    lines.append(f"- Changed assets: {len(diff.changed_assets)}")
    lines.append(f"- Unchanged assets: {len(diff.unchanged_assets)}")
    lines.append("")

    if diff.new_assets:
        lines.append("## New Assets")
        for host in diff.new_assets:
            lines.append(f"- `{host}`")
        lines.append("")

    if diff.removed_assets:
        lines.append("## Removed Assets")
        for host in diff.removed_assets:
            lines.append(f"- `{host}`")
        lines.append("")

    if diff.changed_assets:
        lines.append("## Changed Assets")
        for item in diff.changed_assets:
            lines.append(f"### {item['host']}")
            for change in item["changes"]:
                lines.append(f"- {change}")
            lines.append("")

    (output_dir / "diff_report.md").write_text("\n".join(lines), encoding="utf-8")


def _count_values(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def build_html_dashboard(sorted_assets: list[Asset], summary: dict) -> str:
    cards = []
    for asset in sorted_assets[:20]:
        cards.append(
            f"""
            <article class="card priority-{asset.priority}">
              <h2>{asset.host}</h2>
              <p class="meta">score {asset.score} · {asset.priority} priority · {asset.confidence} confidence</p>
              <p><strong>Tags:</strong> {", ".join(sorted(asset.tags)) or "none"}</p>
              <p><strong>Labels:</strong> {", ".join(sorted(asset.analyst_labels)) or "none"}</p>
              <p><strong>Top reasons:</strong> {", ".join(asset.reasons[:4]) or "none"}</p>
            </article>
            """.strip()
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SurfaceLens Dashboard</title>
  <style>
    :root {{
      --bg: #f5f1e8;
      --ink: #1f1e1a;
      --muted: #6f6a5f;
      --panel: #fffdf8;
      --line: #ddd2bd;
      --critical: #9f2a2a;
      --high: #cc6b28;
      --medium: #b69121;
      --low: #467249;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, "Times New Roman", serif; background: radial-gradient(circle at top, #fff8e8, var(--bg)); color: var(--ink); }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 60px; }}
    .hero {{ margin-bottom: 28px; }}
    .hero h1 {{ margin: 0 0 8px; font-size: 3rem; }}
    .hero p {{ color: var(--muted); max-width: 760px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 24px 0 32px; }}
    .stat, .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 16px; box-shadow: 0 12px 30px rgba(67, 45, 9, 0.06); }}
    .card-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }}
    .meta {{ color: var(--muted); }}
    .priority-critical {{ border-left: 8px solid var(--critical); }}
    .priority-high {{ border-left: 8px solid var(--high); }}
    .priority-medium {{ border-left: 8px solid var(--medium); }}
    .priority-low {{ border-left: 8px solid var(--low); }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>SurfaceLens</h1>
      <p>Analyst-first attack surface triage dashboard generated from local recon evidence.</p>
    </section>
    <section class="stats">
      <div class="stat"><strong>Assets</strong><br>{summary["asset_count"]}</div>
      <div class="stat"><strong>Findings</strong><br>{summary["finding_count"]}</div>
      <div class="stat"><strong>Open ports</strong><br>{summary["open_port_count"]}</div>
      <div class="stat"><strong>Certificates</strong><br>{summary["certificate_count"]}</div>
      <div class="stat"><strong>Priority mix</strong><br>{", ".join(f"{k}:{v}" for k, v in summary["priority_breakdown"].items())}</div>
    </section>
    <section class="card-grid">
      {"".join(cards)}
    </section>
  </main>
</body>
</html>
"""
