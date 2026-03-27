from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import build_assets, diff_snapshots
from .config import load_json_file
from .importers import load_httpx, load_katana, load_naabu, load_nmap, load_nuclei, load_subfinder
from .reporter import export_diff_report, export_reports
from .utils import scan_input_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="surfacelens",
        description="Correlate recon outputs into prioritized attack surface intelligence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a recon directory and export reports.")
    analyze.add_argument("--input-dir", required=True, type=Path, help="Directory containing recon outputs.")
    analyze.add_argument("--output-dir", required=True, type=Path, help="Directory for exports.")
    analyze.add_argument("--config", type=Path, help="Optional JSON config for ignores, tags, and score rules.")
    analyze.add_argument("--annotations", type=Path, help="Optional JSON annotations for labels and notes.")
    analyze.add_argument("--print-summary", action="store_true", help="Print JSON summary to stdout.")

    diff = subparsers.add_parser("diff", help="Compare two recon directories and export reports.")
    diff.add_argument("--old-input-dir", required=True, type=Path, help="Baseline recon directory.")
    diff.add_argument("--new-input-dir", required=True, type=Path, help="Latest recon directory.")
    diff.add_argument("--output-dir", required=True, type=Path, help="Directory for diff exports.")
    diff.add_argument("--config", type=Path, help="Optional JSON config for ignores, tags, and score rules.")
    diff.add_argument("--annotations", type=Path, help="Optional JSON annotations for labels and notes.")
    diff.add_argument("--print-summary", action="store_true", help="Print JSON diff summary to stdout.")

    return parser


def load_assets_from_dir(input_dir: Path, config_path: Path | None = None, annotations_path: Path | None = None):
    files = scan_input_files(input_dir)
    config = load_json_file(config_path)
    annotations = load_json_file(annotations_path)
    return build_assets(
        subdomains=load_subfinder(files["subfinder"]),
        httpx=load_httpx(files["httpx"]),
        nuclei=load_nuclei(files["nuclei"]),
        katana=load_katana(files["katana"]),
        naabu=load_naabu(files["naabu"]),
        nmap=load_nmap(files["nmap"]),
        config=config,
        annotations=annotations,
    )


def run_analyze(
    input_dir: Path,
    output_dir: Path,
    print_summary: bool,
    config_path: Path | None = None,
    annotations_path: Path | None = None,
) -> int:
    assets = load_assets_from_dir(input_dir, config_path, annotations_path)
    export_reports(assets, output_dir)

    if print_summary:
        summary_path = output_dir / "summary.json"
        print(json.dumps(json.loads(summary_path.read_text(encoding="utf-8")), indent=2))
    return 0


def run_diff(
    old_input_dir: Path,
    new_input_dir: Path,
    output_dir: Path,
    print_summary: bool,
    config_path: Path | None = None,
    annotations_path: Path | None = None,
) -> int:
    old_assets = load_assets_from_dir(old_input_dir, config_path, annotations_path)
    new_assets = load_assets_from_dir(new_input_dir, config_path, annotations_path)
    diff = diff_snapshots(old_assets, new_assets)
    export_diff_report(diff, output_dir)

    if print_summary:
        summary_path = output_dir / "diff_summary.json"
        print(json.dumps(json.loads(summary_path.read_text(encoding="utf-8")), indent=2))
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "analyze":
        return run_analyze(args.input_dir, args.output_dir, args.print_summary, args.config, args.annotations)
    if args.command == "diff":
        return run_diff(
            args.old_input_dir,
            args.new_input_dir,
            args.output_dir,
            args.print_summary,
            args.config,
            args.annotations,
        )
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
