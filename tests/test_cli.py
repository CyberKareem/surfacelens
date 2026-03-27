from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest


class CliTests(unittest.TestCase):
    def test_diff_generates_summary(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        output_dir = Path(tempfile.mkdtemp(prefix="surfacelens-diff-"))
        try:
            result = subprocess.run(
                [
                    "python3",
                    "-m",
                    "surfacelens.cli",
                    "diff",
                    "--old-input-dir",
                    str(project_root / "sample_data" / "baseline"),
                    "--new-input-dir",
                    str(project_root / "sample_data"),
                    "--output-dir",
                    str(output_dir),
                    "--config",
                    str(project_root / "sample_data" / "example-config.json"),
                    "--annotations",
                    str(project_root / "sample_data" / "example-annotations.json"),
                    "--print-summary",
                ],
                cwd=project_root,
                env={**os.environ, "PYTHONPATH": "src"},
                check=True,
                capture_output=True,
                text=True,
            )
            summary = json.loads(result.stdout)
            self.assertIn("new_assets", summary)
            self.assertIn("auth.acme.test", summary["new_assets"])
            self.assertTrue((output_dir / "diff_report.md").exists())
        finally:
            for path in output_dir.glob("*"):
                path.unlink()
            output_dir.rmdir()

    def test_analyze_generates_dashboard(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        output_dir = Path(tempfile.mkdtemp(prefix="surfacelens-analyze-"))
        try:
            subprocess.run(
                [
                    "python3",
                    "-m",
                    "surfacelens.cli",
                    "analyze",
                    "--input-dir",
                    str(project_root / "sample_data"),
                    "--output-dir",
                    str(output_dir),
                    "--config",
                    str(project_root / "sample_data" / "example-config.json"),
                    "--annotations",
                    str(project_root / "sample_data" / "example-annotations.json"),
                ],
                cwd=project_root,
                env={**os.environ, "PYTHONPATH": "src"},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue((output_dir / "dashboard.html").exists())
            summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertIn("priority_breakdown", summary)
        finally:
            for path in output_dir.glob("*"):
                path.unlink()
            output_dir.rmdir()
