from pathlib import Path
import json
import unittest

from surfacelens.analyzer import build_assets, diff_snapshots
from surfacelens.importers import load_httpx, load_katana, load_naabu, load_nmap, load_nuclei, load_subfinder


class AnalyzerTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1] / "sample_data"
        self.sample_paths = {
            "subfinder": root / "example-subfinder.txt",
            "httpx": root / "example-httpx.jsonl",
            "nuclei": root / "example-nuclei.jsonl",
            "katana": root / "example-katana.txt",
            "naabu": root / "example-naabu.jsonl",
            "nmap": root / "example-nmap.jsonl",
            "config": root / "example-config.json",
            "annotations": root / "example-annotations.json",
        }

    def test_build_assets_ranks_admin_and_auth_surfaces(self) -> None:
        assets = build_assets(
            subdomains=load_subfinder([self.sample_paths["subfinder"]]),
            httpx=load_httpx([self.sample_paths["httpx"]]),
            nuclei=load_nuclei([self.sample_paths["nuclei"]]),
            katana=load_katana([self.sample_paths["katana"]]),
            naabu=load_naabu([self.sample_paths["naabu"]]),
            nmap=load_nmap([self.sample_paths["nmap"]]),
            config=json.loads(self.sample_paths["config"].read_text(encoding="utf-8")),
            annotations=json.loads(self.sample_paths["annotations"].read_text(encoding="utf-8")),
        )

        self.assertIn("admin.acme.test", assets)
        self.assertIn("auth.acme.test", assets)
        self.assertNotIn("www.acme.test", assets)
        self.assertGreater(assets["admin.acme.test"].score, 0)
        self.assertIn("admin", assets["admin.acme.test"].tags)
        self.assertIn("auth", assets["auth.acme.test"].tags)
        self.assertIn("identity", assets["auth.acme.test"].tags)
        self.assertIn("watchlist", assets["auth.acme.test"].analyst_labels)
        self.assertEqual("critical", assets["api.acme.test"].priority)
        self.assertIn(8443, assets["admin.acme.test"].ports)
        self.assertTrue(assets["admin.acme.test"].certificates[0].self_signed)
        self.assertTrue(any(service.product == "Tomcat" for service in assets["admin.acme.test"].services))
        self.assertEqual(assets["grafana.acme.test"].findings[0].name, "Exposed Grafana Login Panel")

    def test_diff_snapshots_detects_new_assets_and_changes(self) -> None:
        current_assets = build_assets(
            subdomains=load_subfinder([self.sample_paths["subfinder"]]),
            httpx=load_httpx([self.sample_paths["httpx"]]),
            nuclei=load_nuclei([self.sample_paths["nuclei"]]),
            katana=load_katana([self.sample_paths["katana"]]),
            naabu=load_naabu([self.sample_paths["naabu"]]),
            nmap=load_nmap([self.sample_paths["nmap"]]),
            config=json.loads(self.sample_paths["config"].read_text(encoding="utf-8")),
            annotations=json.loads(self.sample_paths["annotations"].read_text(encoding="utf-8")),
        )
        baseline_root = Path(__file__).resolve().parents[1] / "sample_data" / "baseline"
        baseline_assets = build_assets(
            subdomains=load_subfinder([baseline_root / "example-subfinder.txt"]),
            httpx=load_httpx([baseline_root / "example-httpx.jsonl"]),
            nuclei=[],
            katana=load_katana([baseline_root / "example-katana.txt"]),
            naabu=load_naabu([baseline_root / "example-naabu.jsonl"]),
            nmap=load_nmap([baseline_root / "example-nmap.jsonl"]),
            config=json.loads(self.sample_paths["config"].read_text(encoding="utf-8")),
            annotations=json.loads(self.sample_paths["annotations"].read_text(encoding="utf-8")),
        )

        diff = diff_snapshots(baseline_assets, current_assets)
        self.assertIn("auth.acme.test", diff.new_assets)
        self.assertTrue(any(item["host"] == "admin.acme.test" for item in diff.changed_assets))


if __name__ == "__main__":
    unittest.main()
