from __future__ import annotations

import json
from pathlib import Path


def load_json_file(path: Path | None) -> dict:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(f"config file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def matches_rule(asset_value: str, contains: str) -> bool:
    return contains.lower() in asset_value.lower()
