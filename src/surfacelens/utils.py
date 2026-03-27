from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def scan_input_files(input_dir: Path) -> dict[str, list[Path]]:
    buckets = {
        "subfinder": [],
        "httpx": [],
        "nuclei": [],
        "katana": [],
        "naabu": [],
        "nmap": [],
    }
    for path in input_dir.rglob("*"):
        if not path.is_file():
            continue
        lowered = path.name.lower()
        for tool in buckets:
            if tool in lowered:
                buckets[tool].append(path)
                break
    return buckets


def normalize_host(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return value
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or value
    return value.split(":")[0]


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    parsed = urlparse(value)
    if not parsed.scheme:
        return value
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if parsed.query:
        return f"{parsed.scheme.lower()}://{netloc}{path}?{parsed.query}"
    return f"{parsed.scheme.lower()}://{netloc}{path}"


def infer_root_domain(host: str) -> str:
    parts = normalize_host(host).split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def safe_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None
