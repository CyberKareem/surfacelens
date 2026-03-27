from __future__ import annotations

import json
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def _read_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_subfinder(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        if path.suffix.lower() in {".jsonl", ".json"}:
            for item in _read_jsonl(path):
                host = item.get("host") or item.get("input")
                if host:
                    records.append({"host": host, "source": str(path)})
        else:
            for line in _read_lines(path):
                records.append({"host": line, "source": str(path)})
    return records


def load_httpx(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        if path.suffix.lower() not in {".jsonl", ".json"}:
            continue
        for item in _read_jsonl(path):
            records.append(item | {"source": str(path)})
    return records


def load_nuclei(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        if path.suffix.lower() not in {".jsonl", ".json"}:
            continue
        for item in _read_jsonl(path):
            records.append(item | {"source": str(path)})
    return records


def load_katana(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        if path.suffix.lower() in {".jsonl", ".json"}:
            for item in _read_jsonl(path):
                url = item.get("url") or item.get("request", {}).get("endpoint")
                if url:
                    records.append({"url": url, "source": str(path)})
        else:
            for line in _read_lines(path):
                records.append({"url": line, "source": str(path)})
    return records


def load_naabu(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        if path.suffix.lower() in {".jsonl", ".json"}:
            for item in _read_jsonl(path):
                host = item.get("host") or item.get("ip")
                port = item.get("port")
                if host and port is not None:
                    records.append(item | {"host": host, "port": port, "source": str(path)})
        else:
            for line in _read_lines(path):
                if ":" not in line:
                    continue
                host, port = line.rsplit(":", 1)
                records.append({"host": host, "port": port, "source": str(path)})
    return records


def load_nmap(paths: list[Path]) -> list[dict]:
    records: list[dict] = []
    for path in paths:
        if path.suffix.lower() not in {".jsonl", ".json"}:
            continue
        for item in _read_jsonl(path):
            host = item.get("host") or item.get("ip")
            if host:
                records.append(item | {"host": host, "source": str(path)})
    return records
