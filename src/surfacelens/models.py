from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Finding:
    tool: str
    name: str
    severity: str
    matcher: str | None = None
    description: str | None = None
    matched_at: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Certificate:
    subject_cn: str | None = None
    issuer_cn: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    expired: bool = False
    self_signed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Asset:
    host: str
    root_domain: str
    urls: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    services: list[Service] = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)
    tech: set[str] = field(default_factory=set)
    titles: set[str] = field(default_factory=set)
    status_codes: set[int] = field(default_factory=set)
    source_tools: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    analyst_labels: set[str] = field(default_factory=set)
    analyst_notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    confidence: str = "low"
    priority: str = "low"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        for key in ("urls", "ips", "ports", "tech", "titles", "status_codes", "source_tools", "tags", "analyst_labels"):
            data[key] = sorted(data[key])
        data["services"] = [service.to_dict() for service in self.services]
        data["certificates"] = [certificate.to_dict() for certificate in self.certificates]
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass(slots=True)
class SnapshotDiff:
    new_assets: list[str]
    removed_assets: list[str]
    changed_assets: list[dict]
    unchanged_assets: list[str]

    def to_dict(self) -> dict:
        return asdict(self)
