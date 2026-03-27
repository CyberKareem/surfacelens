from __future__ import annotations

from collections import Counter

from .models import Asset, Certificate, Finding, Service, SnapshotDiff
from .utils import infer_root_domain, normalize_host, normalize_url, safe_int


def build_assets(
    subdomains: list[dict],
    httpx: list[dict],
    nuclei: list[dict],
    katana: list[dict],
    naabu: list[dict],
    nmap: list[dict],
    config: dict | None = None,
    annotations: dict | None = None,
) -> dict[str, Asset]:
    assets: dict[str, Asset] = {}
    config = config or {}
    annotations = annotations or {}

    def get_asset(host: str) -> Asset:
        normalized = normalize_host(host)
        if normalized not in assets:
            assets[normalized] = Asset(host=normalized, root_domain=infer_root_domain(normalized))
        return assets[normalized]

    for item in subdomains:
        host = item["host"]
        asset = get_asset(host)
        asset.source_tools.add("subfinder")

    for item in httpx:
        url = item.get("url") or item.get("input")
        host = item.get("host") or url
        if not host:
            continue
        asset = get_asset(host)
        asset.source_tools.add("httpx")
        if url:
            asset.urls.add(normalize_url(url))
        for code_key in ("status_code", "status-code"):
            status_code = safe_int(item.get(code_key))
            if status_code is not None:
                asset.status_codes.add(status_code)
        title = item.get("title")
        if title:
            asset.titles.add(title.strip())
        tech = item.get("tech") or item.get("technologies") or []
        if isinstance(tech, list):
            asset.tech.update(str(value) for value in tech if value)
        elif tech:
            asset.tech.add(str(tech))
        ip = item.get("ip")
        if ip:
            asset.ips.add(str(ip))
        port = safe_int(item.get("port"))
        if port is not None:
            asset.ports.add(port)
        _attach_httpx_certificate(asset, item)

    for item in katana:
        url = item.get("url")
        if not url:
            continue
        asset = get_asset(url)
        asset.source_tools.add("katana")
        asset.urls.add(normalize_url(url))

    for item in nuclei:
        target = item.get("host") or item.get("matched-at") or item.get("url")
        if not target:
            continue
        asset = get_asset(target)
        asset.source_tools.add("nuclei")
        info = item.get("info", {})
        finding = Finding(
            tool="nuclei",
            name=info.get("name") or item.get("template-id") or "unknown-finding",
            severity=(info.get("severity") or "info").lower(),
            matcher=item.get("matcher-name"),
            description=info.get("description"),
            matched_at=item.get("matched-at"),
            tags=info.get("tags") or [],
        )
        asset.findings.append(finding)
        if finding.matched_at:
            asset.urls.add(normalize_url(finding.matched_at))

    for item in naabu:
        host = item.get("host")
        if not host:
            continue
        asset = get_asset(host)
        asset.source_tools.add("naabu")
        port = safe_int(item.get("port"))
        if port is not None:
            asset.ports.add(port)
            _append_service(
                asset,
                Service(
                    port=port,
                    protocol=str(item.get("protocol") or "tcp"),
                    state=str(item.get("state") or "open"),
                    service=str(item.get("service")) if item.get("service") else None,
                ),
            )
        ip = item.get("ip")
        if ip:
            asset.ips.add(str(ip))

    for item in nmap:
        host = item.get("host")
        if not host:
            continue
        asset = get_asset(host)
        asset.source_tools.add("nmap")
        ip = item.get("ip")
        if ip:
            asset.ips.add(str(ip))
        for port_item in item.get("ports", []):
            port = safe_int(port_item.get("port"))
            if port is None:
                continue
            asset.ports.add(port)
            _append_service(
                asset,
                Service(
                    port=port,
                    protocol=str(port_item.get("protocol") or "tcp"),
                    state=str(port_item.get("state") or "open"),
                    service=str(port_item.get("service")) if port_item.get("service") else None,
                    product=str(port_item.get("product")) if port_item.get("product") else None,
                    version=str(port_item.get("version")) if port_item.get("version") else None,
                ),
            )
        certificate = item.get("tls") or {}
        if certificate:
            _append_certificate(
                asset,
                Certificate(
                    subject_cn=certificate.get("subject_cn"),
                    issuer_cn=certificate.get("issuer_cn"),
                    sans=[str(entry) for entry in certificate.get("sans", []) if entry],
                    not_before=certificate.get("not_before"),
                    not_after=certificate.get("not_after"),
                    expired=bool(certificate.get("expired", False)),
                    self_signed=bool(certificate.get("self_signed", False)),
                ),
            )

    apply_annotations(assets, annotations)
    filtered_assets = apply_config_rules(assets, config)
    rank_assets(filtered_assets, config)
    return filtered_assets


def rank_assets(assets: dict[str, Asset], config: dict | None = None) -> None:
    config = config or {}
    auth_keywords = ("login", "auth", "oauth", "sso", "signin", "jwt", "account")
    admin_keywords = ("admin", "grafana", "jenkins", "kibana", "dashboard", "console")
    api_keywords = ("api", "graphql", "swagger", "openapi")
    high_value_ports = {22: "ssh", 443: "https", 3000: "dashboard", 5432: "postgres", 6379: "redis", 8000: "api"}
    sensitive_services = {"jenkins", "grafana", "kibana", "elasticsearch", "postgresql", "redis", "mongodb"}
    severity_weight = {"critical": 40, "high": 25, "medium": 15, "low": 7, "info": 3}

    for asset in assets.values():
        score = 0
        reasons: list[str] = []
        combined_text = " ".join([asset.host, *asset.urls, *asset.titles, *asset.tech]).lower()

        if any(keyword in combined_text for keyword in auth_keywords):
            score += 18
            reasons.append("auth surface detected")
            asset.tags.add("auth")

        if any(keyword in combined_text for keyword in admin_keywords):
            score += 20
            reasons.append("admin or dashboard indicators detected")
            asset.tags.add("admin")

        if any(keyword in combined_text for keyword in api_keywords):
            score += 14
            reasons.append("api surface detected")
            asset.tags.add("api")

        if 200 in asset.status_codes:
            score += 3
            reasons.append("live 200 response observed")
        if 401 in asset.status_codes or 403 in asset.status_codes:
            score += 7
            reasons.append("access-controlled endpoint observed")
        if 500 in asset.status_codes:
            score += 5
            reasons.append("server error observed")

        if len(asset.tech) >= 3:
            score += 4
            reasons.append("multi-technology host")

        if len(asset.urls) >= 5:
            score += 6
            reasons.append("multiple discovered paths")

        if len(asset.ports) >= 2:
            score += 4
            reasons.append("multiple exposed ports")

        unusual_ports = sorted(port for port in asset.ports if port not in {80, 443})
        if unusual_ports:
            score += min(12, len(unusual_ports) * 2)
            reasons.append(f"non-standard exposed ports: {', '.join(map(str, unusual_ports[:5]))}")

        matched_services = sorted(high_value_ports[port] for port in asset.ports if port in high_value_ports)
        if matched_services:
            score += min(10, len(matched_services) * 3)
            reasons.append(f"high-value services exposed: {', '.join(matched_services[:4])}")

        service_names = {
            value
            for service in asset.services
            for value in (service.service, service.product)
            if value
        }
        interesting_services = sorted(
            value for value in service_names if value.lower() in sensitive_services or any(k in value.lower() for k in ("vpn", "panel"))
        )
        if interesting_services:
            score += min(14, len(interesting_services) * 4)
            reasons.append(f"sensitive services identified: {', '.join(interesting_services[:4])}")

        if asset.certificates:
            score += 3
            reasons.append("tls certificate metadata collected")
            if any(certificate.self_signed for certificate in asset.certificates):
                score += 6
                reasons.append("self-signed certificate observed")
            if any(certificate.expired for certificate in asset.certificates):
                score += 8
                reasons.append("expired certificate observed")
            if any(
                any(token in san.lower() for token in ("internal", "dev", "staging"))
                for certificate in asset.certificates
                for san in certificate.sans
            ):
                score += 6
                reasons.append("certificate SANs expose non-production naming")

        if any(word in combined_text for word in ("staging", "dev", "internal", "test")):
            score += 8
            reasons.append("non-production naming indicators")
            asset.tags.add("environment")

        if asset.analyst_labels:
            score += min(10, len(asset.analyst_labels) * 3)
            reasons.append("analyst labels attached")

        for rule in config.get("score_rules", []):
            field = str(rule.get("field", "host"))
            contains = str(rule.get("contains", ""))
            delta = safe_int(rule.get("delta")) or 0
            reason = str(rule.get("reason", f"custom score rule on {field}"))
            haystack = " ".join(_collect_rule_values(asset, field))
            if contains and contains.lower() in haystack.lower():
                score += delta
                reasons.append(reason)

        severity_counts = Counter(finding.severity for finding in asset.findings)
        for severity, count in severity_counts.items():
            score += severity_weight.get(severity, 1) * count
            reasons.append(f"{count} {severity} nuclei finding(s)")

        asset.score = score
        asset.confidence = derive_confidence(asset)
        asset.priority = derive_priority(asset)
        asset.reasons = reasons


def diff_snapshots(old_assets: dict[str, Asset], new_assets: dict[str, Asset]) -> SnapshotDiff:
    old_hosts = set(old_assets)
    new_hosts = set(new_assets)
    changed_assets: list[dict] = []

    for host in sorted(old_hosts & new_hosts):
        before = old_assets[host]
        after = new_assets[host]
        changes: list[str] = []

        new_ports = sorted(after.ports - before.ports)
        removed_ports = sorted(before.ports - after.ports)
        new_urls = sorted(after.urls - before.urls)
        before_services = {_service_label(service) for service in before.services}
        new_services = sorted(_service_label(service) for service in after.services if _service_label(service) not in before_services)
        before_finding_names = {f"{item.severity}:{item.name}" for item in before.findings}
        new_findings = sorted(
            f"{item.severity}:{item.name}" for item in after.findings if f"{item.severity}:{item.name}" not in before_finding_names
        )
        if len(after.certificates) != len(before.certificates):
            changes.append(f"certificate count changed: {len(before.certificates)} -> {len(after.certificates)}")

        if new_ports:
            changes.append(f"new ports: {', '.join(map(str, new_ports))}")
        if removed_ports:
            changes.append(f"removed ports: {', '.join(map(str, removed_ports))}")
        if new_services:
            changes.append(f"new services: {', '.join(new_services[:5])}")
        if new_urls:
            changes.append(f"new urls: {', '.join(new_urls[:5])}")
        if new_findings:
            changes.append(f"new findings: {', '.join(new_findings[:5])}")
        if after.score != before.score:
            changes.append(f"score changed: {before.score} -> {after.score}")

        if changes:
            changed_assets.append({"host": host, "changes": changes, "new_score": after.score, "old_score": before.score})

    changed_hosts = {item["host"] for item in changed_assets}
    return SnapshotDiff(
        new_assets=sorted(new_hosts - old_hosts),
        removed_assets=sorted(old_hosts - new_hosts),
        changed_assets=changed_assets,
        unchanged_assets=sorted((old_hosts & new_hosts) - changed_hosts),
    )


def apply_annotations(assets: dict[str, Asset], annotations: dict) -> None:
    for host, details in annotations.items():
        normalized = normalize_host(host)
        asset = assets.get(normalized)
        if asset is None:
            continue
        labels = details.get("labels", [])
        notes = details.get("notes", [])
        asset.analyst_labels.update(str(label) for label in labels if label)
        asset.analyst_notes.extend(str(note) for note in notes if note)


def apply_config_rules(assets: dict[str, Asset], config: dict) -> dict[str, Asset]:
    ignore_hosts = [str(item).lower() for item in config.get("ignore_hosts", [])]
    ignore_root_domains = [str(item).lower() for item in config.get("ignore_root_domains", [])]
    filtered: dict[str, Asset] = {}

    for host, asset in assets.items():
        lowered_host = host.lower()
        if any(pattern in lowered_host for pattern in ignore_hosts):
            continue
        if asset.root_domain.lower() in ignore_root_domains:
            continue

        for rule in config.get("tag_rules", []):
            field = str(rule.get("field", "host"))
            contains = str(rule.get("contains", ""))
            tags = [str(tag) for tag in rule.get("tags", []) if tag]
            haystack = " ".join(_collect_rule_values(asset, field))
            if contains and contains.lower() in haystack.lower():
                asset.tags.update(tags)

        filtered[host] = asset

    return filtered


def _collect_rule_values(asset: Asset, field: str) -> list[str]:
    mapping = {
        "host": [asset.host],
        "root_domain": [asset.root_domain],
        "tech": list(asset.tech),
        "title": list(asset.titles),
        "url": list(asset.urls),
        "tag": list(asset.tags),
    }
    return mapping.get(field, [asset.host])


def derive_confidence(asset: Asset) -> str:
    evidence_points = 0
    evidence_points += len(asset.source_tools)
    evidence_points += min(3, len(asset.findings))
    evidence_points += 1 if asset.urls else 0
    evidence_points += 1 if asset.ports else 0
    evidence_points += 1 if asset.tech else 0
    evidence_points += 1 if asset.analyst_labels else 0
    evidence_points += 1 if asset.services else 0
    evidence_points += 1 if asset.certificates else 0

    if evidence_points >= 7:
        return "high"
    if evidence_points >= 4:
        return "medium"
    return "low"


def derive_priority(asset: Asset) -> str:
    if asset.score >= 60 or any(finding.severity in {"critical", "high"} for finding in asset.findings):
        return "critical"
    if asset.score >= 35:
        return "high"
    if asset.score >= 18:
        return "medium"
    return "low"


def _attach_httpx_certificate(asset: Asset, item: dict) -> None:
    tls = item.get("tls") or {}
    if not tls:
        return
    _append_certificate(
        asset,
        Certificate(
            subject_cn=tls.get("subject_cn"),
            issuer_cn=tls.get("issuer_cn"),
            sans=[str(entry) for entry in tls.get("sans", []) if entry],
            not_before=tls.get("not_before"),
            not_after=tls.get("not_after"),
            expired=bool(tls.get("expired", False)),
            self_signed=bool(tls.get("self_signed", False)),
        ),
    )


def _append_service(asset: Asset, service: Service) -> None:
    fingerprint = (service.port, service.protocol, service.service, service.product, service.version)
    existing = {
        (item.port, item.protocol, item.service, item.product, item.version)
        for item in asset.services
    }
    if fingerprint not in existing:
        asset.services.append(service)


def _append_certificate(asset: Asset, certificate: Certificate) -> None:
    fingerprint = (
        certificate.subject_cn,
        certificate.issuer_cn,
        tuple(sorted(certificate.sans)),
        certificate.not_before,
        certificate.not_after,
        certificate.expired,
        certificate.self_signed,
    )
    existing = {
        (
            item.subject_cn,
            item.issuer_cn,
            tuple(sorted(item.sans)),
            item.not_before,
            item.not_after,
            item.expired,
            item.self_signed,
        )
        for item in asset.certificates
    }
    if fingerprint not in existing:
        asset.certificates.append(certificate)


def _service_label(service: Service) -> str:
    detail_parts = [value for value in (service.service, service.product, service.version) if value]
    detail = "/".join(detail_parts) if detail_parts else "unknown"
    return f"{service.port}:{detail}"
