"""Shared attack-surface graph for stateful DAST scans."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any, Iterable
from urllib.parse import urldefrag, urljoin, urlparse

from core.surface_mapper import classify_high_value_path, normalize_discovered_url


def _stable_id(*parts: str) -> str:
    material = "|".join(parts)
    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _normalize_url(root_url: str, value: str | None) -> str | None:
    if not value:
        return None
    joined, _fragment = urldefrag(urljoin(root_url, str(value).strip()))
    parsed = urlparse(joined)
    if parsed.scheme not in ("http", "https", "ws", "wss"):
        return None
    return joined


@dataclass
class ScopePolicy:
    root_url: str
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_path_prefixes: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, root_url: str, scope: dict[str, Any] | None = None) -> "ScopePolicy":
        parsed_root = urlparse(root_url)
        raw = scope or {}
        allowed_hosts = {
            str(item).lower()
            for item in raw.get("allowed_hosts", [])
            if str(item).strip()
        }
        if not allowed_hosts and parsed_root.netloc:
            allowed_hosts.add(parsed_root.netloc.lower())
        prefixes = tuple(str(item).strip() for item in raw.get("allowed_path_prefixes", []) if str(item).strip())
        excluded = tuple(str(item).strip() for item in raw.get("excluded_paths", []) if str(item).strip())
        return cls(root_url=root_url, allowed_hosts=allowed_hosts, allowed_path_prefixes=prefixes, excluded_paths=excluded)

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        if self.allowed_hosts and parsed.netloc.lower() not in self.allowed_hosts:
            return False
        path = parsed.path or "/"
        if self.allowed_path_prefixes and not any(path.startswith(prefix) for prefix in self.allowed_path_prefixes):
            return False
        if self.excluded_paths and any(path.startswith(prefix) for prefix in self.excluded_paths):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_hosts": sorted(self.allowed_hosts),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "excluded_paths": list(self.excluded_paths),
        }


class ScanSurfaceGraph:
    """In-memory graph of discovered target surface for one scan."""

    def __init__(self, root_url: str, scope: dict[str, Any] | None = None):
        self.root_url = root_url
        self.scope = ScopePolicy.from_dict(root_url, scope)
        self._nodes: dict[str, dict[str, Any]] = {}
        self._key_to_id: dict[tuple[str, str, str], str] = {}

    def add_node(
        self,
        kind: str,
        url: str,
        *,
        method: str = "GET",
        source: str = "scanner",
        classification: str | None = None,
        params: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        normalized_url = _normalize_url(self.root_url, url)
        if not normalized_url or not self.scope.allows(normalized_url):
            return None

        method = str(method or "GET").upper()
        kind = str(kind or "page").lower()
        key = (kind, method, normalized_url)
        if key in self._key_to_id:
            node_id = self._key_to_id[key]
            node = self._nodes[node_id]
            if classification and not node.get("classification"):
                node["classification"] = classification
            if source and source not in node["sources"]:
                node["sources"].append(source)
            node["params"] = sorted(set(node.get("params") or []) | {str(item) for item in (params or [])})
            node["metadata"].update(metadata or {})
            return node_id

        node_id = _stable_id(kind, method, normalized_url)
        node = {
            "id": node_id,
            "kind": kind,
            "url": normalized_url,
            "method": method,
            "classification": classification or classify_high_value_path(normalized_url) or "unclassified",
            "params": sorted({str(item) for item in (params or []) if str(item).strip()}),
            "sources": [source] if source else [],
            "metadata": dict(metadata or {}),
        }
        self._nodes[node_id] = node
        self._key_to_id[key] = node_id
        return node_id

    def merge_surface(self, source_url: str, surface: dict[str, Any]) -> None:
        for link in surface.get("links") or []:
            normalized = normalize_discovered_url(source_url, link)
            if normalized:
                self.add_node("page", normalized, source="crawler")
        for script in surface.get("scripts") or []:
            normalized = normalize_discovered_url(source_url, script)
            if normalized:
                self.add_node("script", normalized, source="crawler")
        for form in surface.get("forms") or []:
            action = form.get("action") or source_url
            self.add_node(
                "form",
                action,
                method=form.get("method") or "GET",
                source="crawler",
                params=form.get("inputs") or [],
                metadata={"source_url": source_url},
            )
        for endpoint in surface.get("api_candidates") or []:
            normalized = normalize_discovered_url(source_url, endpoint)
            if normalized:
                self.add_node("api", normalized, source="client_code")

    def targets(
        self,
        *,
        kinds: set[str] | None = None,
        classifications: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        wanted_kinds = {item.lower() for item in kinds} if kinds else None
        wanted_classes = {item.lower() for item in classifications} if classifications else None
        nodes = []
        for node in self._nodes.values():
            if wanted_kinds and node["kind"] not in wanted_kinds:
                continue
            if wanted_classes and str(node.get("classification", "")).lower() not in wanted_classes:
                continue
            nodes.append(dict(node))
        return sorted(nodes, key=lambda item: (item["kind"], item["url"], item["method"]))

    def to_dict(self) -> dict[str, Any]:
        nodes = self.targets()
        return {
            "root_url": self.root_url,
            "scope": self.scope.to_dict(),
            "node_count": len(nodes),
            "nodes": nodes,
            "counts_by_kind": {
                kind: sum(1 for node in nodes if node["kind"] == kind)
                for kind in sorted({node["kind"] for node in nodes})
            },
        }


def response_fingerprint(response: Any) -> str:
    status = str(getattr(response, "status_code", ""))
    text = getattr(response, "text", "") or ""
    body_hash = hashlib.sha256(text[:4096].encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{status}:{len(text)}:{body_hash}"


def response_step(phase: str, response: Any, *, method: str = "GET", url: str | None = None, identity: str | None = None) -> dict[str, Any]:
    return {
        "phase": phase,
        "method": method,
        "url": url or str(getattr(getattr(response, "request", None), "url", "")),
        "identity": identity or "unknown",
        "status_code": getattr(response, "status_code", None),
        "body_fingerprint": response_fingerprint(response),
    }


def build_proof_chain(
    *,
    baseline: dict[str, Any],
    mutation: dict[str, Any],
    verdict: str,
) -> list[dict[str, Any]]:
    baseline_step = {"phase": "baseline", **baseline}
    mutation_step = {"phase": "mutation", **mutation}
    return [
        baseline_step,
        mutation_step,
        {"phase": "verdict", "summary": verdict},
    ]
