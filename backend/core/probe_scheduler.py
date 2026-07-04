"""Adaptive module scheduling helpers for stateful DAST."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SURFACE_AWARE_HINTS = (
    "api",
    "graphql",
    "websocket",
    "upload",
    "cache",
    "ssrf",
    "business",
    "mass assignment",
    "jwt",
    "oauth",
)
DEEP_HINTS = (
    "blind",
    "smuggling",
    "desync",
    "oast",
    "ssrf",
    "waf",
    "template",
)


@dataclass(frozen=True)
class ProbeTask:
    module_name: str
    priority: int
    targets: list[dict[str, Any]]


def _target_kinds_for_module(module_name: str) -> set[str]:
    lowered = module_name.lower()
    if "graphql" in lowered:
        return {"api", "page"}
    if "websocket" in lowered:
        return {"websocket", "script", "page"}
    if "upload" in lowered:
        return {"form", "api", "page"}
    if any(token in lowered for token in ("api", "mass assignment", "jwt", "oauth", "business")):
        return {"api", "form", "page"}
    if any(token in lowered for token in ("cache", "ssrf", "injection", "blind", "template")):
        return {"api", "form", "page"}
    return set()


def _priority(module_name: str, target_count: int, intensity: str, penetration_depth: str) -> int:
    lowered = module_name.lower()
    priority = 50
    if any(token in lowered for token in SURFACE_AWARE_HINTS) and target_count:
        priority -= 25
    if any(token in lowered for token in DEEP_HINTS):
        priority += 20
    if penetration_depth == "maximum" and any(token in lowered for token in DEEP_HINTS):
        priority -= 35
    if intensity in ("aggressive", "extreme", "maximum") and any(token in lowered for token in SURFACE_AWARE_HINTS):
        priority -= 5
    return max(priority, 0)


def build_probe_plan(
    module_names: list[str],
    surface_graph: Any,
    *,
    intensity: str,
    penetration_depth: str = "deep",
) -> list[ProbeTask]:
    tasks: list[ProbeTask] = []
    for name in module_names:
        target_kinds = _target_kinds_for_module(name)
        targets = surface_graph.targets(kinds=target_kinds) if target_kinds and surface_graph else []
        priority = _priority(name, len(targets), intensity, penetration_depth)
        tasks.append(ProbeTask(module_name=name, priority=priority, targets=targets))
    return sorted(tasks, key=lambda task: (task.priority, task.module_name))
