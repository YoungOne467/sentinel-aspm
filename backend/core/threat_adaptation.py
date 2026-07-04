"""Adaptive prioritization for stateful DAST scans."""

from __future__ import annotations

from typing import Any


HIGH_VALUE_TERMS = ("admin", "internal", "debug", "actuator", "graphql", "billing", "account", "settings")
OBJECT_ID_TERMS = ("id", "uuid", "user", "account", "tenant", "order", "invoice")
MODULE_ALIASES = {
    "authorization_matrix": ("authorization", "function level", "authz"),
    "api_resource_consumption": ("resource", "consumption", "limit"),
    "client_exposure": ("client", "exposure", "javascript", "source map"),
}


def _node_heat(node: dict[str, Any]) -> int:
    heat = 0
    url = str(node.get("url", "")).lower()
    classification = str(node.get("classification", "")).lower()
    params = [str(item).lower() for item in node.get("params", [])]
    if any(term in url for term in HIGH_VALUE_TERMS):
        heat += 4
    if classification in {"high_value_route", "user_data_route", "auth_flow"}:
        heat += 3
    if node.get("kind") == "api":
        heat += 2
    if node.get("kind") == "script":
        heat += 1
    if any(any(term in param for term in OBJECT_ID_TERMS) for param in params):
        heat += 2
    return heat


def build_adaptive_scan_summary(surface_graph, findings, auth_profiles, intensity: str) -> dict[str, Any]:
    nodes = surface_graph.targets() if surface_graph else []
    auth_profile_count = len(auth_profiles or {})
    surface_heat = sum(_node_heat(node) for node in nodes)
    recommended = []

    if auth_profile_count >= 2 or any(_node_heat(node) >= 6 for node in nodes):
        recommended.append("authorization_matrix")
    if any(node.get("kind") == "api" for node in nodes):
        recommended.append("api_resource_consumption")
    if any(node.get("kind") == "script" for node in nodes):
        recommended.append("client_exposure")
    if intensity in {"aggressive", "extreme"} and "api_resource_consumption" not in recommended:
        recommended.append("api_resource_consumption")

    top_nodes = sorted(nodes, key=_node_heat, reverse=True)[:8]
    return {
        "surface_heat": surface_heat,
        "auth_profile_count": auth_profile_count,
        "recommended_modules": recommended,
        "top_surface_nodes": [
            {
                "id": node.get("id"),
                "kind": node.get("kind"),
                "url": node.get("url"),
                "heat": _node_heat(node),
                "classification": node.get("classification"),
            }
            for node in top_nodes
            if _node_heat(node) > 0
        ],
    }


def module_priority_delta(module_name: str, adaptive_summary: dict[str, Any] | None) -> int:
    if not adaptive_summary:
        return 0
    lowered = module_name.lower()
    for recommended in adaptive_summary.get("recommended_modules") or []:
        aliases = MODULE_ALIASES.get(recommended, (recommended.replace("_", " "),))
        if any(alias in lowered for alias in aliases):
            return -25
    return 0
