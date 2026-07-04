"""
GraphQL introspection fuzzer.
"""
from __future__ import annotations

import logging
from urllib.parse import urljoin
from typing import Any

import httpx

from core.database import AsyncSessionLocal
from core.models import Vulnerability

logger = logging.getLogger("sentinel.graphql_fuzzer")

GRAPHQL_ENDPOINTS = ("/graphql", "/api/graphql")
INTROSPECTION_QUERY = "{ __schema { types { name } } }"


async def fuzz_graphql_introspection(base_url: str, target_id: str | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
        for path in GRAPHQL_ENDPOINTS:
            endpoint = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            result = await probe_graphql_endpoint(client, endpoint, target_id)
            results.append(result)
            if result.get("schema_exposed"):
                break
    return results


async def probe_graphql_endpoint(client: httpx.AsyncClient, endpoint: str, target_id: str | None) -> dict[str, Any]:
    try:
        response = await client.post(endpoint, json={"query": INTROSPECTION_QUERY})
        response.raise_for_status()
        body = response.json()
    except Exception as exc:
        logger.debug("GraphQL introspection probe failed for %s: %s", endpoint, exc)
        return {"endpoint": endpoint, "schema_exposed": False, "mutations": [], "error": str(exc)}

    schema = body.get("data", {}).get("__schema") if isinstance(body, dict) else None
    if not isinstance(schema, dict):
        return {"endpoint": endpoint, "schema_exposed": False, "mutations": [], "raw": body}

    mutations = extract_mutations(schema)
    result = {
        "endpoint": endpoint,
        "schema_exposed": True,
        "mutations": mutations,
        "schema": schema,
    }
    await persist_graphql_finding(result, target_id)
    return result


def extract_mutations(schema: dict[str, Any]) -> list[str]:
    mutations: list[str] = []
    for type_info in schema.get("types") or []:
        if not isinstance(type_info, dict):
            continue
        name = str(type_info.get("name") or "")
        if "mutation" in name.lower() and name not in mutations:
            mutations.append(name)
    return mutations


async def persist_graphql_finding(result: dict[str, Any], target_id: str | None) -> None:
    evidence = (
        f"GraphQL endpoint {result['endpoint']} exposed introspection data. "
        f"Mutation-like types: {', '.join(result['mutations']) or 'none discovered'}."
    )
    async with AsyncSessionLocal() as session:
        session.add(
            Vulnerability(
                target_id=target_id,
                vuln_type="GraphQL Introspection",
                severity="high",
                title=f"Sensitive GraphQL introspection exposed: {result['endpoint']}",
                description="The GraphQL endpoint returned schema introspection data that can assist attackers.",
                evidence=evidence,
                source="graphql_fuzzer",
                raw_data=result,
            )
        )
        await session.commit()
