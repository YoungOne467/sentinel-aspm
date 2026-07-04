from typing import List, Dict, Any
from .interfaces import PluginCapabilityResolver, CapabilityDecision
from .registry import PluginRegistry
from core.database import AsyncSessionLocal, current_workspace
from sqlalchemy import text

HIGH_RISK_CAPABILITIES = {"filesystem:write", "network:external", "container:privileged"}

class DefaultCapabilityResolver(PluginCapabilityResolver):
    def __init__(self):
        # Hardcoded policies for now, could be dynamic later
        self._allowed_global = ["network:external", "network:internal", "filesystem:read", "filesystem:write", "secret:jira", "secret:github"]
        self.registry = PluginRegistry()
        
    async def validate(self, requested_capabilities: List[str], plugin_id: str, manifest_data: dict = None, signature_block: dict = None) -> CapabilityDecision:
        # 1. Trust validation
        if manifest_data:
            trusted = await self.registry.evaluate_trust(manifest_data, signature_block)
            if not trusted:
                from packages.audit.emitter import audit_emitter
                from packages.audit.events import CapabilityDeniedEvent
                await audit_emitter.emit(
                    CapabilityDeniedEvent(
                        name="CapabilityDenied",
                        payload={
                            "plugin_id": plugin_id,
                            "requested_capabilities": requested_capabilities,
                            "reason": "Plugin trust verification failed (signature mismatch or untrusted level)."
                        }
                    ),
                    actor="system"
                )
                return CapabilityDecision(
                    allowed=False,
                    denied_capabilities=requested_capabilities,
                    reason="Plugin trust verification failed: manifest is untrusted."
                )

        # 2. Capability checks
        denied = []
        for cap in requested_capabilities:
            if cap not in self._allowed_global:
                denied.append(cap)
                
        # 3. High-Risk Capability review check (workspace approval required)
        high_risk_requested = [cap for cap in requested_capabilities if cap in HIGH_RISK_CAPABILITIES]
        if high_risk_requested:
            workspace = current_workspace.get() or "default"
            async with AsyncSessionLocal() as session:
                stmt = text("""
                    SELECT 1 FROM workspace_capability_approvals 
                    WHERE workspace_id = :ws AND plugin_id = :plugin AND capability = :cap
                """)
                for cap in high_risk_requested:
                    res = await session.execute(stmt, {"ws": workspace, "plugin": plugin_id, "cap": cap})
                    if not res.fetchone():
                        if cap not in denied:
                            denied.append(cap)
                            
        if denied:
            from packages.audit.emitter import audit_emitter
            from packages.audit.events import CapabilityDeniedEvent
            await audit_emitter.emit(
                CapabilityDeniedEvent(
                    name="CapabilityDenied",
                    payload={
                        "plugin_id": plugin_id,
                        "requested_capabilities": requested_capabilities,
                        "reason": f"Capabilities {denied} are not approved or globally permitted."
                    }
                ),
                actor="system"
            )
            return CapabilityDecision(
                allowed=False,
                denied_capabilities=denied,
                reason=f"Capabilities not allowed by policy: {', '.join(denied)}"
            )
            
        return CapabilityDecision(
            allowed=True,
            denied_capabilities=[],
            reason="All capabilities authorized."
        )

# Global singleton
capability_resolver = DefaultCapabilityResolver()
