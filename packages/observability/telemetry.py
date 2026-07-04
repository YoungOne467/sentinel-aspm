import logging
import contextlib
from typing import Dict, Any, Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.trace import Span, get_current_span

logger = logging.getLogger(__name__)

# Initialize default TracerProvider (Console for OSS default, can target OTLP gRPC endpoint)
_provider = TracerProvider()
_processor = SimpleSpanProcessor(ConsoleSpanExporter())
_provider.add_span_processor(_processor)
trace.set_tracer_provider(_provider)

tracer = trace.get_tracer("sentinel")

@contextlib.contextmanager
def trace_boundary(
    span_name: str,
    tenant_id: str = "default",
    workspace_id: Optional[str] = None,
    user_id: Optional[str] = None,
    plugin_id: Optional[str] = None,
    runtime_type: Optional[str] = None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    policy_name: Optional[str] = None,
    node_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    runtime_version: Optional[str] = None
) -> Span:
    """Enforces standard span attributes across all bounded context boundaries."""
    with tracer.start_as_current_span(span_name) as span:
        # Enforce strategic unified trace attributes
        span.set_attribute("tenant_id", tenant_id)
        if workspace_id: span.set_attribute("workspace_id", workspace_id)
        if user_id: span.set_attribute("user_id", user_id)
        if plugin_id: span.set_attribute("plugin_id", plugin_id)
        if runtime_type: span.set_attribute("runtime_type", runtime_type)
        if provider: span.set_attribute("provider", provider)
        if model: span.set_attribute("model", model)
        if policy_name: span.set_attribute("policy_name", policy_name)
        if node_id: span.set_attribute("node_id", node_id)
        if execution_id: span.set_attribute("execution_id", execution_id)
        if runtime_version: span.set_attribute("runtime_version", runtime_version)
        yield span

@contextlib.contextmanager
def trace_execution_span(
    tenant_id: str,
    workspace_id: str,
    execution_id: str,
    node_id: str,
    runtime_type: str,
    runtime_version: str,
    contract_id: str,
    scheduler_version: str,
    node_version: str,
    span_name: str = "execute_sandbox",
    plugin_id: Optional[str] = None
) -> Span:
    """Enforces that all 9 mandatory execution span attributes are present and non-empty."""
    attrs = {
        "tenant_id": tenant_id,
        "workspace_id": workspace_id,
        "execution_id": execution_id,
        "node_id": node_id,
        "runtime_type": runtime_type,
        "runtime_version": runtime_version,
        "contract_id": contract_id,
        "scheduler_version": scheduler_version,
        "node_version": node_version
    }
    for key, val in attrs.items():
        if not val or str(val).strip() == "":
            raise ValueError(f"Execution span attribute '{key}' is mandatory and cannot be empty")
            
    with trace_boundary(
        span_name=span_name,
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        execution_id=execution_id,
        node_id=node_id,
        runtime_type=runtime_type,
        runtime_version=runtime_version,
        plugin_id=plugin_id
    ) as span:
        span.set_attribute("contract_id", contract_id)
        span.set_attribute("scheduler_version", scheduler_version)
        span.set_attribute("node_version", node_version)
        yield span

def get_trace_context_payload() -> Dict[str, str]:
    """Helper to extract active span details for event/message correlation payloads."""
    span = get_current_span()
    ctx = span.get_span_context()
    if ctx.is_valid:
        return {
            "trace_id": format(ctx.trace_id, '032x'),
            "span_id": format(ctx.span_id, '016x')
        }
    return {}
