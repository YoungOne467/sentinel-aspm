import logging
import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import AsyncSessionLocal
from core.models import Finding
from core.llm_router import llm_router, AITaskType, ModelProvider
from core.ai_orchestrator import ai_orchestrator, ExecutableAction

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ai", tags=["AI Triage"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@router.get("/compile-prompt/{finding_id}")
async def compile_prompt(finding_id: str):
    """Compiles the raw prompt representation for a finding, with optimized context tokens, model choices and config."""
    res = await ai_orchestrator.compile_prompt_for_finding(finding_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res

@router.post("/execute-custom-prompt")
async def execute_custom_prompt(payload: dict):
    """Executes a user-edited prompt and returns the parsed Pydantic structured response with blast-radius assessments."""
    prompt = payload.get("prompt")
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt parameter is required")
        
    task_type = payload.get("task_type")
    override_provider = payload.get("provider")
    override_model = payload.get("model")
    force_override = payload.get("force_override", False)

    try:
        structured_res = await ai_orchestrator.execute_custom_prompt(
            prompt=prompt,
            task_type=task_type,
            override_provider=override_provider,
            override_model=override_model,
            force_override=force_override
        )
        return structured_res.model_dump()
    except Exception as e:
        logger.error("Failed executing custom prompt: %s", e)
        raise HTTPException(status_code=500, detail=f"AI Engine failure: {str(e)}")

@router.post("/analyze-finding/{finding_id}")
async def analyze_finding(finding_id: str, payload: dict = None):
    """Orchestrate the full analysis pipeline for a finding: compress, inject context, route, validate schema, sandbox."""
    payload = payload or {}
    override_provider = payload.get("provider")
    override_model = payload.get("model")
    force_override = payload.get("force_override", False)

    try:
        structured_res = await ai_orchestrator.analyze_finding(
            finding_id=finding_id,
            override_provider=override_provider,
            override_model=override_model,
            force_override=force_override
        )
        return structured_res.model_dump()
    except Exception as e:
        logger.error("Failed analyzing finding %s: %s", finding_id, e)
        raise HTTPException(status_code=500, detail=f"Analysis engine failure: {str(e)}")

@router.get("/routing-config")
async def get_routing_config():
    """Retrieve the routing matrix, cost ceilings, and model catalog."""
    try:
        return await llm_router.get_routing_config()
    except Exception as e:
        logger.error("Failed to retrieve routing config: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/execute/ad-hoc")
async def execute_ad_hoc(payload: dict):
    """Execute a single validated ExecutableAction inside an ephemeral Docker container."""
    from core.ai_orchestrator import docker_executor
    try:
        action = ExecutableAction.model_validate(payload)
    except Exception as parse_err:
        raise HTTPException(status_code=400, detail=f"Invalid ExecutableAction payload: {parse_err}")

    try:
        res = await docker_executor.execute(action)
        return res
    except Exception as e:
        logger.error("Failed executing ad-hoc payload: %s", e)
        raise HTTPException(status_code=500, detail=f"Execution engine failure: {str(e)}")

