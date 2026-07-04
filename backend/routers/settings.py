import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from core.database import AsyncSessionLocal
from core.models import PlatformSettings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["Settings"])

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

def mask_secret(value: str, prefix: str = "sk-") -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return prefix + "..."
    return f"{prefix}...{value[-4:]}"

@router.get("")
async def get_settings(db: AsyncSession = Depends(get_db)):
    """Fetch current platform settings (sensitive values are masked)."""
    try:
        stmt = select(PlatformSettings).where(PlatformSettings.id == "default")
        result = await db.execute(stmt)
        settings = result.scalar_one_or_none()
        
        if not settings:
            raise HTTPException(status_code=404, detail="Settings not initialized")
            
        return {
            "openai_key": mask_secret(settings.openai_key, "sk-"),
            "anthropic_key": mask_secret(settings.anthropic_key, "sk-"),
            "deepseek_key": mask_secret(settings.deepseek_key, "sk-"),
            "google_ai_key": mask_secret(settings.google_ai_key, "sk-"),
            "moonshot_key": mask_secret(settings.moonshot_key, "sk-"),
            "azure_ai_key": mask_secret(settings.azure_ai_key, "sk-"),
            "azure_ai_endpoint": settings.azure_ai_endpoint or "",
            "vllm_base_url": settings.vllm_base_url or "",
            "ollama_base_url": settings.ollama_base_url or "",
            "ai_routing_config": settings.ai_routing_config or {},
            "custom_headers": settings.custom_headers or [],
            "session_cookies": settings.session_cookies or [],
            "upstream_proxy": settings.upstream_proxy or "",
            "user_agent": settings.user_agent or "",
            "jira_host": settings.jira_host or "",
            "jira_email": settings.jira_email or "",
            "jira_pat": mask_secret(settings.jira_pat, "pat-"),
            "github_pat": mask_secret(settings.github_pat, "ghp-"),
            "discord_webhook": mask_secret(settings.discord_webhook, "disc-"),
            "slack_webhook": mask_secret(settings.slack_webhook, "slack-"),
            "max_concurrent_workers": settings.max_concurrent_workers,
            "rate_limit_rps": settings.rate_limit_rps,
            "global_blacklist": settings.global_blacklist or ""
        }
    except Exception as e:
        logger.error("Failed to retrieve settings: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve settings: {str(e)}")

@router.put("")
async def update_settings(payload: dict, db: AsyncSession = Depends(get_db)):
    """Save platform settings, ignoring masked placeholders."""
    try:
        stmt = select(PlatformSettings).where(PlatformSettings.id == "default")
        result = await db.execute(stmt)
        settings = result.scalar_one_or_none()
        
        if not settings:
            settings = PlatformSettings(id="default")
            db.add(settings)
        
        # Keys updating maps
        # Check if the submitted key is masked (contains '...'); if so, do not alter original value
        if "openai_key" in payload and "..." not in payload["openai_key"]:
            settings.openai_key = payload["openai_key"]
        if "anthropic_key" in payload and "..." not in payload["anthropic_key"]:
            settings.anthropic_key = payload["anthropic_key"]
        if "deepseek_key" in payload and "..." not in payload["deepseek_key"]:
            settings.deepseek_key = payload["deepseek_key"]
        if "google_ai_key" in payload and "..." not in payload["google_ai_key"]:
            settings.google_ai_key = payload["google_ai_key"]
        if "moonshot_key" in payload and "..." not in payload["moonshot_key"]:
            settings.moonshot_key = payload["moonshot_key"]
        if "azure_ai_key" in payload and "..." not in payload["azure_ai_key"]:
            settings.azure_ai_key = payload["azure_ai_key"]
        if "jira_pat" in payload and "..." not in payload["jira_pat"]:
            settings.jira_pat = payload["jira_pat"]
        if "github_pat" in payload and "..." not in payload["github_pat"]:
            settings.github_pat = payload["github_pat"]
        if "discord_webhook" in payload and "..." not in payload["discord_webhook"]:
            settings.discord_webhook = payload["discord_webhook"]
        if "slack_webhook" in payload and "..." not in payload["slack_webhook"]:
            settings.slack_webhook = payload["slack_webhook"]
            
        # Standard values
        if "azure_ai_endpoint" in payload:
            settings.azure_ai_endpoint = payload["azure_ai_endpoint"]
        if "vllm_base_url" in payload:
            settings.vllm_base_url = payload["vllm_base_url"]
        if "ai_routing_config" in payload:
            settings.ai_routing_config = payload["ai_routing_config"]
        if "ollama_base_url" in payload:
            settings.ollama_base_url = payload["ollama_base_url"]
        if "custom_headers" in payload:
            settings.custom_headers = payload["custom_headers"]
        if "session_cookies" in payload:
            settings.session_cookies = payload["session_cookies"]
        if "upstream_proxy" in payload:
            settings.upstream_proxy = payload["upstream_proxy"]
        if "user_agent" in payload:
            settings.user_agent = payload["user_agent"]
        if "jira_host" in payload:
            settings.jira_host = payload["jira_host"]
        if "jira_email" in payload:
            settings.jira_email = payload["jira_email"]
        if "max_concurrent_workers" in payload:
            settings.max_concurrent_workers = int(payload["max_concurrent_workers"])
        if "rate_limit_rps" in payload:
            settings.rate_limit_rps = int(payload["rate_limit_rps"])
        if "global_blacklist" in payload:
            settings.global_blacklist = payload["global_blacklist"]
            
        await db.commit()
        
        # Invalidate LLM router's settings cache
        try:
            from core.llm_router import llm_router
            llm_router.invalidate_cache()
        except Exception as cache_err:
            logger.warning("Could not invalidate LLM router cache: %s", cache_err)

        return {"status": "success", "message": "Settings updated successfully"}
    except Exception as e:
        await db.rollback()
        logger.error("Failed to save settings: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to save settings: {str(e)}")

@router.post("/test")
async def test_integration(payload: dict):
    """Test connection for a specific integration (jira, github, discord, slack)."""
    target = payload.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Integration target parameter is required")
        
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            if target == "discord":
                webhook_url = payload.get("url")
                if not webhook_url or "..." in webhook_url:
                    # Fallback to check DB
                    async with AsyncSessionLocal() as session:
                        settings = await session.get(PlatformSettings, "default")
                        webhook_url = settings.discord_webhook if settings else None
                if not webhook_url:
                    raise HTTPException(status_code=400, detail="Discord Webhook URL is missing")
                
                resp = await client.post(webhook_url, json={"content": "SENTINEL connection test: SUCCESS!"})
                if resp.status_code >= 400:
                    raise HTTPException(status_code=resp.status_code, detail=f"Discord webhook error: {resp.text}")
                return {"status": "success", "message": "Discord webhook connection tested successfully"}
                
            elif target == "slack":
                webhook_url = payload.get("url")
                if not webhook_url or "..." in webhook_url:
                    # Fallback
                    async with AsyncSessionLocal() as session:
                        settings = await session.get(PlatformSettings, "default")
                        webhook_url = settings.slack_webhook if settings else None
                if not webhook_url:
                    raise HTTPException(status_code=400, detail="Slack Webhook URL is missing")
                    
                resp = await client.post(webhook_url, json={"text": "SENTINEL connection test: SUCCESS!"})
                if resp.status_code >= 400:
                    raise HTTPException(status_code=resp.status_code, detail=f"Slack webhook error: {resp.text}")
                return {"status": "success", "message": "Slack webhook connection tested successfully"}
                
            elif target == "github":
                pat = payload.get("pat")
                if not pat or "..." in pat:
                    async with AsyncSessionLocal() as session:
                        settings = await session.get(PlatformSettings, "default")
                        pat = settings.github_pat if settings else None
                if not pat:
                    raise HTTPException(status_code=400, detail="GitHub Personal Access Token is missing")
                    
                headers = {"Authorization": f"Bearer {pat}"}
                resp = await client.get("https://api.github.com/user", headers=headers)
                if resp.status_code >= 400:
                    raise HTTPException(status_code=resp.status_code, detail=f"GitHub validation failed: {resp.text}")
                return {"status": "success", "message": "GitHub connection verified successfully"}
                
            elif target == "jira":
                host = payload.get("host")
                email = payload.get("email")
                pat = payload.get("pat")
                
                async with AsyncSessionLocal() as session:
                    settings = await session.get(PlatformSettings, "default")
                    if not host:
                        host = settings.jira_host if settings else None
                    if not email:
                        email = settings.jira_email if settings else None
                    if not pat or "..." in pat:
                        pat = settings.jira_pat if settings else None
                        
                if not host or not email or not pat:
                    raise HTTPException(status_code=400, detail="Jira integration fields are incomplete")
                    
                # Standard Jira basic auth call
                auth = (email, pat)
                resp = await client.get(f"{host.rstrip('/')}/rest/api/2/myself", auth=auth)
                if resp.status_code >= 400:
                    raise HTTPException(status_code=resp.status_code, detail=f"Jira verification failed: {resp.text}")
                return {"status": "success", "message": "Jira integration verified successfully"}
                
            else:
                raise HTTPException(status_code=400, detail=f"Unknown test integration target: {target}")
    except Exception as e:
        logger.error("Integration verification failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Integration verification failed: {str(e)}")
