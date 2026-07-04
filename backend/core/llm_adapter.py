import os
import re
import json
import httpx
import logging
from typing import Optional, List
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# --- Structured Pydantic Response Schemas ---

class ExecutableAction(BaseModel):
    action_type: str = Field(description="Type of action, e.g., 'curl', 'bash', 'patch'")
    title: str = Field(description="Short description of the action")
    command: Optional[str] = Field(description="The shell command or curl execution request", default=None)
    patch_content: Optional[str] = Field(description="Diff code patch contents if action is patching", default=None)
    target_file: Optional[str] = Field(description="File destination to apply the patch", default=None)

class ExploitAnalysisResponse(BaseModel):
    summary: str = Field(description="Detailed analysis of exploit execution and observations")
    vulnerability_detected: bool = Field(description="True if vulnerability verification is confirmed")
    risk_score: float = Field(description="Risk assessment score from 0.0 (none) to 10.0 (critical)")
    remediation_steps: List[str] = Field(description="Bullet-point instructions to patch the issue")
    actions: List[ExecutableAction] = Field(default_factory=list, description="Structured actions for automated validation/mitigation")

# --- Token Optimization Utility ---

def compress_http_response(raw_text: str, max_chars: int = 1500) -> str:
    """Optimizes raw HTTP/HTML payload inputs to reduce token consumption."""
    if not raw_text:
        return ""
    
    try:
        # Strip simple headers block if present
        if "\r\n\r\n" in raw_text or "\n\n" in raw_text:
            parts = re.split(r'(?:\r?\n){2}', raw_text, 1)
            headers, body = parts[0], parts[1]
            
            # Strip standard generic headers
            filtered_headers = []
            for line in headers.splitlines():
                lower_line = line.lower()
                if not any(lower_line.startswith(h) for h in [
                    "date:", "server:", "connection:", "content-length:",
                    "x-powered-by:", "keep-alive:", "etag:", "cache-control:"
                ]):
                    filtered_headers.append(line)
            
            # Clean body
            body_clean = body.strip()
            if (body_clean.startswith("{") and body_clean.endswith("}")) or \
               (body_clean.startswith("[") and body_clean.endswith("]")):
                try:
                    body_clean = json.dumps(json.loads(body_clean), separators=(',', ':'))
                except Exception:
                    pass
            else:
                body_clean = re.sub(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "", body_clean, flags=re.IGNORECASE)
                body_clean = re.sub(r"<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>", "", body_clean, flags=re.IGNORECASE)
                body_clean = re.sub(r"<!--[\s\S]*?-->", "", body_clean)
                body_clean = re.sub(r"\s+", " ", body_clean)
            
            raw_text = "\n".join(filtered_headers) + "\n\n" + body_clean
        else:
            body_clean = raw_text.strip()
            if (body_clean.startswith("{") and body_clean.endswith("}")) or \
               (body_clean.startswith("[") and body_clean.endswith("]")):
                try:
                    body_clean = json.dumps(json.loads(body_clean), separators=(',', ':'))
                except Exception:
                    pass
            else:
                body_clean = re.sub(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "", body_clean, flags=re.IGNORECASE)
                body_clean = re.sub(r"<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>", "", body_clean, flags=re.IGNORECASE)
                body_clean = re.sub(r"<!--[\s\S]*?-->", "", body_clean)
                body_clean = re.sub(r"\s+", " ", body_clean)
            raw_text = body_clean
    except Exception:
        pass
        
    if len(raw_text) > max_chars:
        return raw_text[:max_chars] + "\n...[TRUNCATED FOR TOKEN OPTIMIZATION]..."
    return raw_text


class LLMAdapter:
    """Unified adapter layer supporting local Ollama, OpenAI, Anthropic, and other providers."""
    
    def __init__(self):
        pass

    async def _resolve_config(self):
        provider = os.getenv("AI_PROVIDER", "ollama").lower()
        model = os.getenv("AI_MODEL", "llama3")
        api_key = os.getenv("AI_API_KEY", "")
        base_url = os.getenv("AI_BASE_URL", "")

        try:
            from core.database import AsyncSessionLocal
            from core.models import PlatformSettings
            async with AsyncSessionLocal() as session:
                settings = await session.get(PlatformSettings, "default")
                if settings:
                    if provider == "openai" and settings.openai_key:
                        api_key = settings.openai_key
                    elif provider == "anthropic" and settings.anthropic_key:
                        api_key = settings.anthropic_key
                    
                    if provider == "ollama" and settings.ollama_base_url:
                        base_url = settings.ollama_base_url
        except Exception as e:
            logger.warning("Failed to resolve dynamic config from database: %s", e)

        return provider, api_key, model, base_url

    async def generate_response(self, prompt: str, system_prompt: str = "") -> str:
        provider, api_key, model, base_url = await self._resolve_config()
        if provider == "openai":
            return await self._call_openai(prompt, system_prompt, api_key, model, base_url)
        elif provider == "anthropic":
            return await self._call_anthropic(prompt, system_prompt, api_key, model, base_url)
        else:
            return await self._call_ollama(prompt, system_prompt, base_url, model)


    async def _call_ollama(self, prompt: str, system_prompt: str, base_url: str, model: str) -> str:
        url = base_url or os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
        # If generate is not in url, append it
        if not url.endswith(("/generate", "/chat")):
            url = url.rstrip("/") + "/api/generate"
            
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    return resp.json().get("response", "")
                else:
                    raise Exception(f"Ollama returned status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Ollama integration failure: {e}")
            return f"Ollama fallback error: {e}"

    async def _call_openai(self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str) -> str:
        url = base_url or "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    return resp.json()["choices"][0]["message"]["content"]
                else:
                    raise Exception(f"OpenAI returned status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"OpenAI API integration failure: {e}")
            return f"OpenAI integration error: {e}"

    async def _call_anthropic(self, prompt: str, system_prompt: str, api_key: str, model: str, base_url: str) -> str:
        url = base_url or "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    return resp.json()["content"][0]["text"]
                else:
                    raise Exception(f"Anthropic returned status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Anthropic API integration failure: {e}")
            return f"Anthropic integration error: {e}"

    async def generate_structured_response(self, prompt: str, system_prompt: str = "") -> ExploitAnalysisResponse:
        """Calls the configured LLM and enforces/validates a structured JSON response matching ExploitAnalysisResponse."""
        schema_instruction = (
            "\n\nCRITICAL DIRECTIVE: You MUST respond with a valid JSON object strictly matching this schema:\n"
            f"{json.dumps(ExploitAnalysisResponse.model_json_schema(), indent=2)}\n"
            "Do NOT wrap the JSON in markdown code blocks or any other characters. Respond ONLY with the raw JSON string."
        )
        compiled_prompt = prompt + schema_instruction
        
        raw_output = await self.generate_response(compiled_prompt, system_prompt)
        
        # Clean potential markdown wrapping
        cleaned = raw_output.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        
        try:
            parsed = json.loads(cleaned)
            return ExploitAnalysisResponse.model_validate(parsed)
        except Exception as e:
            logger.error("JSON parsing / Pydantic validation failed for LLM response: %s. Raw output: %s", e, raw_output)
            return ExploitAnalysisResponse(
                summary=f"Analysis engine execution completed, but the LLM output could not be parsed as a structured JSON object. Error: {str(e)}",
                vulnerability_detected=False,
                risk_score=0.0,
                remediation_steps=["Review engine logs to inspect raw AI output."],
                actions=[]
            )

# Singleton adapter
llm_adapter = LLMAdapter()
