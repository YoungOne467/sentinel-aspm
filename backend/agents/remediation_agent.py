import os
import asyncio
import json
import logging
import importlib
from pydantic import BaseModel

genai = None
try:
    _google_genai = importlib.import_module('google.genai')
    genai = _google_genai
except (ImportError, ModuleNotFoundError):
    genai = None

logger = logging.getLogger(__name__)

_GEMINI_API_KEYS = []
_key = os.getenv("GEMINI_API_KEY")
if _key:
    _GEMINI_API_KEYS.append(_key)
_key2 = os.getenv("GEMINI_API_KEY_2")
if _key2:
    _GEMINI_API_KEYS.append(_key2)
_current_key_index = 0

class RemediationReport(BaseModel):
    vuln_type: str
    explanation: str
    code_patch: str
    config_remediation: str
    remediation_steps: list[str]

class RemediationAgent:
    def __init__(self):
        self._ai_backoff_level = 0
        self.use_ai = bool(_GEMINI_API_KEYS and genai is not None)

    def _get_genai_client(self):
        global _current_key_index
        if not _GEMINI_API_KEYS:
            return None
        key = _GEMINI_API_KEYS[_current_key_index % len(_GEMINI_API_KEYS)]
        return genai.Client(api_key=key)

    def _rotate_api_key(self):
        global _current_key_index
        if len(_GEMINI_API_KEYS) > 1:
            _current_key_index = (_current_key_index + 1) % len(_GEMINI_API_KEYS)
            logger.info("Rotated Gemini API key: new slot %s", _current_key_index)
            return True
        return False

    async def _call_ai(self, prompt, response_schema=None, ai_model="gemini-2.0-flash"):
        if not _GEMINI_API_KEYS:
            return None

        max_total_retries = 5
        keys_tried_this_call = 0
        
        while self._ai_backoff_level < max_total_retries:
            try:
                client = self._get_genai_client()
                if not client: return None
                
                config = {}
                if response_schema:
                    config['response_mime_type'] = 'application/json'
                    config['response_schema'] = response_schema

                def _do_call():
                    return client.models.generate_content(
                        model=ai_model,
                        contents=prompt,
                        config=config
                    )
                
                response = await asyncio.get_event_loop().run_in_executor(None, _do_call)
                self._ai_backoff_level = 0
                return response

            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                    keys_tried_this_call += 1
                    if keys_tried_this_call < len(_GEMINI_API_KEYS):
                        self._rotate_api_key()
                        continue
                    
                    self._ai_backoff_level += 1
                    if self._ai_backoff_level > max_total_retries:
                        return None
                        
                    wait_time = (2 ** self._ai_backoff_level) * 10
                    await asyncio.sleep(wait_time)
                    keys_tried_this_call = 0
                else:
                    logger.error("AI Call failed: %s", err_str)
                    return None
        return None

    async def remediate(self, vuln_type: str, target_url: str, vector: str, payload: str, response_snippet: str = ""):
        """Analyzes a successful exploit and generates a comprehensive remediation report."""
        if not self.use_ai:
            logger.warning("AI features disabled. Cannot generate remediation report.")
            return None

        # Pass full raw snippet — no redaction, no truncation
        raw_response = response_snippet or ""
        
        prompt = f"""
You are an expert Application Security Engineer and Senior Developer.
An automated exploit was just successfully executed against a target.

Vulnerability Type: {vuln_type}
Target URL: {target_url}
Attack Vector: {vector}
Successful Payload: {payload}
Response Snippet: {raw_response}

Your task is to analyze this verified breach and provide a highly technical, actionable remediation report.
Output a JSON object matching the requested schema with the following fields:
- vuln_type: The name of the vulnerability.
- explanation: A clear, concise explanation of the root cause based on the payload and context.
- code_patch: A clean, language-agnostic or relevant secure code snippet that fixes the underlying issue (e.g., parameterized query, proper encoding, safe deserialization).
- config_remediation: Any server or infrastructure level configuration changes that would mitigate this (e.g., WAF rules, CSP headers).
- remediation_steps: An array of step-by-step instructions for developers to implement the fix.
"""
        try:
            logger.info("Generating Remediation Report for %s on %s...", vuln_type, target_url)
            response = await self._call_ai(prompt, response_schema=RemediationReport, ai_model="gemini-2.0-flash")
            
            if response and response.text:
                text = response.text.strip()
                if text.startswith("```json"):
                    text = text[7:]
                elif text.startswith("```"):
                    text = text[3:]
                if text.endswith("```"):
                    text = text[:-3]
                data = json.loads(text.strip())
                return data
        except json.JSONDecodeError as e:
            logger.error("Failed to parse Remediation Report JSON: %s | Raw Text: %s", e, response.text)
        except Exception as e:
            logger.error("Failed to generate remediation report: %s", e)
            
        return None

remediation_agent = RemediationAgent()
