import os
import httpx
import logging

logger = logging.getLogger(__name__)

_cached_tags = None

async def fetch_ollama_tags() -> list[str]:
    """Fetch the list of loaded model tags from the local Ollama registry."""
    global _cached_tags
    if _cached_tags is not None:
        return _cached_tags
    try:
        url = os.getenv("OLLAMA_TAGS_URL", "http://localhost:11434/api/tags")
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                models_data = resp.json().get("models", [])
                tags = [m.get("name") for m in models_data if m.get("name")]
                _cached_tags = tags
                return tags
    except Exception as e:
        logger.debug("Failed to query Ollama tags: %s", e)
    return []


def clear_ollama_tags_cache():
    global _cached_tags
    _cached_tags = None


async def resolve_ollama_model(preferred_model: str, fallback_model: str | None = None) -> str:
    """
    Checks the local Ollama instance's model registry to see if the preferred_model is loaded.
    If not, it checks if fallback_model is loaded.
    If neither is loaded, it defaults to the preferred_model.
    """
    tags = await fetch_ollama_tags()
    if not tags:
        return preferred_model

    # 1. Try exact match on preferred
    if preferred_model in tags:
        return preferred_model

    # 2. Try substring/alias matches on preferred
    for tag in tags:
        if preferred_model.lower() in tag.lower() or tag.lower() in preferred_model.lower():
            logger.info("Matched preferred model '%s' to loaded tag '%s'", preferred_model, tag)
            return tag

    # 3. Try exact match on fallback
    if fallback_model:
        if fallback_model in tags:
            logger.info("Preferred model '%s' not loaded. Falling back to exact match: '%s'", preferred_model, fallback_model)
            return fallback_model
        
        # Try substring matches on fallback
        for tag in tags:
            if fallback_model.lower() in tag.lower() or tag.lower() in fallback_model.lower():
                logger.info("Preferred model '%s' not loaded. Falling back to substring match: '%s' (from tag '%s')", preferred_model, fallback_model, tag)
                return tag

    logger.warning("Neither preferred model '%s' nor fallback '%s' found in Ollama tags. Defaulting to '%s'", preferred_model, fallback_model, preferred_model)
    return preferred_model


def fetch_ollama_tags_sync() -> list[str]:
    try:
        url = os.getenv("OLLAMA_TAGS_URL", "http://localhost:11434/api/tags")
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                models_data = resp.json().get("models", [])
                return [m.get("name") for m in models_data if m.get("name")]
    except Exception as e:
        logger.debug("Failed to query Ollama tags (sync): %s", e)
    return []


def resolve_ollama_model_sync(preferred_model: str, fallback_model: str | None = None) -> str:
    tags = fetch_ollama_tags_sync()
    if not tags:
        return preferred_model

    if preferred_model in tags:
        return preferred_model

    for tag in tags:
        if preferred_model.lower() in tag.lower() or tag.lower() in preferred_model.lower():
            return tag

    if fallback_model:
        if fallback_model in tags:
            return fallback_model
        for tag in tags:
            if fallback_model.lower() in tag.lower() or tag.lower() in fallback_model.lower():
                return tag

    return preferred_model
