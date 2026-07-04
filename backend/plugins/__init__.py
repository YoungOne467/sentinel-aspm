import importlib
import logging
from importlib import metadata
from typing import Dict, Optional

# Set up module logger
logger = logging.getLogger(__name__)

# Type hint for plugin base class – import lazily to avoid circular imports
ScannerPlugin = None
try:
    from ..scanner import ScannerPlugin  # Adjust the import path as needed
except Exception:
    # If the base class cannot be imported at import time, we will resolve it later
    pass

# Discover plugins registered under the "vuln_scanner.plugins" entry‑point group
def _discover_plugins() -> Dict[str, object]:
    plugins: Dict[str, object] = {}
    for ep in metadata.entry_points().select(group="vuln_scanner.plugins"):
        try:
            plugin_cls = ep.load()
            plugins[ep.name] = plugin_cls
            logger.debug("Loaded plugin %s -> %s", ep.name, plugin_cls)
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", ep.name, exc)
    return plugins

# Store discovered plugins at import time
_available_plugins: Dict[str, object] = _discover_plugins()

# Log the discovered plugins so they are visible on startup
if _available_plugins:
    logger.info("Discovered vuln_scanner plugins: %s", ", ".join(_available_plugins.keys()))
else:
    logger.info("No vuln_scanner plugins discovered.")


def get_plugin(name: str) -> Optional[object]:
    """Return the plugin class registered under *name*.

    Args:
        name: The entry‑point name of the desired plugin.

    Returns:
        The plugin class implementing ``ScannerPlugin`` or ``None`` if no such
        plugin is registered.
    """
    return _available_plugins.get(name)
