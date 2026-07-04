"""Agent package exports.

Heavy scanner modules are imported lazily so unrelated agent tests do not fail
when an optional scanner module is unavailable.
"""


async def run_active_scan(*args, **kwargs):
    from .active_scanner import run_active_scan as _run_active_scan

    return await _run_active_scan(*args, **kwargs)
