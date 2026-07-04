import platform
platform._wmi = None

import traceback

def test_import(module_name):
    try:
        print(f"Importing {module_name}...", end=" ", flush=True)
        __import__(module_name)
        print("OK")
    except Exception as e:
        print(f"FAILED: {e}")
        traceback.print_exc()

print("Testing critical dependencies...")
test_import("fastapi")
test_import("uvicorn")
test_import("sqlalchemy")
test_import("psutil")
test_import("yaml")
test_import("httpx")

print("\nTesting core modules...")
test_import("core.database")
test_import("core.models")
test_import("core.orchestrator")
test_import("core.parser")
test_import("core.exporter")
test_import("core.scope_manager")
test_import("core.feed_sync")
test_import("core.js_analyzer")
test_import("core.fingerprint_engine")
test_import("core.fuzzer_orchestrator")
test_import("core.ai_triage")

print("\nTesting main app...")
test_import("main")
