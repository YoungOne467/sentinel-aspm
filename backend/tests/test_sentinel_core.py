import pytest
import types
from core.scope_manager import ScopeManager
from core.parser import compute_finding_hash
from core.orchestrator import TaskOrchestrator
import asyncio


def _close_background_task(coro):
    coro.close()


def test_scope_manager():
    sm = ScopeManager()
    
    # Mock loaded rules directly to isolate matching logic
    sm._include_rules = [{"pattern_type": "wildcard", "pattern": "*.example.com"}]
    sm._exclude_rules = [
        {"pattern_type": "domain", "pattern": "malicious.example.com"},
        {"pattern_type": "cidr", "pattern": "10.0.0.0/24"}
    ]

    # Test domain matches
    assert sm.is_in_scope("target.example.com") is True
    assert sm.is_in_scope("malicious.example.com") is False
    assert sm.is_in_scope("other.com") is False

    # Test IP matches
    assert sm.is_in_scope("10.0.0.5") is False

def test_hash_deduplication():
    h1 = compute_finding_hash("t1", "SQL Injection", "web", "param=id")
    h2 = compute_finding_hash("t1", "SQL Injection", "web", "param=id")
    h3 = compute_finding_hash("t1", "SQL Injection", "web", "param=name")
    
    assert h1 == h2
    assert h1 != h3

@pytest.mark.asyncio
async def test_orchestrator_execution():
    orchestrator = TaskOrchestrator(max_concurrent=2)
    
    # Mock update status to avoid database call during unit test
    async def mock_update_status(job_id, status, **kwargs):
        pass
    orchestrator._update_job_status = mock_update_status
    
    # Capture broadcast messages
    broadcasted = []
    async def mock_broadcast(msg):
        broadcasted.append(msg)
    orchestrator.set_broadcast(mock_broadcast)

    # Run a simple echo command on Windows
    res = await orchestrator.execute_job("job1", "cmd.exe /c echo hello sentinel", "echo")
    
    assert res["status"] == "completed"
    assert res["exit_code"] == 0
    
    # Verify that the stdout was streamed via broadcast
    stdout_lines = [m["line"] for m in broadcasted if m.get("type") == "terminal_output" and m.get("stream") == "stdout"]
    assert any("hello sentinel" in line for line in stdout_lines)


@pytest.mark.asyncio
async def test_pipeline_manager_execution(monkeypatch):
    import core.pipeline_manager
    import core.ssl_extractor
    import core.osint_fetcher
    
    # Mock verify_binary_exists to always return True
    monkeypatch.setattr(core.pipeline_manager, "verify_binary_exists", lambda name: True)
    monkeypatch.setattr(core.pipeline_manager, "_spawn_background_discovery", _close_background_task)
    
    # Mock background discovery network calls to prevent unclosed pipe/socket warnings
    monkeypatch.setattr(core.ssl_extractor, "extract_sans", lambda host, port=443: [])
    
    async def mock_fetch_wayback_subdomains(domain):
        return []
    monkeypatch.setattr(core.osint_fetcher, "fetch_wayback_subdomains", mock_fetch_wayback_subdomains)
    
    # Mock orchestrator.execute_job to return successful outputs
    executed_commands = []
    async def mock_execute_job(job_id, command, tool_name):
        executed_commands.append((command, tool_name))
        # If it's subfinder, we need to mock writing to a file or returning stdout
        if "subfinder" in command:
            # Check if command has -o for a temp file
            if "-o " in command:
                # Find output filepath
                parts = command.split("-o ")
                filepath = parts[1].split()[0]
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("sub1.example.local\nsub2.example.local\n")
            return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": '{"host": "example.local", "subdomain": "sub.example.local"}', "stderr": ""}
        elif "nuclei" in command:
            if "-json-export " in command:
                parts = command.split("-json-export ")
                filepath = parts[1].split()[0]
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write('{"title": "Nuclei Finding", "severity": "high", "category": "vuln", "evidence": "poc"}\n')
            return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}
        return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(core.pipeline_manager.orchestrator, "execute_job", mock_execute_job)

    # Insert a target and a job
    from core.database import AsyncSessionLocal
    from core.models import Target, Job, Finding
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        t = Target(name="Pipeline Test Target", host="example.local", port=80)
        session.add(t)
        await session.commit()
        target_id = t.id

        j = Job(target_id=target_id, tool_name="pipeline", command="Full Pipeline")
        session.add(j)
        await session.commit()
        job_id = j.id

    # Run the pipeline!
    from core.pipeline_manager import run_pipeline
    await run_pipeline(job_id, "Full Pipeline", target_id)

    # Assertions
    # 1. Check job completed
    async with AsyncSessionLocal() as session:
        updated_job = await session.get(Job, job_id)
        assert updated_job.status == "completed"
        
        # 2. Check findings were created (both subdomain findings and nuclei findings!)
        res = await session.execute(select(Finding).where(Finding.target_id == target_id))
        findings = res.scalars().all()
        assert len(findings) >= 2

        # Check specific findings
        categories = [f.category for f in findings]
        assert "subdomain_recon" in categories
        assert "vuln" in categories

        # Clean up database
        await session.delete(updated_job)
        target_obj = await session.get(Target, target_id)
        if target_obj:
            await session.delete(target_obj)
        await session.commit()


@pytest.mark.asyncio
async def test_inventory_pipeline_falls_back_when_naabu_has_no_valid_targets(monkeypatch):
    import core.pipeline_manager
    import core.ssl_extractor
    import core.osint_fetcher

    monkeypatch.setattr(core.pipeline_manager, "verify_binary_exists", lambda name: True)
    monkeypatch.setattr(core.pipeline_manager, "_spawn_background_discovery", _close_background_task)
    monkeypatch.setattr(core.ssl_extractor, "extract_sans", lambda host, port=443: [])

    async def mock_fetch_wayback_subdomains(domain):
        return []

    monkeypatch.setattr(core.osint_fetcher, "fetch_wayback_subdomains", mock_fetch_wayback_subdomains)

    executed_tools = []
    katana_input_lines = []

    async def mock_execute_job(job_id, command, tool_name):
        executed_tools.append(tool_name)
        if tool_name == "subfinder":
            filepath = command.split("-o ", 1)[1].split()[0]
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("assets.example.local\nwww.example.local\n")
            return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}
        if tool_name == "naabu":
            return {
                "job_id": job_id,
                "status": "failed",
                "exit_code": 1,
                "stdout": "",
                "stderr": "Could not run enumeration: no valid ipv4 or ipv6 targets were found",
            }
        if tool_name == "katana":
            list_path = command.split("-list ", 1)[1].split()[0]
            with open(list_path, "r", encoding="utf-8") as f:
                katana_input_lines.extend([line.strip() for line in f if line.strip()])
            out_path = command.split("-o ", 1)[1].split()[0]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write('{"url": "https://assets.example.local/"}\n')
            return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}
        return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(core.pipeline_manager.orchestrator, "execute_job", mock_execute_job)

    from core.database import AsyncSessionLocal
    from core.models import Target, Job

    async with AsyncSessionLocal() as session:
        target = Target(name="Inventory Fallback Target", host="example.local", port=80)
        session.add(target)
        await session.commit()
        target_id = target.id

        job = Job(target_id=target_id, tool_name="pipeline", command="Inventory Mapping")
        session.add(job)
        await session.commit()
        job_id = job.id

    await core.pipeline_manager.run_pipeline(job_id, "Inventory Mapping", target_id)

    async with AsyncSessionLocal() as session:
        updated_job = await session.get(Job, job_id)
        assert updated_job.status == "completed"

    assert executed_tools == ["subfinder", "naabu", "katana", "nuclei"]
    assert katana_input_lines == ["assets.example.local", "www.example.local"]


@pytest.mark.asyncio
async def test_inventory_pipeline_uses_installed_naabu_versioned_directory(monkeypatch):
    import core.pipeline_manager
    import core.ssl_extractor
    import core.osint_fetcher

    installed_naabu = r"C:\BugBountyTools\naabu_2.6.1_windows_amd64\naabu.exe"

    monkeypatch.setattr(core.pipeline_manager, "verify_binary_exists", lambda name: True)
    monkeypatch.setattr(core.pipeline_manager, "_spawn_background_discovery", _close_background_task)
    monkeypatch.setattr(core.pipeline_manager.os.path, "isfile", lambda path: path == installed_naabu)
    monkeypatch.setattr(
        core.pipeline_manager,
        "glob",
        types.SimpleNamespace(
            glob=lambda pattern: [installed_naabu]
            if pattern == r"C:\BugBountyTools\naabu_*_windows_amd64\naabu.exe"
            else []
        ),
        raising=False,
    )
    monkeypatch.setattr(core.ssl_extractor, "extract_sans", lambda host, port=443: [])

    async def mock_fetch_wayback_subdomains(domain):
        return []

    monkeypatch.setattr(core.osint_fetcher, "fetch_wayback_subdomains", mock_fetch_wayback_subdomains)

    naabu_commands = []

    async def mock_execute_job(job_id, command, tool_name):
        if tool_name == "subfinder":
            filepath = command.split("-o ", 1)[1].split()[0]
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("assets.example.local\n")
            return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}
        if tool_name == "naabu":
            naabu_commands.append(command)
            return {
                "job_id": job_id,
                "status": "failed",
                "exit_code": 1,
                "stdout": "",
                "stderr": "Could not run enumeration: no valid ipv4 or ipv6 targets were found",
            }
        if tool_name == "katana":
            out_path = command.split("-o ", 1)[1].split()[0]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("")
            return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}
        return {"job_id": job_id, "status": "completed", "exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(core.pipeline_manager.orchestrator, "execute_job", mock_execute_job)

    from core.database import AsyncSessionLocal
    from core.models import Target, Job

    async with AsyncSessionLocal() as session:
        target = Target(name="Naabu Version Target", host="example.local", port=80)
        session.add(target)
        await session.commit()
        target_id = target.id

        job = Job(target_id=target_id, tool_name="pipeline", command="Inventory Mapping")
        session.add(job)
        await session.commit()
        job_id = job.id

    await core.pipeline_manager.run_pipeline(job_id, "Inventory Mapping", target_id)

    assert len(naabu_commands) == 1
    assert naabu_commands[0].startswith(f'"{installed_naabu}" ')
    assert "naabu_2.3.0_windows_amd64" not in naabu_commands[0]


def test_parse_json_output_empty_list():
    from core.parser import parse_json_output
    # Test empty list raw JSON output
    res = parse_json_output("[]")
    assert res == []

    # Test JSON Lines empty line / empty list
    res_lines = parse_json_output("[]\n[]")
    assert res_lines == []


def test_katana_profile_commands_use_supported_jsonl_flag():
    from core.pipeline_manager import PROFILES

    for profile_name in ("Inventory Mapping", "Deep Mapping"):
        katana_step = next(
            step for step in PROFILES[profile_name]["steps"]
            if step["tool"] == "katana"
        )
        command_tpl = katana_step["command_tpl"]
        assert " -j " in command_tpl
        assert "-oJ" not in command_tpl
        assert " -ps " not in command_tpl


def test_parse_json_output_robustness():
    from core.parser import parse_json_output
    # Test list containing valid dictionary, nested empty list, and raw string
    raw_input = '[{"title": "Valid SQLi", "severity": "high"}, [], "just a raw string"]'
    res = parse_json_output(raw_input)
    assert len(res) == 2
    
    # First item should be normalized properly
    assert res[0]["title"] == "Valid SQLi"
    assert res[0]["severity"] == "high"
    
    # Second item (raw string) should be normalized using the fallback logic without crashing
    assert res[1]["title"] == "Raw Finding Data"
    assert res[1]["severity"] == "info"


@pytest.mark.asyncio
async def test_is_new_finding_state():
    from core.database import AsyncSessionLocal
    from core.models import Target, Finding
    from core.parser import ingest_findings
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        t = Target(name="State Test Target", host="state.local")
        session.add(t)
        await session.commit()
        target_id = t.id

    try:
        # 1. Ingest a new finding
        finding_data = '[{"title": "New Finding", "severity": "medium", "category": "vuln", "evidence": "unique-poc-123"}]'
        new_count = await ingest_findings(target_id, None, finding_data, "json")
        assert new_count == 1

        # Check it is stored with is_new = True
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(Finding).where(Finding.target_id == target_id))
            findings = res.scalars().all()
            assert len(findings) == 1
            assert findings[0].is_new is True

        # 2. Ingest the same finding again
        new_count2 = await ingest_findings(target_id, None, finding_data, "json")
        assert new_count2 == 0

        # Check that is_new became False
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(Finding).where(Finding.target_id == target_id))
            findings = res.scalars().all()
            assert len(findings) == 1
            assert findings[0].is_new is False

    finally:
        # Clean up database
        async with AsyncSessionLocal() as session:
            res = await session.execute(select(Finding).where(Finding.target_id == target_id))
            findings = res.scalars().all()
            for f in findings:
                await session.delete(f)
            t_obj = await session.get(Target, target_id)
            if t_obj:
                await session.delete(t_obj)
            await session.commit()
