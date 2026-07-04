import pytest

@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "system" in data

@pytest.mark.asyncio
async def test_targets_api(client):
    # Add a target
    res = await client.post("/api/targets", json={
        "name": "Test Target",
        "host": "test.local",
        "port": 80,
        "tags": ["test"],
        "notes": "some notes"
    })
    assert res.status_code == 201
    target = res.json()
    assert target["name"] == "Test Target"
    assert target["host"] == "test.local"

    # List targets
    res = await client.get("/api/targets")
    assert res.status_code == 200
    targets = res.json()
    assert len(targets) >= 1

    # Clean up target
    res = await client.delete(f"/api/targets/{target['id']}")
    assert res.status_code == 200

@pytest.mark.asyncio
async def test_jobs_api(client, monkeypatch):
    # Mock run_pipeline to be a no-op so background tasks are not launched
    async def mock_run_pipeline(*args, **kwargs):
        pass
    monkeypatch.setattr("core.pipeline_manager.run_pipeline", mock_run_pipeline)

    # Add a target
    res = await client.post("/api/targets", json={
        "name": "Test Target",
        "host": "test.local",
        "port": 80,
    })
    assert res.status_code == 201
    target = res.json()
    target_id = target["id"]

    # Queue a job
    res = await client.post("/api/jobs", json={
        "target_id": target_id,
        "scan_profile": "Subdomain Recon"
    })
    assert res.status_code == 201
    job = res.json()
    assert "job_id" in job
    assert job["status"] == "queued"

    # List jobs
    res = await client.get("/api/jobs")
    assert res.status_code == 200
    jobs = res.json()
    assert any(j["id"] == job["job_id"] for j in jobs)

    # Clean up target
    res = await client.delete(f"/api/targets/{target_id}")
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_shutdown_api(client, monkeypatch):
    killed_pid = None
    killed_sig = None
    
    def mock_kill(pid, sig):
        nonlocal killed_pid, killed_sig
        killed_pid = pid
        killed_sig = sig

    monkeypatch.setattr("os.kill", mock_kill)

    response = await client.post("/api/shutdown")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "shutting_down"


@pytest.mark.asyncio
async def test_topology_api(client):
    # 1. Create a target
    res = await client.post("/api/targets", json={
        "name": "Topology Target",
        "host": "topo.local",
        "port": 80,
    })
    assert res.status_code == 201
    target = res.json()
    target_id = target["id"]

    # 2. Get topology for target_id
    response = await client.get(f"/api/topology?target_id={target_id}")
    assert response.status_code == 200
    topo = response.json()
    assert "nodes" in topo
    assert "edges" in topo
    
    # Root node should be present
    nodes = topo["nodes"]
    assert any(n["type"] == "root" and n["label"] == "topo.local" for n in nodes)

    # 3. Clean up target
    res = await client.delete(f"/api/targets/{target_id}")
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_download_report_api(client):
    # 1. Create a target
    res = await client.post("/api/targets", json={
        "name": "Report Target",
        "host": "report.local",
        "port": 80,
    })
    assert res.status_code == 201
    target = res.json()
    target_id = target["id"]

    # 2. Hit the download report endpoint
    response = await client.get(f"/api/reports/{target_id}/download")
    assert response.status_code == 200
    assert "Content-Disposition" in response.headers
    assert f"attachment; filename=sentinel_report_{target_id}.html" in response.headers["Content-Disposition"]
    assert "AETHER Security Audit Report" in response.text

    # 3. Clean up target
    res = await client.delete(f"/api/targets/{target_id}")
    assert res.status_code == 200


