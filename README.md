# Sentinel

Sentinel is a fast, local-first Application Security Posture Management (ASPM) platform. It orchestrates multiple security scanners, normalizes their output, and provides a central dashboard for triaging vulnerabilities. 

Built with FastAPI, React, and Celery.

## Features

- **Declarative Scanners:** Add new security tools by writing a simple YAML file. No codebase changes required.
- **Smart Deduplication:** Automatically deduplicates findings across different tools and scans using SHA-256 fingerprinting.
- **Real-Time Telemetry:** Live scan execution logs and results streamed to the UI via WebSockets and Redis Pub/Sub.
- **Safe Execution:** Asynchronous, non-blocking subprocess execution (`asyncio.create_subprocess_exec`) to prevent command injection.
- **Low Overhead:** Built-in "Eco Mode" dynamically disables heavy UI elements for smooth operation on lower-end hardware.

## Quick Start (Docker)

The fastest way to run Sentinel is via Docker Compose. This spins up Postgres, Redis, Neo4j, the API backend, Celery workers, and the frontend dashboard.

1. **Clone the repository**
   ```bash
   git clone https://github.com/YoungOne467/sentinel-aspm.git
   cd sentinel-aspm
   ```

2. **Configure your environment**
   ```bash
   cp .env.example .env
   ```
   *(Optional)* Edit `.env` to configure AI providers or default credentials.

3. **Start the stack**
   ```bash
   docker-compose up --build -d
   ```

4. **Access the platform**
   - Dashboard: http://localhost:3000
   - API Docs: http://localhost:8000/docs

## Native Local Setup

If you prefer running the stack natively without Docker, you'll need Python 3.10+, Node.js 18+, and local instances of Postgres, Redis, and Neo4j.

**1. Backend setup:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
cp ../.env .env
uvicorn main:app --reload --port 8000
```

**2. Frontend setup:**
```bash
cd aspm-frontend
npm install
npm run dev
```

*(Windows users can use the included `start_aspm.bat` or `launch_suite.bat` scripts for quick native launches).*

## Configuration

Core components are configured via the `.env` file. Key variables include:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Async SQLAlchemy URL for Postgres. | `postgresql://sentinel_user:sentinel_password@localhost:5432/sentinel_db` |
| `REDIS_URL` | Redis URL for Celery and WebSockets. | `redis://localhost:6379/0` |
| `NEO4J_ENABLED` | Toggle attack path graph analysis. | `true` |
| `AI_PROVIDER` | Provider for vulnerability triage. | `ollama` |
| `AI_MODEL` | LLM used for triage. | `llama3` |

## License

This project is licensed under a custom personal and non-commercial use license. See the [LICENSE](./LICENSE) file for details.
