# SENTINEL: Application Security Posture Management (ASPM) Platform

SENTINEL is an enterprise-grade, highly robust, and scalable open-source Application Security Posture Management (ASPM) platform. It provides a unified dashboard to orchestrate, analyze, and triage vulnerability data across multi-scanner pipelines, with a high-end, responsive "hacker-workspace" theme.

```mermaid
graph TD
    A[Frontend: Vite / React / Zustand] -->|WebSockets / HTTP| B[Backend API: FastAPI]
    B -->|Task Queue| C[Celery Workers]
    C -->|Results & Telemetry| D[(Postgres DB)]
    C -->|Deduplication & Cache| E[(Redis Cache)]
    C -->|Vulnerability Graph| F[(Neo4j Graph Database)]
    B -->|State Sync| E
```

## Features

- **Hacker-Workspace Frontend**: A stunning, premium Dark NOC (Network Operations Center) theme built with React, Vite, and CSS variables. Features responsive charts, real-time log monitoring, and an **Eco Mode** performance toggle.
- **Eco Mode Performance Control**: Dynamic client-side state handling to disable CPU-intensive canvas animations (aurora containers, high-blur glassmorphism panels) for lower hardware environments.
- **Declarative Scanner Plugins**: Add scanners dynamically using simple, declarative YAML schemas that define CLI signatures and regex-based output parsing.
- **Secure Subprocess Engine**: Asynchronous non-blocking subprocess commands via `asyncio.create_subprocess_exec` to guard against command injection.
- **Advanced Deduplication**: Normalize and aggregate redundant scan telemetry automatically on sqlite/postgres with SHA-256 checksums mapping unique signatures.
- **Real-Time Telemetry Stream**: WebSockets streaming scan execution telemetry backed by Redis Pub/Sub.

---

## Environment Configuration

Both the native setup and the Docker-based setup rely on configuration via environment variables. An `.env.example` file is provided at the root of the project to serve as a blueprint.

### 1. Copy the Environment File
To configure the environment, copy the `.env.example` file to a new file named `.env`:
```bash
cp .env.example .env
```

### 2. Configure Key Variables
Open the `.env` file and adjust the settings to match your local setup. Below is a breakdown of the key variables:

| Variable | Description | Default / Example Value |
|----------|-------------|-------------------------|
| `POSTGRES_DB` | Name of the PostgreSQL database. | `sentinel_db` |
| `POSTGRES_USER` | Username for PostgreSQL database access. | `sentinel_user` |
| `POSTGRES_PASSWORD` | Password for PostgreSQL database access. | `sentinel_password` |
| `DATABASE_URL` | Async SQLAlchemy URL connecting the backend to PostgreSQL. | `postgresql://sentinel_user:sentinel_password@localhost:5432/sentinel_db` |
| `REDIS_URL` | Redis URL for Celery workers and WebSocket messaging. | `redis://localhost:6379/0` |
| `NEO4J_ENABLED` | Toggle flag to enable/disable Neo4j attack path analysis. | `true` |
| `NEO4J_URI` | Neo4j URI endpoint. | `bolt://localhost:7687` |
| `NEO4J_USER` | Username for Neo4j database authentication. | `neo4j` |
| `NEO4J_PASSWORD` | Password for Neo4j database authentication. | `password` |
| `AI_PROVIDER` | AI provider for vulnerability triage (`ollama`, `openai`, `anthropic`). | `ollama` |
| `AI_API_KEY` | Authentication key (leave blank for local Ollama instances). | `[your-api-key-here]` |
| `AI_MODEL` | Large Language Model used (`llama3`, `gpt-4o`, `claude-3-opus`). | `llama3` |
| `AI_BASE_URL` | Custom endpoint URL for AI model query generation. | `http://localhost:11434/api/generate` |
| `HOST` | The bind address for the local development server. | `0.0.0.0` |
| `PORT` | Port number on which the Backend API runs. | `8000` |
| `DEBUG` | Enables or disables debug level error responses from the API. | `false` |

---

## Native Setup (Local Development)

To run SENTINEL natively on your local machine, ensure you have the following prerequisites installed:
*   **Python 3.10+**
*   **Node.js 18+**
*   **PostgreSQL, Redis, and Neo4j** servers running locally (or via Docker).

### Step 1: Configure Backend Environment
1. Copy `.env` to the backend directory so the FastAPI app can load it on startup:
   ```bash
   cp .env backend/.env
   ```
   *(Alternatively, export the environment variables directly into your current shell session before booting the servers).*

### Step 2: Install and Start Backend API
1. Navigate to the `backend` directory, create a virtual environment, and install dependencies:
   ```bash
   cd backend
   python -m venv venv
   
   # Activate virtual environment
   # On macOS/Linux:
   source venv/bin/activate
   # On Windows:
   venv\Scripts\activate
   
   # Install required packages
   pip install -r requirements.txt
   ```
2. Run the development server (the database tables will automatically initialize on startup):
   ```bash
   uvicorn main:app --reload --port 8000
   ```
   The backend API is now running at `http://localhost:8000`. You can access interactive Swagger documentation at `http://localhost:8000/docs`.

### Step 3: Install and Start Frontend Dashboard
1. Open a new terminal window and navigate to the `aspm-frontend` directory:
   ```bash
   cd aspm-frontend
   ```
2. Install node dependencies and start the development server:
   ```bash
   npm install
   npm run dev
   ```
   The frontend is now running at `http://localhost:5174` (or `http://localhost:5173` depending on port availability) and proxies requests to the backend server automatically.

### Shortcut Launchers (Windows only)
For quick local development on Windows:
*   **`start_aspm.bat`**: A one-shot launcher script that installs backend/frontend dependencies, runs backend, waits for health response, and opens the frontend in Firefox.
*   **`launch_suite.bat`**: An interactive terminal control panel launcher allowing you to start either the frontend individually or the full stack simultaneously.
*   **`sentinel_bootloader.py`**: A python lifecycle script controlling resource consumption: runs FastAPI + Vite, and stops them to free RAM when offline batch analysis signals are triggered.

---

## Docker-based Setup

The simplest way to orchestrate the entire SENTINEL stack (PostgreSQL, Redis, Neo4j, API backend, Celery workers, and the Vite UI dashboard) is using Docker Compose.

### Prerequisites
*   **Docker** (v20.10+)
*   **Docker Compose** (v2.0+)

### Step 1: Configure Environment
Make sure you have created your `.env` file in the root directory:
```bash
cp .env.example .env
```
Docker Compose reads this file automatically on startup.

### Step 2: Launch the Services
From the root directory, run the following command to build and launch all containers in detached mode:
```bash
docker-compose up --build -d
```

This starts:
1.  `sentinel-postgres`: Postgres DB running on port `5432`
2.  `sentinel-redis`: Redis message broker running on port `6379`
3.  `sentinel-neo4j`: Neo4j browser and bolt endpoints on `7474` and `7687`
4.  `sentinel-api`: FastAPI backend running on port `8000`
5.  `sentinel-worker`: Celery workers processing background scan tasks
6.  `sentinel-ui`: Production React/Vite dashboard served via NGINX on port `3000`

### Step 3: Access the Platform
*   **Frontend Dashboard**: `http://localhost:3000`
*   **FastAPI Documentation**: `http://localhost:8000/docs`

### Step 4: Stop the Stack
To tear down the containers and preserve persistent database volumes:
```bash
docker-compose down
```
To also destroy persistent volumes (clean slate):
```bash
docker-compose down -v
```

---

## License

This project is licensed under a custom personal and non-commercial use license agreement. For detailed terms, restrictions, and permissions, please refer to the [LICENSE](./LICENSE) file in the root directory.
