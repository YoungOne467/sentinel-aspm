# ASPM Production Deployment Guide

This guide covers advanced architectural upgrades recommended for deploying the Autonomous Security Posture Management (ASPM) platform into a true production environment. These were deferred from the initial implementation to keep the platform accessible and easy to run locally.

## 1. Database Migration: SQLite to PostgreSQL

Currently, the backend uses **SQLite** (`aspm.db` and `scans.db`). SQLite is excellent for local development and single-user instances, but it struggles with concurrency (multiple things writing at once) when many heavy autonomous scans run simultaneously.

### Why you need it:
PostgreSQL is a robust, concurrent database engine that will prevent "database is locked" errors and easily handle thousands of parallel vulnerability scans.

### How to do it:
1. **Spin up Postgres:** 
   You can easily run Postgres using Docker. Create a `docker-compose.yml` file in your root folder:
   ```yaml
   version: '3.8'
   services:
     db:
       image: postgres:15-alpine
       environment:
         POSTGRES_USER: aspm_user
         POSTGRES_PASSWORD: aspm_password
         POSTGRES_DB: aspm_db
       ports:
         - "5432:5432"
   ```
   Run `docker-compose up -d`.

2. **Update the Application:**
   In `backend/.env`, set your connection string:
   `DATABASE_URL=postgresql+asyncpg://aspm_user:aspm_password@localhost:5432/aspm_db`

   SQLAlchemy (which the backend uses) will automatically connect and create the necessary tables on startup.

---

## 2. API Authentication (JWT)

Right now, the backend API (`http://localhost:8000/api/...`) is unauthenticated. Anyone who can reach that port on your network can trigger autonomous exploits. 

### Why you need it:
To prevent unauthorized users from using your offensive security tool against arbitrary targets.

### How to do it:
1. **Install JWT Libraries:**
   `pip install PyJWT passlib[bcrypt]`
2. **Create an Authentication Endpoint:**
   Create an endpoint (e.g., `/api/auth/login`) that accepts a username and password and returns a signed JSON Web Token (JWT).
3. **Secure the API Routes:**
   Use FastAPI's `Depends` injection to require the JWT token on sensitive routes. For example:
   ```python
   from fastapi.security import OAuth2PasswordBearer
   
   oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")
   
   @app.post("/api/scan/start")
   async def start_scan(req: ScanRequest, token: str = Depends(oauth2_scheme)):
       # Verify token logic here...
       ...
   ```

---

## 3. Private OAST Provider (Interactsh)

The platform relies on Out-of-Band Application Security Testing (OAST) to catch "blind" vulnerabilities like Log4Shell or SSRF. Currently, it uses public, anonymous Interactsh servers.

### Why you need it:
When you use a public OAST server, the vulnerable payloads and callbacks (which might contain sensitive data from your target) are processed by a server you don't control. A private server ensures your vulnerability data remains strictly confidential.

### How to do it:
1. **Infrastructure Requirements:**
   You will need a cheap VPS (Virtual Private Server) and a custom domain name (e.g., `my-oast-server.com`).
2. **Deploy Interactsh-Server:**
   Install and run the `interactsh-server` on your VPS, configuring it with your domain name and a secret authentication token.
   *See the official guide here: [https://github.com/projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh)*
3. **Configure the ASPM Backend:**
   In your `backend/.env` file, you would define:
   ```env
   OAST_SERVER_URL=https://my-oast-server.com
   OAST_AUTH_TOKEN=your-secret-token
   ```
   The backend's `OASTClient` in `core/interactsh.py` is already designed to use these environment variables if they are present.
