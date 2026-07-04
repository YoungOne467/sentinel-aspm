"""
AETHER Intercepting Proxy — Request Store

Manages the storage, retrieval, and replay of HTTP requests captured
by the mitmproxy interceptor. This serves as the data layer for the 
AETHER Repeater and Intruder modules.
"""

import asyncio
import base64
import json
import logging
import sqlite3
import time
import uuid
from typing import List, Dict, Any, Optional

import httpx
from core.http_pool import HTTPClientPool

logger = logging.getLogger(__name__)


class RequestStore:
    """Stores proxy history and manages request replays."""
    
    def __init__(self, db_path: str = "proxy_history.db"):
        self.db_path = db_path
        self._init_db()
        
    def _connect(self) -> sqlite3.Connection:
        """Helper to connect to SQLite with WAL pragmas."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        """Initialize the SQLite database for proxy history."""
        with self._connect() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS proxy_history (
                    id TEXT PRIMARY KEY,
                    timestamp REAL,
                    method TEXT,
                    url TEXT,
                    host TEXT,
                    path TEXT,
                    request_headers TEXT,
                    request_body BLOB,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_body BLOB,
                    response_time REAL,
                    is_intercepted BOOLEAN,
                    is_modified BOOLEAN,
                    notes TEXT
                )
            ''')
            # Create indexes for fast filtering
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON proxy_history(timestamp DESC)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_host ON proxy_history(host)')
            
    def add_record(self, record: Dict[str, Any]) -> str:
        """Add a new proxy record to the store."""
        record_id = record.get("id", str(uuid.uuid4()))
        timestamp = record.get("timestamp", time.time())
        
        req = record.get("request", {})
        resp = record.get("response", {})
        
        with self._connect() as conn:
            conn.execute('''
                INSERT OR IGNORE INTO proxy_history (
                    id, timestamp, method, url, host, path, 
                    request_headers, request_body,
                    response_status, response_headers, response_body, response_time,
                    is_intercepted, is_modified, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record_id,
                timestamp,
                req.get("method", "GET"),
                req.get("url", ""),
                req.get("host", ""),
                req.get("path", ""),
                json.dumps(req.get("headers", {})),
                req.get("content", b""),
                resp.get("status_code", 0),
                json.dumps(resp.get("headers", {})),
                resp.get("content", b""),
                record.get("response_time", 0.0),
                record.get("is_intercepted", False),
                record.get("is_modified", False),
                record.get("notes", "")
            ))
            
        return record_id
        
    def get_history(self, limit: int = 100, offset: int = 0, host_filter: str = None) -> List[Dict[str, Any]]:
        """Retrieve proxy history, optionally filtered by host."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            
            query = "SELECT id, timestamp, method, url, host, path, response_status, response_time FROM proxy_history"
            params = []
            
            if host_filter:
                query += " WHERE host LIKE ?"
                params.append(f"%{host_filter}%")
                
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
    def get_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Get a full record including headers and bodies."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM proxy_history WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            record = dict(row)
            
            # Format nicely for the frontend
            return {
                "id": record["id"],
                "timestamp": record["timestamp"],
                "response_time": record["response_time"],
                "is_intercepted": record["is_intercepted"],
                "is_modified": record["is_modified"],
                "notes": record["notes"],
                "request": {
                    "method": record["method"],
                    "url": record["url"],
                    "host": record["host"],
                    "path": record["path"],
                    "headers": json.loads(record["request_headers"] or "{}"),
                    # Base64 encode bodies so they survive JSON serialization to the frontend
                    "body_b64": base64.b64encode(record["request_body"] or b"").decode('ascii')
                },
                "response": {
                    "status_code": record["response_status"],
                    "headers": json.loads(record["response_headers"] or "{}"),
                    "body_b64": base64.b64encode(record["response_body"] or b"").decode('ascii')
                }
            }
            
    async def replay_request(self, record_id: str, modifications: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Replay a historical request.
        Modifications can specify overridden 'method', 'url', 'headers', or 'body_b64'.
        Returns the new response.
        """
        record = await asyncio.to_thread(self.get_record, record_id)
        if not record:
            raise ValueError(f"Record {record_id} not found")
            
        req = record["request"]
        modifications = modifications or {}
        
        method = modifications.get("method", req["method"])
        url = modifications.get("url", req["url"])
        headers = modifications.get("headers", req["headers"])
        
        if "body_b64" in modifications:
            body = base64.b64decode(modifications["body_b64"])
        else:
            body = base64.b64decode(req["body_b64"])
            
        # Clean up problematic headers for replay
        headers.pop("content-length", None)
        headers.pop("accept-encoding", None) # Let httpx handle decompression
        
        start_time = time.monotonic()
        
        client = await HTTPClientPool.get_client()
        resp = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=body,
            timeout=15.0
        )
            
        elapsed = time.monotonic() - start_time
        
        # Save the replay as a new record
        new_record = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "response_time": elapsed,
            "is_intercepted": False,
            "is_modified": True,
            "notes": f"Replayed from {record_id}",
            "request": {
                "method": method,
                "url": str(resp.request.url),
                "host": resp.request.url.host,
                "path": resp.request.url.path,
                "headers": dict(resp.request.headers),
                "content": body
            },
            "response": {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "content": resp.content
            }
        }
        
        await asyncio.to_thread(self.add_record, new_record)
        return await asyncio.to_thread(self.get_record, new_record["id"])

# Global store singleton
store = RequestStore()
