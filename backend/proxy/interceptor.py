"""
AETHER mitmproxy Interceptor

A standalone addon for mitmproxy that captures HTTP traffic,
logs it to our RequestStore, and handles on-the-fly modifications.
"""

import logging
import time

from mitmproxy import http
from mitmproxy import ctx
from proxy.request_store import store

logger = logging.getLogger(__name__)

class AetherInterceptor:
    """mitmproxy addon to capture and store requests."""
    
    def __init__(self):
        self.num_requests = 0

    def request(self, flow: http.HTTPFlow):
        """Handle outgoing request."""
        # We can implement interception rules here later
        pass

    def response(self, flow: http.HTTPFlow):
        """Handle incoming response and save to store."""
        try:
            req = flow.request
            resp = flow.response
            
            # Filter out noisy static assets
            if req.path.endswith((".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf")):
                if "application/json" not in resp.headers.get("content-type", ""):
                    return

            record = {
                "id": str(flow.id),
                "timestamp": time.time(),
                "response_time": flow.response.timestamp_end - flow.request.timestamp_start if flow.response else 0.0,
                "is_intercepted": False,
                "is_modified": False,
                "notes": "",
                "request": {
                    "method": req.method,
                    "url": req.url,
                    "host": req.host,
                    "path": req.path,
                    "headers": dict(req.headers),
                    "content": req.content,
                },
                "response": {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "content": resp.content,
                }
            }
            
            store.add_record(record)
            self.num_requests += 1
            
        except Exception as e:
            logger.error("Error processing flow: %s", e)

addons = [
    AetherInterceptor()
]
