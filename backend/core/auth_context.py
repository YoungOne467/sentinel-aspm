import threading
from typing import Dict

class AuthContextManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._active_headers: Dict[str, str] = {}
        self._active_cookies: Dict[str, str] = {}

    def set_context(self, headers: Dict[str, str], cookies: Dict[str, str]):
        with self._lock:
            self._active_headers = dict(headers)
            self._active_cookies = dict(cookies)

    def get_headers(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._active_headers)

    def get_cookies(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._active_cookies)

    def clear(self):
        with self._lock:
            self._active_headers.clear()
            self._active_cookies.clear()

global_auth_context = AuthContextManager()
