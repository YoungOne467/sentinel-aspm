"""Small same-origin surface mapper used by scanner modules."""

from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urldefrag, urljoin, urlparse


API_LITERAL_RE = re.compile(
    r"""(?P<quote>['"])(?P<path>/(?:api|graphql|v\d+|rest|admin|account|user|users|orders|billing|auth)[^'"\s<>]*) (?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)


def _origin(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    return parsed.scheme.lower(), parsed.netloc.lower()


def normalize_discovered_url(base_url: str, discovered: str | None) -> str | None:
    if not discovered:
        return None
    raw = discovered.strip()
    if not raw or raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
        return None
    joined, _fragment = urldefrag(urljoin(base_url, raw))
    parsed = urlparse(joined)
    if parsed.scheme not in ("http", "https"):
        return None
    if _origin(base_url) != _origin(joined):
        return None
    return joined


class _SurfaceHTMLParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self.inline_script_chunks: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {name.lower(): value for name, value in attrs}
        if tag == "a":
            link = normalize_discovered_url(self.base_url, attr.get("href"))
            if link:
                self.links.add(link)
        elif tag == "script":
            self._in_script = True
            script = normalize_discovered_url(self.base_url, attr.get("src"))
            if script:
                self.scripts.add(script)
        elif tag == "form":
            action = normalize_discovered_url(self.base_url, attr.get("action") or self.base_url)
            self._current_form = {
                "action": action or self.base_url,
                "method": str(attr.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr.get("name") or attr.get("id")
            if name:
                self._current_form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data:
            self.inline_script_chunks.append(data)


def extract_surface_from_html(base_url: str, html: str) -> dict:
    parser = _SurfaceHTMLParser(base_url)
    parser.feed(html or "")
    api_candidates: set[str] = set()
    for chunk in parser.inline_script_chunks:
        for match in API_LITERAL_RE.finditer(chunk):
            endpoint = normalize_discovered_url(base_url, match.group("path"))
            if endpoint:
                api_candidates.add(endpoint)
    for form in parser.forms:
        action = form.get("action")
        if action and any(token in action.lower() for token in ("/api", "/graphql", "/auth", "/user")):
            api_candidates.add(action)
    return {
        "links": sorted(parser.links),
        "scripts": sorted(parser.scripts),
        "forms": parser.forms,
        "api_candidates": sorted(api_candidates),
    }


def classify_high_value_path(url: str) -> str | None:
    path = urlparse(url).path.lower()
    if any(token in path for token in ("/admin", "/internal", "/debug", "/actuator", "/swagger", "/openapi", "/graphql")):
        return "high_value_route"
    if any(token in path for token in ("/login", "/reset", "/forgot", "/oauth", "/saml", "/auth")):
        return "auth_flow"
    if any(token in path for token in ("/account", "/billing", "/profile", "/settings", "/orders")):
        return "user_data_route"
    return None
