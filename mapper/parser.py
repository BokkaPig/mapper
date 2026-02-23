from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

from bs4 import BeautifulSoup

# Maximum JS file size to analyse statically (bytes). Files larger than
# this are skipped to avoid excessive memory/CPU on minified bundles.
MAX_JS_PARSE_BYTES = 5 * 1024 * 1024  # 5 MB


class PageParser:
    """
    Parses rendered HTML (post-JS) to extract links, form actions,
    inline script text, and external script sources.
    """

    def extract_links(self, html: str, base_url: str) -> list:
        """
        Return absolute URLs from <a>, <link>, <form action>, <script src>,
        <img src>, <iframe src>, <area href>.
        Does NOT filter by domain — that is the crawler's responsibility.
        """
        soup = BeautifulSoup(html, "lxml")
        urls: set = set()

        tag_attr_map = {
            "a": "href",
            "area": "href",
            "link": "href",
            "script": "src",
            "img": "src",
            "iframe": "src",
        }
        skip_schemes = ("javascript:", "mailto:", "tel:", "#", "data:", "void(")

        for tag, attr in tag_attr_map.items():
            for el in soup.find_all(tag, **{attr: True}):
                raw = el[attr].strip()
                if not raw or any(raw.startswith(s) for s in skip_schemes):
                    continue
                try:
                    abs_url = urljoin(base_url, raw)
                    urls.add(abs_url)
                except Exception:
                    pass

        # Form actions
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and not any(action.startswith(s) for s in skip_schemes):
                try:
                    urls.add(urljoin(base_url, action))
                except Exception:
                    pass

        return list(urls)

    def extract_inline_scripts(self, html: str) -> list:
        """Return text content of all <script> tags without a src attribute."""
        soup = BeautifulSoup(html, "lxml")
        scripts = []
        for tag in soup.find_all("script", src=False):
            content = tag.string
            if content and len(content.encode()) <= MAX_JS_PARSE_BYTES:
                scripts.append(content)
        return scripts

    def extract_script_srcs(self, html: str, base_url: str) -> list:
        """Return absolute URLs of all external <script src=...> tags."""
        soup = BeautifulSoup(html, "lxml")
        srcs = []
        for tag in soup.find_all("script", src=True):
            try:
                srcs.append(urljoin(base_url, tag["src"]))
            except Exception:
                pass
        return srcs


class JSParser:
    """
    Extracts potential endpoint URLs and WebSocket URIs from JavaScript source
    using regex-based pattern matching (fast, minification-tolerant).
    """

    # fetch() / fetch(url, {method: 'PUT', ...})
    # Captures the URL argument
    _FETCH_URL = re.compile(
        r'fetch\s*\(\s*["`\']((?!//)(?!data:)[^"`\']+)["`\']',
        re.IGNORECASE,
    )

    # axios.get/post/put/patch/delete/request
    _AXIOS = re.compile(
        r'axios\s*\.\s*(?:get|post|put|patch|delete|request|head|options)\s*\(\s*'
        r'["`\']((?!//)(?!data:)[^"`\']+)["`\']',
        re.IGNORECASE,
    )

    # $.ajax / $.get / $.post
    _JQUERY_AJAX = re.compile(
        r'\$\s*\.\s*(?:ajax|get|post)\s*\(\s*["`\']((?!//)(?!data:)[^"`\']+)["`\']',
        re.IGNORECASE,
    )

    # XMLHttpRequest.open("METHOD", "/path")
    _XHR_OPEN = re.compile(
        r'\.open\s*\(\s*["`\']\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*["`\']\s*,\s*'
        r'["`\']((?!//)(?!data:)[^"`\']+)["`\']',
        re.IGNORECASE,
    )

    # Path-like string literals starting with /api, /v\d, /graphql, /rest,
    # /admin, /auth, /user, /search, /account, /dashboard, /internal, /public
    _PATH_LITERAL = re.compile(
        r'["`\'](/(?:api|v\d+|graphql|rest|admin|auth|user|users|search|account'
        r'|dashboard|internal|public|app|service|data|backend|upload|download|file'
        r'|static|media|assets|ws|socket)[a-zA-Z0-9/_\-\.?=&%+@:]*)["`\']',
        re.IGNORECASE,
    )

    # Template literals with paths: `/api/users/${id}`
    _TEMPLATE_PATH = re.compile(
        r'`(/[a-zA-Z0-9/_\-\.${}\?=&%+@:]+)`',
    )

    # WebSocket constructor
    _WEBSOCKET = re.compile(
        r'new\s+WebSocket\s*\(\s*["`\'](wss?://[^"`\']+)["`\']',
        re.IGNORECASE,
    )

    # fetch() method option — captures method alongside URL for richer info
    _FETCH_METHOD = re.compile(
        r'method\s*:\s*["`\']\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*["`\']',
        re.IGNORECASE,
    )

    def extract_endpoints(self, js_source: str, base_url: str) -> list:
        """
        Return list of (absolute_url, method_or_None) tuples extracted from JS.
        """
        if not js_source:
            return []

        endpoints: dict = {}  # url -> method

        patterns = [
            self._FETCH_URL,
            self._AXIOS,
            self._JQUERY_AJAX,
            self._XHR_OPEN,
            self._PATH_LITERAL,
            self._TEMPLATE_PATH,
        ]

        for pattern in patterns:
            for match in pattern.finditer(js_source):
                raw = match.group(1).strip()
                if not raw or raw in ('/', '//'):
                    continue
                # Skip obviously non-path content
                if len(raw) < 2:
                    continue
                try:
                    if raw.startswith('http'):
                        abs_url = raw
                    else:
                        abs_url = urljoin(base_url, raw)
                    if abs_url not in endpoints:
                        endpoints[abs_url] = None
                except Exception:
                    pass

        # Try to associate methods for XHR.open patterns
        for match in self._XHR_OPEN.finditer(js_source):
            raw = match.group(1).strip()
            # The method is in the first capture group of the full pattern —
            # re-extract by looking at what preceded the URL capture
            before = js_source[max(0, match.start() - 10):match.start()]
            method_m = re.search(
                r'(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)', before, re.IGNORECASE
            )
            if method_m:
                try:
                    abs_url = urljoin(base_url, raw) if not raw.startswith('http') else raw
                    endpoints[abs_url] = method_m.group(1).upper()
                except Exception:
                    pass

        return [(url, method) for url, method in endpoints.items()]

    def extract_websockets(self, js_source: str) -> list:
        """Return list of WebSocket URIs found in JS source."""
        if not js_source:
            return []
        return [m.group(1) for m in self._WEBSOCKET.finditer(js_source)]
