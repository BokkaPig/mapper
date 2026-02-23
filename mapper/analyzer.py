from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .models import DetectedFunction

# File extensions that indicate a download link
_DOWNLOAD_EXT = re.compile(
    r'\.(pdf|docx?|xlsx?|pptx?|zip|tar\.gz|tar|gz|7z|rar|csv|xml|json'
    r'|txt|log|exe|msi|dmg|pkg|deb|rpm|apk|ipa|iso|img|bin|dat)(\?|#|$)',
    re.IGNORECASE,
)

# Field name patterns that suggest a search input
_SEARCH_NAMES = re.compile(
    r'^(q|query|search|s|keyword|term|find|k|searchterm|searchquery)$',
    re.IGNORECASE,
)

# Field/token names that suggest CSRF protection
_CSRF_NAMES = re.compile(
    r'csrf|_token|authenticity_token|nonce|__requestverificationtoken',
    re.IGNORECASE,
)

# Static asset extensions to filter out of API endpoint detection
_STATIC_ASSET = re.compile(
    r'\.(css|js|jsx|ts|tsx|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map'
    r'|webp|avif|mp4|mp3|webm|pdf)(\?|#|$)',
    re.IGNORECASE,
)


class FunctionAnalyzer:
    """
    Turns rendered HTML + network intercepts + JS endpoints into
    a list of DetectedFunction objects.
    """

    def analyze(
        self,
        html: str,
        base_url: str,
        intercepted_urls: list,
        js_endpoints: list,  # list of (url, method_or_None)
        js_websockets: list,
    ) -> list:
        soup = BeautifulSoup(html, "lxml")
        functions = []

        functions.extend(self._detect_forms(soup, base_url))
        functions.extend(self._detect_download_links(soup, base_url))
        functions.extend(self._detect_standalone_inputs(soup))
        functions.extend(
            self._detect_api_endpoints(intercepted_urls, js_endpoints, base_url)
        )
        functions.extend(self._detect_websockets(js_websockets))

        return functions

    # ------------------------------------------------------------------
    # Form detection
    # ------------------------------------------------------------------

    def _detect_forms(self, soup: BeautifulSoup, base_url: str) -> list:
        functions = []
        for form in soup.find_all("form"):
            action = form.get("action", "") or ""
            method = (form.get("method", "GET") or "GET").upper()
            abs_action = urljoin(base_url, action) if action else base_url

            # --- File upload ---
            file_inputs = form.find_all("input", type="file")
            if file_inputs:
                accept = [fi.get("accept", "*") for fi in file_inputs]
                multiple = any(fi.has_attr("multiple") for fi in file_inputs)
                functions.append(DetectedFunction(
                    function_type="file_upload",
                    description=f"File upload ({method} {abs_action})",
                    method=method,
                    action=abs_action,
                    details={
                        "accept": accept,
                        "multiple": multiple,
                        "enctype": form.get("enctype", "multipart/form-data"),
                    },
                    pentest_tests=[],
                ))
                continue  # Don't double-count as generic form

            # --- Login form ---
            password_inputs = form.find_all("input", type="password")
            if password_inputs:
                all_inputs = form.find_all(
                    "input",
                    type=lambda t: t in (None, "text", "email", "tel")
                    if t is not None else True,
                )
                has_csrf = bool(form.find(
                    "input", attrs={"name": _CSRF_NAMES}
                )) or bool(form.find(
                    "input", attrs={"id": _CSRF_NAMES}
                ))
                functions.append(DetectedFunction(
                    function_type="login_form",
                    description=f"Login form ({method} {abs_action})",
                    method=method,
                    action=abs_action,
                    details={
                        "fields": [
                            i.get("name") or i.get("id")
                            for i in form.find_all("input")
                            if i.get("name") or i.get("id")
                        ],
                        "has_csrf": has_csrf,
                    },
                    pentest_tests=[],
                ))
                continue

            # --- Search form ---
            search_inputs = form.find_all("input", type="search")
            if not search_inputs:
                # Also match by common field names
                search_inputs = [
                    i for i in form.find_all("input")
                    if i.get("name") and _SEARCH_NAMES.match(i.get("name", ""))
                ]
            if search_inputs:
                si = search_inputs[0]
                functions.append(DetectedFunction(
                    function_type="search",
                    description=f"Search form ({method} {abs_action})",
                    method=method,
                    action=abs_action,
                    details={
                        "field_name": si.get("name", "q"),
                        "placeholder": si.get("placeholder", ""),
                    },
                    pentest_tests=[],
                ))
                continue

            # --- Generic form ---
            all_inputs = form.find_all(["input", "textarea", "select"])
            visible = [
                i for i in all_inputs
                if (i.get("type") or "text").lower() not in
                ("hidden", "submit", "button", "reset", "image")
            ]
            has_csrf = bool(form.find("input", attrs={"name": _CSRF_NAMES})) or \
                       bool(form.find("input", attrs={"id": _CSRF_NAMES}))
            functions.append(DetectedFunction(
                function_type="form_generic",
                description=f"Form ({method} {abs_action})",
                method=method,
                action=abs_action,
                details={
                    "input_count": len(visible),
                    "fields": [
                        i.get("name") or i.get("id")
                        for i in visible
                        if i.get("name") or i.get("id")
                    ],
                    "has_csrf": has_csrf,
                },
                pentest_tests=[],
            ))
        return functions

    # ------------------------------------------------------------------
    # Download link detection
    # ------------------------------------------------------------------

    def _detect_download_links(self, soup: BeautifulSoup, base_url: str) -> list:
        functions = []
        for a in soup.find_all("a", href=True):
            href = (a["href"] or "").strip()
            if not href:
                continue
            abs_href = urljoin(base_url, href)
            if a.has_attr("download") or _DOWNLOAD_EXT.search(href):
                ext_m = re.search(r'\.(\w+)(\?|#|$)', href)
                ext = ext_m.group(1) if ext_m else "unknown"
                functions.append(DetectedFunction(
                    function_type="download_link",
                    description=f"Download: {abs_href}",
                    method="GET",
                    action=abs_href,
                    details={
                        "extension": ext.lower(),
                        "text": a.get_text(strip=True)[:80],
                    },
                    pentest_tests=[],
                ))
        return functions

    # ------------------------------------------------------------------
    # Standalone input detection (not inside a <form>)
    # ------------------------------------------------------------------

    def _detect_standalone_inputs(self, soup: BeautifulSoup) -> list:
        functions = []
        skip_types = {"hidden", "submit", "button", "reset", "image"}
        for inp in soup.find_all(["input", "textarea"]):
            if inp.find_parent("form"):
                continue
            inp_type = (inp.get("type") or "text").lower()
            if inp_type in skip_types:
                continue
            functions.append(DetectedFunction(
                function_type="input_field",
                description=(
                    f"Standalone input: "
                    f"{inp.get('name') or inp.get('id') or inp_type}"
                ),
                method=None,
                action=None,
                details={
                    "type": inp_type,
                    "name": inp.get("name"),
                    "id": inp.get("id"),
                    "placeholder": inp.get("placeholder", ""),
                },
                pentest_tests=[],
            ))
        return functions

    # ------------------------------------------------------------------
    # API endpoint detection
    # ------------------------------------------------------------------

    def _detect_api_endpoints(
        self,
        intercepted_urls: list,
        js_endpoints: list,  # [(url, method_or_None), ...]
        base_url: str,
    ) -> list:
        seen: set = set()
        functions = []

        # Network-intercepted requests (most reliable — actual runtime calls)
        for item in intercepted_urls:
            if isinstance(item, dict):
                url = item.get("url", "")
                method = item.get("method")
            else:
                url, method = item, None

            if not url or _STATIC_ASSET.search(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            functions.append(DetectedFunction(
                function_type="api_endpoint",
                description=f"API endpoint: {url}",
                method=method,
                action=url,
                details={"source": "network_intercept"},
                pentest_tests=[],
            ))

        # Statically extracted from JS source
        for url, method in (js_endpoints or []):
            if not url or _STATIC_ASSET.search(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            functions.append(DetectedFunction(
                function_type="api_endpoint",
                description=f"API endpoint: {url}",
                method=method,
                action=url,
                details={"source": "static_js_analysis"},
                pentest_tests=[],
            ))

        return functions

    # ------------------------------------------------------------------
    # WebSocket detection
    # ------------------------------------------------------------------

    def _detect_websockets(self, ws_uris: list) -> list:
        return [
            DetectedFunction(
                function_type="websocket",
                description=f"WebSocket: {uri}",
                method=None,
                action=uri,
                details={"protocol": "wss" if uri.startswith("wss://") else "ws"},
                pentest_tests=[],
            )
            for uri in (ws_uris or [])
        ]
