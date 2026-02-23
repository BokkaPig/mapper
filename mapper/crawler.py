from __future__ import annotations

import asyncio
import shutil
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import httpx

from .analyzer import FunctionAnalyzer
from .browser import BrowserManager, BrowserFetchError
from .filters import should_exclude
from .models import CrawlConfig, CrawlResult, Page
from .parser import JSParser, PageParser
from .rate_limiter import TokenBucketRateLimiter

# Size cap for external JS files fetched statically (bytes)
_MAX_JS_BYTES = 5 * 1024 * 1024

_IMAGE_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".ico", ".bmp", ".tiff", ".tif", ".avif", ".heic", ".heif",
})
_CSS_EXTENSIONS = frozenset({".css"})


class Crawler:
    """
    Async BFS web crawler.

    - One shared Playwright Chromium browser, N concurrent workers.
    - asyncio.Queue drives the BFS; asyncio.Lock protects the visited set.
    - Token bucket rate limiter enforces --rate-limit (req/min).
    - Semaphore caps concurrent in-flight requests to --threads.
    """

    def __init__(self, config: CrawlConfig):
        self.config = config
        self._rate_limiter = TokenBucketRateLimiter(config.rate_limit)
        self._semaphore = asyncio.Semaphore(config.max_workers)
        self._browser = BrowserManager(config.headers, config.max_workers)
        self._page_parser = PageParser()
        self._js_parser = JSParser()
        self._analyzer = FunctionAnalyzer()
        self._result = CrawlResult(seed_urls=list(config.seed_urls))
        self._visited: set = set()
        self._visited_lock = asyncio.Lock()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._stats = {"pages": 0, "functions": 0}
        self._http_client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> CrawlResult:
        seed_domains = self._get_seed_domains()

        async with httpx.AsyncClient(
            headers=self.config.headers,
            follow_redirects=True,
            verify=False,
            timeout=15.0,
        ) as http_client:
            self._http_client = http_client
            await self._browser.start()
            try:
                # Seed the queue
                for url in self.config.seed_urls:
                    norm = self._normalize_url(url)
                    self._visited.add(norm)
                    await self._queue.put((norm, 0, None))

                # Discover additional URLs from robots.txt and sitemaps
                robots_urls = await self._fetch_robots_and_sitemaps(seed_domains)
                for url in robots_urls:
                    norm = self._normalize_url(url)
                    if norm not in self._visited:
                        self._visited.add(norm)
                        await self._queue.put((norm, 0, None))

                # Launch worker pool
                workers = [
                    asyncio.create_task(self._worker(seed_domains))
                    for _ in range(self.config.max_workers)
                ]

                await self._queue.join()

                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

            finally:
                await self._browser.stop()
                if not self.config.quiet:
                    sys.stdout.write("\n")
                    sys.stdout.flush()

        return self._result

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    async def _worker(self, seed_domains: set) -> None:
        while True:
            try:
                url, depth, parent_url = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.05)
                continue
            try:
                await self._process_url(url, depth, parent_url, seed_domains)
            except Exception as exc:
                self._result.errors.append({"url": url, "reason": str(exc)})
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Per-URL processing
    # ------------------------------------------------------------------

    async def _process_url(
        self,
        url: str,
        depth: int,
        parent_url: str | None,
        seed_domains: set,
    ) -> None:
        async with self._semaphore:
            await self._rate_limiter.acquire()
            self._print_tally(url)

            # Fetch via headless browser
            try:
                fetch = await self._browser.fetch_page(url)
            except BrowserFetchError as exc:
                self._result.errors.append({"url": url, "reason": exc.reason})
                return

            html = fetch.html
            final_url = self._normalize_url(fetch.final_url)

            # If the page redirected to an out-of-scope domain, record it
            if not self._is_in_scope(final_url, seed_domains):
                self._result.external_urls.add(fetch.final_url)
                return

            # Compute response metrics from rendered HTML text
            body_bytes = html.encode("utf-8", errors="replace")
            byte_count = len(body_bytes)
            word_count = len(html.split())
            line_count = html.count("\n") + 1

            # Determine content type
            content_type = (
                fetch.response_headers.get("content-type", "text/html")
                .split(";")[0]
                .strip()
            )

            page = Page(
                url=final_url,
                status_code=fetch.status_code,
                byte_count=byte_count,
                word_count=word_count,
                line_count=line_count,
                depth=depth,
                parent_url=parent_url,
                content_type=content_type,
                redirect_url=(
                    fetch.final_url if fetch.final_url != url else None
                ),
            )

            # Drop image/CSS pages unless explicitly included
            is_image = content_type.startswith("image/")
            is_css = content_type == "text/css"
            if is_image and not self.config.include_images:
                return
            if is_css and not self.config.include_css:
                return

            # Apply exclusion filters — silently drop if matched
            if should_exclude(
                page,
                self.config.exclude_bytes,
                self.config.exclude_words,
                self.config.exclude_lines,
            ):
                return

            # Only parse HTML-ish content for links and functions
            is_html = "html" in content_type or "xml" in content_type

            if is_html:
                # Extract links
                all_links = self._page_parser.extract_links(html, final_url)
                for link in all_links:
                    norm = self._normalize_url(link)
                    if self._is_in_scope(norm, seed_domains):
                        page.child_urls.append(norm)
                    else:
                        if norm not in page.external_urls:
                            page.external_urls.append(norm)
                        self._result.external_urls.add(norm)

                # Extract and fetch JS
                inline_scripts = self._page_parser.extract_inline_scripts(html)
                script_srcs = self._page_parser.extract_script_srcs(html, final_url)

                all_js_sources = list(inline_scripts)
                if script_srcs:
                    fetched = await asyncio.gather(
                        *[self._fetch_js(src) for src in script_srcs],
                        return_exceptions=True,
                    )
                    for text in fetched:
                        if isinstance(text, str) and text:
                            all_js_sources.append(text)

                js_endpoints: list = []
                js_websockets: list = []
                for js_src in all_js_sources:
                    js_endpoints.extend(
                        self._js_parser.extract_endpoints(js_src, final_url)
                    )
                    js_websockets.extend(
                        self._js_parser.extract_websockets(js_src)
                    )

                # Detect functions
                page.functions = self._analyzer.analyze(
                    html=html,
                    base_url=final_url,
                    intercepted_urls=fetch.intercepted_requests,
                    js_endpoints=js_endpoints,
                    js_websockets=js_websockets,
                )

            # Record the page
            self._stats["pages"] += 1
            self._stats["functions"] += len(page.functions)
            self._result.pages.append(page)

            # Enqueue child URLs (respecting max_depth)
            if is_html and (
                self.config.max_depth is None or depth < self.config.max_depth
            ):
                for child_url in page.child_urls:
                    # Skip image/CSS URLs unless the user opted in
                    child_ext = urlparse(child_url).path.rsplit(".", 1)
                    child_ext = ("." + child_ext[-1].lower()) if len(child_ext) == 2 else ""
                    if child_ext in _IMAGE_EXTENSIONS and not self.config.include_images:
                        continue
                    if child_ext in _CSS_EXTENSIONS and not self.config.include_css:
                        continue
                    async with self._visited_lock:
                        if child_url not in self._visited:
                            self._visited.add(child_url)
                            await self._queue.put(
                                (child_url, depth + 1, final_url)
                            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_seed_domains(self) -> set:
        domains = set()
        for url in self.config.seed_urls:
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc.lower())
        return domains

    def _is_in_scope(self, url: str, seed_domains: set) -> bool:
        try:
            netloc = urlparse(url).netloc.lower()
        except Exception:
            return False
        for domain in seed_domains:
            if netloc == domain or netloc.endswith("." + domain):
                return True
        return False

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Canonical form: remove fragment, strip trailing slash (not root),
        sort query parameters for deduplication.
        """
        try:
            p = urlparse(url)
            # Sort query params for dedup
            qs_sorted = urlencode(sorted(parse_qsl(p.query)))
            path = p.path.rstrip("/") or "/"
            return urlunparse((p.scheme, p.netloc, path, p.params, qs_sorted, ""))
        except Exception:
            return url

    async def _fetch_js(self, url: str) -> str:
        """Fetch a JS file with httpx (no browser needed)."""
        try:
            resp = await self._http_client.get(url)
            content = resp.content
            if len(content) > _MAX_JS_BYTES:
                return ""
            return content.decode("utf-8", errors="replace")
        except Exception:
            return ""

    async def _fetch_robots_and_sitemaps(self, seed_domains: set) -> list:
        """
        Fetch robots.txt for each seed domain, parse Disallow/Allow/Sitemap
        directives, and recursively parse any discovered sitemaps.

        Stores parsed data in self._result.robots_data and returns a list of
        in-scope URLs to add to the crawl queue.
        """
        discovered: list = []
        seen_seeds: set = set()

        for seed_url in self.config.seed_urls:
            parsed = urlparse(seed_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base in seen_seeds:
                continue
            seen_seeds.add(base)

            entry = {
                "domain": parsed.netloc,
                "disallowed": [],
                "allowed": [],
                "sitemaps": [],
            }
            sitemap_urls: list = []

            # --- Fetch robots.txt ---
            robots_url = f"{base}/robots.txt"
            try:
                resp = await self._http_client.get(robots_url)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        line = line.strip()
                        lower = line.lower()
                        if lower.startswith("disallow:"):
                            path = line[9:].split("#")[0].strip()
                            if path and path != "/":
                                entry["disallowed"].append(path)
                                full = base + path if path.startswith("/") else path
                                if self._is_in_scope(full, seed_domains):
                                    discovered.append(full)
                        elif lower.startswith("allow:"):
                            path = line[6:].split("#")[0].strip()
                            if path:
                                entry["allowed"].append(path)
                        elif lower.startswith("sitemap:"):
                            sm = line[8:].split("#")[0].strip()
                            if sm and sm not in sitemap_urls:
                                sitemap_urls.append(sm)
                                entry["sitemaps"].append(sm)
            except Exception as exc:
                reason = str(exc) or f"{type(exc).__name__}"
                self._result.errors.append({"url": robots_url, "reason": reason})

            # Always try /sitemap.xml as a fallback
            default_sm = f"{base}/sitemap.xml"
            if default_sm not in sitemap_urls:
                sitemap_urls.append(default_sm)

            # --- Parse sitemaps ---
            for sm_url in sitemap_urls:
                sm_urls = await self._fetch_sitemap(sm_url, seed_domains)
                if sm_urls:
                    discovered.extend(sm_urls)
                    if sm_url not in entry["sitemaps"]:
                        entry["sitemaps"].append(sm_url)

            self._result.robots_data.append(entry)

        return discovered

    async def _fetch_sitemap(self, sitemap_url: str, seed_domains: set) -> list:
        """
        Fetch and parse a sitemap XML (urlset or sitemapindex).
        Returns a list of in-scope URLs found.
        """
        urls: list = []
        try:
            resp = await self._http_client.get(sitemap_url)
            if resp.status_code != 200:
                return []
            root = ET.fromstring(resp.text)
            # Strip namespace prefix for tag comparison
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"
            if "sitemapindex" in root.tag:
                # Sitemap index — recurse into child sitemaps
                for child in root.findall(f"{ns}sitemap"):
                    loc = child.find(f"{ns}loc")
                    if loc is not None and loc.text:
                        child_urls = await self._fetch_sitemap(loc.text.strip(), seed_domains)
                        urls.extend(child_urls)
            else:
                # Regular sitemap urlset
                for url_elem in root.findall(f"{ns}url"):
                    loc = url_elem.find(f"{ns}loc")
                    if loc is not None and loc.text:
                        url = loc.text.strip()
                        if self._is_in_scope(url, seed_domains):
                            urls.append(url)
        except Exception as exc:
            reason = str(exc) or type(exc).__name__
            self._result.errors.append(
                {"url": sitemap_url, "reason": f"Sitemap parse error: {reason}"}
            )
        return urls

    def _print_tally(self, current_url: str) -> None:
        if self.config.quiet:
            return
        try:
            term_width = shutil.get_terminal_size((80, 20)).columns
        except Exception:
            term_width = 80
        prefix = (
            f"\r[*] Pages: {self._stats['pages']} | "
            f"Functions: {self._stats['functions']} | "
            f"Current: "
        )
        max_url_len = max(10, term_width - len(prefix) - 1)
        display_url = (
            current_url
            if len(current_url) <= max_url_len
            else "..." + current_url[-(max_url_len - 3):]
        )
        line = prefix + display_url
        # Pad with spaces to overwrite previous longer line
        sys.stdout.write(line.ljust(term_width - 1))
        sys.stdout.flush()
