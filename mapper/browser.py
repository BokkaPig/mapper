from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BrowserFetchResult:
    url: str                        # Requested URL
    final_url: str                  # URL after all redirects (including JS)
    status_code: int
    html: str                       # Fully rendered DOM (post-JS execution)
    response_headers: dict
    intercepted_requests: list      # List of {"url": ..., "method": ...} dicts


class BrowserFetchError(Exception):
    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Browser fetch failed for {url}: {reason}")


class BrowserManager:
    """
    Manages a single Playwright Chromium instance shared across all crawl
    workers. Each page fetch gets its own isolated BrowserContext so that
    cookies/storage do not leak between requests.

    A semaphore caps the number of simultaneously open browser pages to
    prevent memory exhaustion.
    """

    def __init__(self, headers: dict, max_concurrent_pages: int = 10):
        self._headers = headers
        self._page_semaphore = asyncio.Semaphore(max_concurrent_pages)
        self._playwright = None
        self._browser = None

    async def start(self) -> None:
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
            ],
        )

    async def stop(self) -> None:
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def fetch_page(self, url: str) -> BrowserFetchResult:
        """
        Open a new context + page, navigate to the URL, wait for network
        idle (or timeout), capture the fully rendered HTML and all network
        requests made during page load, then close the context.
        """
        async with self._page_semaphore:
            context = await self._browser.new_context(
                extra_http_headers=self._headers,
                ignore_https_errors=True,
            )

            intercepted: list = []

            async def on_request(request):
                intercepted.append({
                    "url": request.url,
                    "method": request.method.upper(),
                })

            context.on("request", on_request)

            page = await context.new_page()
            response = None
            try:
                try:
                    response = await page.goto(
                        url,
                        timeout=30_000,
                        wait_until="networkidle",
                    )
                except Exception:
                    # Fallback: domcontentloaded for pages that never reach
                    # networkidle (long-polling, WebSocket heartbeats, etc.)
                    try:
                        response = await page.goto(
                            url,
                            timeout=15_000,
                            wait_until="domcontentloaded",
                        )
                    except Exception as exc:
                        raise BrowserFetchError(url, str(exc)) from exc

                final_url = page.url
                html = await page.content()
                status = response.status if response else 0
                resp_headers = dict(response.headers) if response else {}

                return BrowserFetchResult(
                    url=url,
                    final_url=final_url,
                    status_code=status,
                    html=html,
                    response_headers=resp_headers,
                    intercepted_requests=intercepted,
                )
            finally:
                await context.close()
