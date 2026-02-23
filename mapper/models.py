from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectedFunction:
    """A single interactive function discovered on a page."""

    function_type: str
    # "file_upload" | "login_form" | "search" | "form_generic" |
    # "download_link" | "api_endpoint" | "input_field" | "websocket"

    description: str
    method: Optional[str]   # "GET", "POST", "PUT", "PATCH", "DELETE", None
    action: Optional[str]   # Form action URL or API endpoint path
    details: dict           # Type-specific extras
    pentest_tests: list     # Populated at report time from tests.yaml


@dataclass
class Page:
    """A single crawled page and everything found on it."""

    url: str
    status_code: int
    byte_count: int
    word_count: int
    line_count: int
    depth: int
    parent_url: Optional[str]
    content_type: str
    redirect_url: Optional[str]
    functions: list = field(default_factory=list)
    child_urls: list = field(default_factory=list)
    external_urls: list = field(default_factory=list)


@dataclass
class CrawlResult:
    """Top-level container for all crawl output."""

    seed_urls: list
    pages: list = field(default_factory=list)
    external_urls: set = field(default_factory=set)
    errors: list = field(default_factory=list)  # [{"url": ..., "reason": ...}]
    robots_data: list = field(default_factory=list)  # [{"domain": ..., "disallowed": [...], "allowed": [...], "sitemaps": [...]}]


@dataclass
class CrawlConfig:
    """Configuration built from CLI arguments."""

    seed_urls: list
    headers: dict               # Merged cookie + explicit headers
    rate_limit: int             # Requests per minute
    output_dir: Optional[str]
    max_workers: int
    exclude_bytes: list         # List of filter expressions e.g. ["=200", ">5000"]
    exclude_words: list
    exclude_lines: list
    max_depth: Optional[int]    # None = unlimited
    output_format: str          # "json" | "markdown"
    include_images: bool = False
    include_css: bool = False
    quiet: bool = False         # Suppress all console output (--json mode)
