from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import yaml

from .models import CrawlResult, Page, DetectedFunction

# Resolve tests.yaml relative to this file (always alongside the package)
_TESTS_YAML = Path(__file__).parent.parent / "tests.yaml"


class Reporter:
    """
    Generates output files:
      tree.txt        — ASCII path tree with functions
      urls.txt        — Base URLs only (no query string), deduplicated
      urls_params.txt — Full URLs that have query parameters
      params.txt      — Unique parameter names discovered, sorted
      js.txt          — Deduplicated list of JavaScript file URLs
      robots.txt      — robots.txt disallow/allow/sitemap summary
      report.json     — Full structured report (default)
      report.md       — Markdown report (--format markdown)
      external.txt    — External URLs found but not crawled
    """

    def __init__(self, result: CrawlResult, output_dir: str, output_format: str):
        self.result = result
        self.output_dir = Path(output_dir)
        self.output_format = output_format
        self._tests: dict = self._load_tests()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._inject_pentest_tests()
        self._write_urls_txt()
        self._write_urls_params_txt()
        self._write_params_txt()
        self._write_js_txt()
        self._write_external_txt()
        self._write_tree_txt()
        self._write_robots_txt()
        if self.output_format == "markdown":
            self._write_report_md()
        else:
            self._write_report_json()
        self._write_page_functions_json()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_tests(self) -> dict:
        if not _TESTS_YAML.exists():
            return {}
        with open(_TESTS_YAML, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def _inject_pentest_tests(self) -> None:
        """Populate pentest_tests on each DetectedFunction from tests.yaml."""
        for page in self.result.pages:
            for fn in page.functions:
                fn.pentest_tests = self._tests.get(fn.function_type, [])

    # ------------------------------------------------------------------
    # urls.txt — base URLs only (no query string), deduplicated
    # ------------------------------------------------------------------

    def _write_urls_txt(self) -> None:
        seen: set = set()
        path = self.output_dir / "urls.txt"
        with open(path, "w", encoding="utf-8") as f:
            for page in self.result.pages:
                parsed = urlparse(page.url)
                base = parsed._replace(query="", fragment="").geturl()
                if base not in seen:
                    seen.add(base)
                    f.write(base + "\n")

    # ------------------------------------------------------------------
    # urls_params.txt — full URLs that have query parameters
    # ------------------------------------------------------------------

    def _write_urls_params_txt(self) -> None:
        path = self.output_dir / "urls_params.txt"
        with open(path, "w", encoding="utf-8") as f:
            for page in self.result.pages:
                if urlparse(page.url).query:
                    f.write(page.url + "\n")

    # ------------------------------------------------------------------
    # params.txt — unique parameter names, sorted alphabetically
    # ------------------------------------------------------------------

    def _write_params_txt(self) -> None:
        param_names: set = set()
        for page in self.result.pages:
            query = urlparse(page.url).query
            if query:
                param_names.update(parse_qs(query).keys())
        path = self.output_dir / "params.txt"
        with open(path, "w", encoding="utf-8") as f:
            for name in sorted(param_names):
                f.write(name + "\n")

    # ------------------------------------------------------------------
    # js.txt — deduplicated JS file URLs
    # ------------------------------------------------------------------

    def _write_js_txt(self) -> None:
        js_urls: set = set()
        for page in self.result.pages:
            # Pages crawled that are JS files
            if "javascript" in page.content_type or page.url.lower().split("?")[0].endswith(".js"):
                js_urls.add(page.url)
            # Child URLs linked from this page that end in .js
            for child in page.child_urls:
                if child.lower().split("?")[0].endswith(".js"):
                    js_urls.add(child)
        path = self.output_dir / "js.txt"
        with open(path, "w", encoding="utf-8") as f:
            for url in sorted(js_urls):
                f.write(url + "\n")

    # ------------------------------------------------------------------
    # robots.txt — summary of robots.txt directives found per domain
    # ------------------------------------------------------------------

    def _write_robots_txt(self) -> None:
        has_content = any(
            e.get("disallowed") or e.get("allowed") or e.get("sitemaps")
            for e in self.result.robots_data
        )
        if not has_content:
            return
        path = self.output_dir / "robots.txt"
        lines = ["# robots.txt Analysis\n"]
        for entry in self.result.robots_data:
            lines.append(f"Domain: {entry['domain']}")
            disallowed = entry.get("disallowed", [])
            allowed = entry.get("allowed", [])
            sitemaps = entry.get("sitemaps", [])
            if disallowed:
                lines.append(f"  Disallowed paths ({len(disallowed)}):")
                for p in disallowed:
                    lines.append(f"    {p}")
            if allowed:
                lines.append(f"  Allowed paths ({len(allowed)}):")
                for p in allowed:
                    lines.append(f"    {p}")
            if sitemaps:
                lines.append(f"  Sitemaps ({len(sitemaps)}):")
                for s in sitemaps:
                    lines.append(f"    {s}")
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ------------------------------------------------------------------
    # external.txt
    # ------------------------------------------------------------------

    def _write_external_txt(self) -> None:
        path = self.output_dir / "external.txt"
        with open(path, "w", encoding="utf-8") as f:
            for url in sorted(self.result.external_urls):
                f.write(url + "\n")

    # ------------------------------------------------------------------
    # tree.txt
    # ------------------------------------------------------------------

    def _write_tree_txt(self) -> None:
        path = self.output_dir / "tree.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._build_tree())

    def _build_tree(self) -> str:
        """
        Build a Linux-tree-style ASCII representation grouped by domain.

        example.com
        ├── / [200]
        │   └── [search] Search form (GET /)
        └── /admin [200]
            └── [file_upload] File upload (POST /admin/upload)
        """
        by_domain: dict = defaultdict(list)
        for page in self.result.pages:
            parsed = urlparse(page.url)
            domain = parsed.netloc or "unknown"
            by_domain[domain].append(page)

        lines = []
        domains = sorted(by_domain.keys())

        for d_idx, domain in enumerate(domains):
            lines.append(domain)
            pages = sorted(by_domain[domain], key=lambda p: urlparse(p.url).path or "/")

            for p_idx, page in enumerate(pages):
                is_last_page = p_idx == len(pages) - 1
                page_conn = "└── " if is_last_page else "├── "
                child_pfx = "    " if is_last_page else "│   "

                path = urlparse(page.url).path or "/"
                lines.append(f"{page_conn}{path} [{page.status_code}]")

                for f_idx, fn in enumerate(page.functions):
                    is_last_fn = f_idx == len(page.functions) - 1
                    fn_conn = "└── " if is_last_fn else "├── "
                    lines.append(
                        f"{child_pfx}{fn_conn}[{fn.function_type}] {fn.description}"
                    )

            # Blank line between domains for readability
            if d_idx < len(domains) - 1:
                lines.append("")

        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # report.json
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Return the full report as a JSON string (for --json stdout mode)."""
        self._inject_pentest_tests()
        return json.dumps(self._build_report_dict(), indent=2)

    def _build_report_dict(self) -> dict:
        return {
            "meta": {
                "seed_urls": self.result.seed_urls,
                "total_pages": len(self.result.pages),
                "total_functions": sum(len(p.functions) for p in self.result.pages),
                "total_external_urls": len(self.result.external_urls),
                "errors": self.result.errors,
            },
            "pages": [self._page_to_dict(p) for p in self.result.pages],
        }

    def _write_report_json(self) -> None:
        path = self.output_dir / "report.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._build_report_dict(), f, indent=2)

    # ------------------------------------------------------------------
    # page-functions.json — slim output for AI checklist generation
    # ------------------------------------------------------------------

    def _write_page_functions_json(self) -> None:
        seed_hostnames = {urlparse(u).hostname for u in self.result.seed_urls}
        total_pages = len(self.result.pages)

        # First pass: deduplicate per page, filter localhost and third-party
        clean_pages = []
        for page in self.result.pages:
            seen: set = set()
            deduped_functions = []
            for fn in page.functions:
                if fn.action:
                    action_host = urlparse(fn.action).hostname
                    if action_host:
                        # Drop localhost/loopback
                        if action_host == "localhost" or action_host.startswith("127."):
                            continue
                        # Drop third-party (domain not in seed hosts)
                        if action_host not in seed_hostnames:
                            continue
                key = (fn.function_type, fn.method, fn.action)
                if key not in seen:
                    seen.add(key)
                    deduped_functions.append({
                        "type": fn.function_type,
                        "method": fn.method,
                        "action": fn.action,
                        "details": fn.details,
                    })
            clean_pages.append((page, deduped_functions))

        # Second pass: count pages each unique function appears on
        fn_page_count: dict = defaultdict(int)
        for _page, fns in clean_pages:
            for fn in fns:
                fn_page_count[(fn["type"], fn["method"], fn["action"])] += 1

        # Functions on 50%+ of pages are global
        threshold = max(1, total_pages * 0.5)
        global_keys = {k for k, count in fn_page_count.items() if count >= threshold}

        # Build global_functions list (deduplicated, sorted by seen_on_pages desc)
        global_functions = sorted(
            [
                {
                    "type": k[0],
                    "method": k[1],
                    "action": k[2],
                    "seen_on_pages": fn_page_count[k],
                }
                for k in global_keys
            ],
            key=lambda x: x["seen_on_pages"],
            reverse=True,
        )

        # Build per-page output, stripping global functions
        pages = []
        for page, fns in clean_pages:
            page_fns = [
                fn for fn in fns
                if (fn["type"], fn["method"], fn["action"]) not in global_keys
            ]
            pages.append({
                "url": page.url,
                "status_code": page.status_code,
                "content_type": page.content_type,
                "functions": page_fns,
            })

        total_functions = sum(len(p["functions"]) for p in pages) + len(global_functions)
        output = {
            "meta": {
                "seed_urls": self.result.seed_urls,
                "total_pages": len(pages),
                "total_functions": total_functions,
            },
            "global_functions": global_functions,
            "pages": pages,
        }
        path = self.output_dir / "page-functions.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

    def _page_to_dict(self, page: Page) -> dict:
        return {
            "url": page.url,
            "status_code": page.status_code,
            "byte_count": page.byte_count,
            "word_count": page.word_count,
            "line_count": page.line_count,
            "depth": page.depth,
            "content_type": page.content_type,
            "redirect_url": page.redirect_url,
            "functions": [self._fn_to_dict(fn) for fn in page.functions],
        }

    def _fn_to_dict(self, fn: DetectedFunction) -> dict:
        return {
            "type": fn.function_type,
            "description": fn.description,
            "method": fn.method,
            "action": fn.action,
            "details": fn.details,
            "pentest_tests": fn.pentest_tests,
        }

    # ------------------------------------------------------------------
    # report.md
    # ------------------------------------------------------------------

    def _write_report_md(self) -> None:
        path = self.output_dir / "report.md"
        lines = []

        lines.append("# Web Application Mapper — Pentest Report\n")
        lines.append(f"**Seed URLs:** {', '.join(self.result.seed_urls)}  ")
        lines.append(f"**Pages discovered:** {len(self.result.pages)}  ")
        lines.append(
            f"**Functions found:** "
            f"{sum(len(p.functions) for p in self.result.pages)}  "
        )
        lines.append(f"**External URLs:** {len(self.result.external_urls)}\n")
        lines.append("---\n")

        for page in self.result.pages:
            lines.append(f"## `{page.url}`\n")
            lines.append(
                f"| Status | Bytes | Words | Lines | Depth |"
            )
            lines.append(
                f"|--------|-------|-------|-------|-------|"
            )
            lines.append(
                f"| {page.status_code} | {page.byte_count} | "
                f"{page.word_count} | {page.line_count} | {page.depth} |"
            )
            lines.append("")

            if page.redirect_url:
                lines.append(f"> Redirected to: `{page.redirect_url}`\n")

            if not page.functions:
                lines.append("*No functions detected.*\n")
            else:
                lines.append("### Functions\n")
                for fn in page.functions:
                    lines.append(
                        f"#### [{fn.function_type}] {fn.description}\n"
                    )
                    lines.append(f"- **Method:** `{fn.method or 'unknown'}`")
                    lines.append(f"- **Action:** `{fn.action or 'N/A'}`")
                    if fn.details:
                        detail_str = ", ".join(
                            f"{k}: {v}" for k, v in fn.details.items()
                        )
                        lines.append(f"- **Details:** {detail_str}")
                    if fn.pentest_tests:
                        lines.append("\n**Pentest Checklist:**\n")
                        for test in fn.pentest_tests:
                            lines.append(f"- [ ] {test}")
                    lines.append("")

            lines.append("---\n")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """Print a summary table to stdout after crawl completes."""
        total_fn = sum(len(p.functions) for p in self.result.pages)
        print(f"\n{'='*60}")
        print(f"  Mapper Complete")
        print(f"{'='*60}")
        print(f"  Pages crawled   : {len(self.result.pages)}")
        print(f"  Functions found : {total_fn}")
        print(f"  External URLs   : {len(self.result.external_urls)}")
        print(f"  Errors          : {len(self.result.errors)}")
        if self.output_dir:
            print(f"  Output folder   : {self.output_dir}/")
            fmt = "report.md" if self.output_format == "markdown" else "report.json"
            print(f"    ├── tree.txt")
            print(f"    ├── urls.txt          (base URLs, no params)")
            print(f"    ├── urls_params.txt   (URLs with query strings)")
            print(f"    ├── params.txt        (unique parameter names)")
            print(f"    ├── js.txt            (JavaScript file URLs)")
            has_robots = any(
                e.get("disallowed") or e.get("allowed") or e.get("sitemaps")
                for e in self.result.robots_data
            )
            if has_robots:
                print(f"    ├── robots.txt        (robots.txt summary)")
            print(f"    ├── external.txt")
            print(f"    ├── {fmt}")
            print(f"    └── page-functions.json")
        print(f"{'='*60}\n")

        # Print the tree inline
        print(self._build_tree())

        # Print all URLs
        print("\n--- Discovered URLs ---")
        for page in self.result.pages:
            print(f"  {page.status_code}  {page.url}")

        # Print the pentest findings
        print("\n--- Pentest Findings ---")
        for page in self.result.pages:
            if not page.functions:
                continue
            print(f"\n{page.url} [{page.status_code}]  "
                  f"{page.byte_count}B / {page.word_count}W / {page.line_count}L")
            for fn in page.functions:
                method_str = fn.method or "?"
                print(f"  [{fn.function_type}] {fn.description}")
                if fn.pentest_tests:
                    for test in fn.pentest_tests:
                        print(f"    - {test}")
