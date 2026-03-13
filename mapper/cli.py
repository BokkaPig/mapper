from __future__ import annotations

import asyncio
import sys

import click

from .crawler import Crawler
from .filters import parse_filter_expr
from .models import CrawlConfig
from .reporter import Reporter


def _parse_header(value: str) -> tuple:
    """Split 'Header:Value' into (header, value). Raises UsageError if malformed."""
    if ":" not in value:
        raise click.UsageError(
            f"Invalid --header value {value!r}. "
            "Expected format: 'HeaderName:HeaderValue'"
        )
    name, _, val = value.partition(":")
    return name.strip(), val.strip()


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("urls", nargs=-1, required=True, metavar="URL [URL ...]")
@click.option(
    "-c",
    "--cookie",
    default=None,
    metavar="STRING",
    help="Cookie header value, e.g. 'session=abc123; token=xyz'",
)
@click.option(
    "-H",
    "--header",
    "raw_headers",
    multiple=True,
    metavar="Header:Value",
    help="Extra HTTP header in 'Header:Value' format. Repeatable.",
)
@click.option(
    "--rate-limit",
    default=60,
    show_default=True,
    type=int,
    metavar="N",
    help="Max requests per minute.",
)
@click.option(
    "-o",
    "--output",
    "output_dir",
    default=None,
    metavar="FOLDER",
    help="Output folder name. Omit to suppress file output.",
)
@click.option(
    "-t",
    "--threads",
    default=10,
    show_default=True,
    type=int,
    metavar="N",
    help="Max concurrent workers.",
)
@click.option(
    "-eb",
    "--exclude-bytes",
    "exclude_bytes",
    multiple=True,
    metavar="EXPR",
    help=(
        "Exclude pages matching byte count expression. "
        "Supports =N, <N, >N (e.g. '=0', '<200', '>50000'). Repeatable."
    ),
)
@click.option(
    "-ew",
    "--exclude-words",
    "exclude_words",
    multiple=True,
    metavar="EXPR",
    help="Exclude pages matching word count expression. Repeatable.",
)
@click.option(
    "-el",
    "--exclude-lines",
    "exclude_lines",
    multiple=True,
    metavar="EXPR",
    help="Exclude pages matching line count expression. Repeatable.",
)
@click.option(
    "--max-depth",
    default=None,
    type=int,
    metavar="N",
    help="Maximum crawl depth. Default: unlimited.",
)
@click.option(
    "--format",
    "output_format",
    default="json",
    show_default=True,
    type=click.Choice(["json", "markdown"], case_sensitive=False),
    help="Output report format.",
)
@click.option(
    "--img",
    "include_images",
    is_flag=True,
    default=False,
    help="Include image files in the output (excluded by default).",
)
@click.option(
    "--css",
    "include_css",
    is_flag=True,
    default=False,
    help="Include CSS files in the output (excluded by default).",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Suppress all output and print the report as JSON to stdout when done.",
)
@click.option(
    "--external",
    "crawl_external",
    is_flag=True,
    default=False,
    help="Crawl external (out-of-scope) URLs. Off by default; always recorded in external.txt.",
)
def main(
    urls,
    cookie,
    raw_headers,
    rate_limit,
    output_dir,
    threads,
    exclude_bytes,
    exclude_words,
    exclude_lines,
    max_depth,
    output_format,
    include_images,
    include_css,
    json_output,
    crawl_external,
):
    """
    \b
    Web Application Mapper — Pentest Discovery Tool
    ================================================
    Crawls web applications using a headless browser, discovers all pages
    and interactive functions, and outputs a pentest checklist per function.

    \b
    Examples:
      mapper.py https://example.com -o results
      mapper.py https://example.com --cookie "session=abc" --threads 5
      mapper.py https://example.com -o out --exclude-bytes =0 --exclude-bytes "<100"
      mapper.py https://example.com -o out --format markdown --max-depth 3
    """
    # Validate and build headers dict
    headers: dict = {}
    for raw in raw_headers:
        try:
            name, val = _parse_header(raw)
            headers[name] = val
        except click.UsageError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
    if cookie:
        headers["Cookie"] = cookie

    # Validate filter expressions early
    for label, exprs in [
        ("--exclude-bytes", exclude_bytes),
        ("--exclude-words", exclude_words),
        ("--exclude-lines", exclude_lines),
    ]:
        for expr in exprs:
            try:
                parse_filter_expr(expr)
            except ValueError as exc:
                click.echo(f"Error in {label}: {exc}", err=True)
                sys.exit(1)

    config = CrawlConfig(
        seed_urls=list(urls),
        headers=headers,
        rate_limit=rate_limit,
        output_dir=output_dir,
        max_workers=threads,
        exclude_bytes=list(exclude_bytes),
        exclude_words=list(exclude_words),
        exclude_lines=list(exclude_lines),
        max_depth=max_depth,
        output_format=output_format.lower(),
        include_images=include_images,
        include_css=include_css,
        quiet=json_output,
        crawl_external=crawl_external,
    )

    if not json_output:
        click.echo(f"[*] Starting mapper against: {', '.join(urls)}")
        click.echo(
            f"[*] Threads: {threads} | Rate limit: {rate_limit} req/min"
            + (f" | Max depth: {max_depth}" if max_depth else "")
        )
        if output_dir:
            click.echo(f"[*] Output: {output_dir}/")
        click.echo("")

    # Run the async crawl
    try:
        result = asyncio.run(_run(config))
    except KeyboardInterrupt:
        click.echo("\n[!] Interrupted by user.", err=True)
        sys.exit(130)

    reporter = Reporter(result, output_dir or ".", output_format.lower())

    if json_output:
        if output_dir:
            reporter.generate()
        print(reporter.to_json())
    else:
        reporter.print_summary()
        if output_dir:
            reporter.generate()
            click.echo(f"[*] Files written to: {output_dir}/")


async def _run(config: CrawlConfig):
    crawler = Crawler(config)
    return await crawler.run()
