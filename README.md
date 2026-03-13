# Mapper

A web application mapper for penetration testers. Crawls a target using a headless Chromium browser, discovers all pages and interactive functions, and generates structured output ready for security testing.

## Features

- Headless Chromium crawling via Playwright
- Detects interactive functions: forms, file uploads, login pages, search fields, API endpoints, WebSockets, download links
- Parses `robots.txt` and `sitemap.xml`
- Extracts API endpoints from JavaScript files
- Maps discovered functions to pentest checklists (OWASP Top 10, WSTG, HackTricks, PortSwigger)
- Multiple output formats: JSON, Markdown, plain text files
- Slim `page-functions.json` output for AI-assisted checklist generation
- Configurable rate limiting, concurrency, crawl depth, and page filters
- Cookie and custom header support for authenticated crawls
- External URL tracking — recorded in `external.txt` but not crawled by default (`--external` to enable)

## Requirements

- Python 3.10+
- Chromium (installed via Playwright)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/mapper.git
cd mapper
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
python mapper.py <URL> [OPTIONS]
```

### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--cookie` | `-c` | Cookie header value for authenticated crawls | |
| `--header` | `-H` | Custom HTTP header (repeatable) | |
| `--rate-limit` | | Max requests per minute | 60 |
| `--output` | `-o` | Output folder name | |
| `--threads` | `-t` | Max concurrent workers | 10 |
| `--max-depth` | | Maximum crawl depth | |
| `--format` | | Output format: `json` or `markdown` | json |
| `--exclude-bytes` | `-eb` | Filter pages by byte count (e.g. `=0`, `<100`) | |
| `--exclude-words` | `-ew` | Filter pages by word count | |
| `--exclude-lines` | `-el` | Filter pages by line count | |
| `--img` | | Include image files | |
| `--css` | | Include CSS files | |
| `--json` | | Print JSON to stdout only | |
| `--external` | | Crawl external (out-of-scope) URLs | |

### Examples

```bash
# Basic crawl with output folder
python mapper.py https://example.com -o results

# Authenticated crawl with session cookie (short flags)
python mapper.py https://example.com -c "session=abc123" -o results

# Limit depth and threads, markdown output
python mapper.py https://example.com --max-depth 3 -t 5 --format markdown -o results

# Filter out empty/tiny pages
python mapper.py https://example.com -o results -eb "=0" -eb "<100"

# Add custom headers
python mapper.py https://example.com -H "Authorization: Bearer TOKEN" -o results

# Include external URLs in the crawl
python mapper.py https://example.com --external -o results
```

## Output Files

All files are written to the specified output folder (`-o`):

| File | Contents |
|------|----------|
| `report.json` | Full structured report with pages, functions, and pentest tests |
| `report.md` | Markdown version of the report (with `--format markdown`) |
| `page-functions.json` | Slim report — pages with their discovered functions only (no pentest tests); ideal for AI-assisted checklist generation |
| `tree.txt` | ASCII tree view of discovered pages and functions |
| `urls.txt` | All discovered URLs (no query parameters) |
| `urls_params.txt` | All discovered URLs with query parameters |
| `params.txt` | Unique parameter names across all pages |
| `js.txt` | JavaScript file URLs |
| `robots.txt` | Summary of robots.txt rules |
| `external.txt` | External (out-of-scope) URLs found during the crawl; always written regardless of `--external` |

## Detected Function Types

- **file_upload** — File upload forms
- **login_form** — Login/authentication forms
- **search** — Search fields
- **form_generic** — Generic HTML forms
- **download_link** — Links to downloadable files
- **api_endpoint** — REST/GraphQL API endpoints (from JS analysis and network interception)
- **input_field** — Standalone input fields
- **websocket** — WebSocket connections

Each detected function includes a list of pentest tests mapped from `tests.yaml`, sourced from OWASP Top 10, OWASP API Security Top 10, WSTG, HackTricks, and PortSwigger.

## License

[GPL v3](LICENSE)
