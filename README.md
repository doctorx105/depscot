# DepScout

![Go Version](https://img.shields.io/github/go-mod/go-version/doctorx105/depscot)
![Release](https://img.shields.io/github/v/release/doctorx105/depscot?include_prereleases)
![Build Status](https://github.com/doctorx105/depscot/workflows/Release%20DepScout/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/doctorx105/depscot?style=social)
![Go Report Card](https://goreportcard.com/badge/github.com/doctorx105/depscot)

<div align="center">
<pre>
  _____             _____                 _
 |  __ \           / ____|               | |
 | |  | | ___ _ __| (___   ___ ___  _   _| |_
 | |  | |/ _ \ '_ \\___ \ / __/ _ \| | | | __|
 | |__| |  __/ |_) |___) | (_| (_) | |_| | |_
 |_____/ \___| .__/_____/ \___\___/ \__,_|\__|
             | |
             |_|
</pre>
</div>

<p align="center">
    <b>Concurrent scanner for detecting unclaimed npm packages (Dependency Confusion).</b>
</p>

---

## Features

### Core Scanning
- **Dependency Confusion Detection** — Scans JavaScript files for `require()` and `import` statements, then checks each discovered package name against the public npm registry. A `404` response means the package is unclaimed and a potential attack vector.
- **Dual Parsing Engine**
  - **Regex Mode** *(default)* — Fast, high-performance scanning using fine-tuned regular expressions.
  - **Deep Scan Mode** (`--deep-scan`) — High-accuracy scanning using a full JavaScript Abstract Syntax Tree (AST) parser to eliminate false positives from comments and non-code contexts. Automatically falls back to regex if AST parsing fails.

### Smart Input Handling
- **Flexible Input Sources** — Accepts targets from a single URL (`-u`), a target list file (`-f`), a local directory (`-d`), or piped via `stdin`.
- **Automatic Subdomain / Hostname Normalisation** — Entries in `-f` files (or via `-u` / `stdin`) that do not include an `http://` or `https://` scheme are automatically promoted to `https://`. If the HTTPS connection fails, the tool silently retries with `http://` before surfacing an error. This means your wordlist can contain raw hostnames like `api.example.com` without any pre-processing.
- **HTML Page Crawling** — When a target URL returns an HTML page, the response is automatically parsed for `<script src="…">` tags and every discovered JavaScript URL is queued for analysis. Pointing the tool at a web application root (e.g. `https://app.example.com`) is enough to reach all its bundled scripts.

### Source Map Analysis
- **Automatic Source Map Discovery** — After fetching any JavaScript file, DepScout scans the response body for a `//# sourceMappingURL=…` annotation. When found, the referenced `.map` file is automatically fetched and analysed. Works for both remote URLs and local files scanned with `-d`.
- **Deep Source Map Extraction** — Source map files (`.js.map`) are analysed with two complementary strategies:
  1. **Path scan** — Every entry in the `sources[]` array is inspected for `node_modules/<pkg>` path segments. This reveals packages that were tree-shaken out of the final bundle (their code was removed, but the path remains in the map).
  2. **Content re-scan** — Each non-null `sourcesContent[]` entry (the original, unminified source file) is fed back through the full JS extraction pipeline (regex or AST depending on `--deep-scan`). Because these strings are the pre-minification originals, the scanner produces far more accurate results than it would on the minified bundle text.

### Headless Browser Mode
- **Dynamic Script Discovery** (`--headless`) — Launches a real headless Chrome/Chromium browser to navigate target pages. Unlike static HTML parsing, the browser actually executes the page JavaScript, discovering scripts that are injected dynamically by SPA frameworks, webpack lazy-loaders, and runtime `document.createElement('script')` calls.
- **Dual Collection Strategies**
  - **Network Interception** — Hooks into the Chrome DevTools Protocol at the network layer to capture every `Script`-typed request Chrome issues, including `dynamic import()`, route-based code splitting, and `fetch()`-driven injection.
  - **DOM Fallback** — After a 4-second dwell period (to allow SPAs to bootstrap), `document.querySelectorAll('script[src]')` is evaluated in the live DOM to catch scripts that were loaded from cache and therefore did not fire a fresh network event.
- **Anti-Detection Hardening** — Each headless crawl is equipped with multiple layers of bot-detection evasion:
  - **Random User-Agent Rotation** — A random profile is chosen per-crawl from a pool of 19 realistic browser signatures spanning Chrome, Firefox, Edge, and Safari across Windows, macOS, and Linux. The profile includes matching `navigator.platform` and `Accept-Language` headers so all three values stay consistent with each other.
  - **Allocator-Level Flags** — `--disable-blink-features=AutomationControlled` and `--exclude-switches=enable-automation` are applied at browser startup, removing the primary Chrome automation class that most bot-detection libraries check first.
  - **Pre-page-script JS Injection** — `Page.addScriptToEvaluateOnNewDocument` injects a masking script *before* any page-level JavaScript runs. It hides `navigator.webdriver`, spoofs `navigator.plugins` (headless Chrome has none), aligns `navigator.languages` with the sent `Accept-Language`, and ensures `window.chrome.runtime` exists.

### Networking
- **Adaptive Rate Limiting** — A smart per-domain token-bucket limiter starts at 2 req/s and ramps up by +0.2 on each successful response (AIMD-style). On a `429 Too Many Requests`, the rate is cut by ×0.7 and exponential backoff is applied. Domains that repeatedly 429 are permanently discarded.
- **Proxy Support** — Round-robin proxy rotation from a file (`-p`) or single proxy (`-proxy`). All proxies are live-checked against a probe URL before the scan starts.
- **Custom Headers** — Inject authentication tokens, cookies, or any other header with `-H` (repeatable).
- **TLS Bypass** — `--skip-verify` disables certificate validation for targets with self-signed or expired certificates.

### Output
- **Real-Time Progress Bar** — Displays file count, completion percentage, live requests/second, and estimated time remaining.
- **Multiple Output Formats** — Human-readable terminal output or machine-readable JSON (`-json`).
- **File Output** — Write results to a file with `-o` without suppressing terminal display.

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/doctorx105/depscot.git
cd depscot

# Build the binary
go build -o depscout ./cmd/depscout

# Optional: move to PATH (Linux / macOS)
sudo mv depscout /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/doctorx105/depscot/cmd/depscout@latest
```

### Binary Releases

Pre-built binaries for Windows, Linux, and macOS are available on the [releases page](https://github.com/doctorx105/depscot/releases).

---

## Quick Start

**Scan a single JavaScript file:**
```bash
depscout -u https://example.com/assets/app.js
```

**Scan a local directory (JS + TS files):**
```bash
depscout -d /path/to/js/files
```

**Scan with AST-based deep scan for higher accuracy:**
```bash
depscout -d /path/to/js/files --deep-scan
```

**Scan a list of targets — URLs and bare subdomains can be mixed freely:**
```bash
# targets.txt can contain any combination:
#   https://app.example.com/bundle.js
#   api.example.com              ← no scheme needed, https:// is auto-added
#   http://legacy.example.com
#   staging.example.com

depscout -f targets.txt
```

**Scan web application roots (HTML → script discovery):**
```bash
# The tool fetches the page, parses <script src="…"> tags,
# and queues every discovered JS file automatically.
depscout -f subdomains.txt
```

**Use the headless browser to capture dynamically loaded scripts (requires Chrome):**
```bash
depscout -f subdomains.txt --headless
```

**Combine headless + deep scan for maximum coverage:**
```bash
depscout -f subdomains.txt --headless --deep-scan -v
```

**Scan with authentication headers:**
```bash
depscout -f targets.txt -H "Authorization: Bearer <token>" -H "Cookie: session=abc123"
```

**Output results as JSON to a file:**
```bash
depscout -f targets.txt -json -o findings.json --silent
```

**Pipe targets from another tool:**
```bash
subfinder -d example.com -silent | depscout
```

---

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | A single target URL, bare hostname, or local file path. | — |
| `-f` | File containing a list of targets (URLs, bare hostnames, or local paths). Bare hostnames are auto-promoted to `https://`. | — |
| `-d` | Local directory to scan recursively for `.js` and `.ts` files. | — |
| `-c` | Number of concurrent workers. | `25` |
| `-t` | HTTP request timeout in seconds. | `10` |
| `-l` | Maximum requests per second per domain (upper ceiling for the auto rate limiter). | `30` |
| `-H` | Custom HTTP header to include in all requests. Can be specified multiple times (e.g. `-H "X-Api-Key: …"`). | — |
| `-o` | File to write results to (text or JSON depending on `-json`). | stdout |
| `-p` | File containing a list of proxies (`http://`, `https://`, or `socks5://`). Proxies are live-checked before the scan. | — |
| `-proxy` | A single proxy server (e.g. `http://127.0.0.1:8080`). Cannot be combined with `-p`. | — |
| `--deep-scan` | Enable deep scan using a full JavaScript AST parser. Slower but eliminates false positives from comments and string literals. Automatically falls back to regex if parsing fails. | `false` |
| `--headless` | Enable headless Chrome/Chromium to discover dynamically injected scripts. Requires Chrome or Chromium to be installed and available in `PATH`. Includes automatic random User-Agent rotation and anti-detection hardening per crawl. | `false` |
| `-json` | Output results in JSON format. | `false` |
| `--max-file-size` | Maximum file size to download and process, in KB. | `10240` |
| `--no-limit` | Disable the file size limit entirely. | `false` |
| `--skip-verify` | Skip TLS certificate verification. Also passed to the headless browser when `--headless` is used. | `false` |
| `-v` | Enable verbose output (debug logs, per-domain rate changes, source map discoveries, etc.). | `false` |
| `--silent` | Suppress all output except findings. Useful when piping results. | `false` |
| `--no-color` | Disable ANSI colour codes in terminal output. | `false` |

---

## How It Works

```
Input targets (URLs / hostnames / local files)
        │
        ▼
 ┌─ NormalizeTarget ──────────────────────────────────────────────────┐
 │  bare hostname → https://  (http:// fallback on connection error)  │
 └────────────────────────────────────────────────────────────────────┘
        │
        ▼
 FetchJS ──── HTML response ──────► parse <script src="…"> ──► FetchJS (each)
    │
    ├──── --headless + page URL ──► HeadlessCrawl (Chrome CDP)
    │          └── network intercept + DOM query ──► FetchJS (each script)
    │
    └──── JS response ────────────► extract //# sourceMappingURL=…
                │                          └──► FetchJS (.map file)
                │
                ▼
           ProcessJS  ──── regex / AST ──► VerifyPackage ──► npm 404? → FINDING
                │
           .map file ──────────────────► ProcessSourceMap
                                              ├── node_modules paths ──► VerifyPackage
                                              └── sourcesContent[] ────► ProcessJS ──► VerifyPackage
```

---

## Headless Mode — Requirements

`--headless` requires a Chromium-based browser installed on the system:

| OS | Install |
|----|---------|
| **Debian / Ubuntu** | `sudo apt install chromium-driver chromium` |
| **Fedora / RHEL** | `sudo dnf install chromium` |
| **macOS** | `brew install --cask google-chrome` or `brew install chromium` |
| **Windows** | Install [Google Chrome](https://www.google.com/chrome/) or [Chromium](https://www.chromium.org/getting-chromium/) |

The binary must be reachable via `PATH`.  If Chrome is installed but not found, DepScout will print a clear error message and exit rather than silently falling back.

> **Note:** Headless mode launches one browser process shared across all workers.  Each individual crawl job gets its own isolated browser tab.  If you scan a large number of URLs with `--headless`, consider reducing concurrency with `-c` to keep memory usage reasonable (e.g. `-c 5`).

---

## Source Map Coverage

DepScout treats source maps as a first-class analysis target because they often reveal far more about an application's dependency graph than the minified bundle text:

- **Tree-shaken packages** — A package imported in source but fully optimised away by the bundler will not appear in the minified JS.  Its original path (`node_modules/pkg/…`) remains in the `sources[]` array of the source map.
- **Unminified originals** — `sourcesContent[]` contains the pre-minification source of every bundled module.  Running the package extractor on these strings yields cleaner, more complete results than running it on the minified output.

Source maps are discovered in two ways:
1. **Automatic annotation following** — Any `//# sourceMappingURL=…` comment found in a fetched JS file causes the referenced map to be fetched and queued automatically.
2. **Direct targeting** — You can point DepScout directly at a `.map` file URL or include `.map` files in a local directory scan.

---

## Disclaimer

**Usage Warning & Responsibility**

This tool is intended for security professionals and researchers for legitimate testing purposes only. Running DepScout against a target generates HTTP requests to the target and to the public npm registry. You are solely responsible for your actions and must have explicit written permission to test any system you do not own. The author of this tool is not responsible for any misuse or damage caused by this program.

---

## Documentation

- [Changelog](CHANGELOG.md) — Latest updates and version history.

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a pull request.

## License

This project is licensed under the MIT License.
