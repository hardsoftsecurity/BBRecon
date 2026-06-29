# BBRecon — Bug Bounty Recon Framework

Automated, per-domain recon pipeline for bug bounty and web security assessments. Given one domain or a scope file, BBRecon runs subdomain enumeration, HTTP probing, endpoint crawling, secret extraction, parameter classification, screenshots, vulnerability scanning, and — optionally — active fuzzing across 9 vulnerability classes.

---

## Features

- **8-step automated pipeline** — subfinder → httpx → katana → SecretFinder → param classification → screenshots → nuclei → fuzzing
- **Batch mode** — process an entire scope file; output is isolated per domain
- **Parallel execution** — Steps 3 & 6 run concurrently; Steps 4, 5 & 7 run concurrently; fuzzing waits until classification finishes
- **Parameter auto-classification** — regex-based bucketing into SSRF, IDOR, XSS, Path Traversal, and Open Redirect candidates
- **Active fuzzing module** — 9 vuln-type fuzzing steps (XSS, SQLi, SSRF, IDOR, SSTI, CRLF, LFI, Open Redirect, Command Injection) fed by the classified parameter files
- **Authenticated fuzzing** — pass custom HTTP headers to all fuzzing tools with `--fuzz-headers`
- **Out-of-band detection** — supply an interactsh / Burp Collaborator URL via `--oob-url` for blind SSRF probes
- **Playwright screenshots** — headless Chromium captures 1280×900 PNGs with a dark-themed, searchable HTML gallery
- **tmux integration** — Nuclei runs in a dedicated tmux window when inside a session; falls back to a background process otherwise
- **Flexible skip flags** — independently skip any step by number (`--skip-steps`) or by name
- **Standalone screenshot mode** — screenshot any URL list and generate an HTML gallery without running the full pipeline

---

## Requirements

### Python

Python 3.7+ and the Playwright package:

```bash
pip install playwright
python -m playwright install chromium
```

### Critical tools (pipeline will abort if missing)

| Tool | Default path |
|------|-------------|
| subfinder | `~/Offensive-Security-Tools/Enumeration/subfinder` |
| httpx | `~/Offensive-Security-Tools/Enumeration/httpx` |
| katana | `~/Offensive-Security-Tools/Enumeration/katana` |

### Optional recon tools

| Tool | Purpose | Skip flag |
|------|---------|-----------|
| nuclei | Vulnerability scanning (Step 7) | `--skip-nuclei` |
| SecretFinder | JS secret extraction (Step 4) | `--skip-secretfinder` |

### Optional fuzzing tools (Step 8)

All fuzzing tools are optional. Missing tools log a warning at startup and their sub-step is skipped gracefully — they do not abort the pipeline.

| Tool | Vuln type | Install |
|------|-----------|---------|
| dalfox | XSS | `go install github.com/hahwul/dalfox/v2@latest` |
| kxss | XSS (pre-filter fallback) | `go install github.com/tomnomnom/hacks/kxss@latest` |
| ghauri | SQLi (default) | `git clone https://github.com/r0oth3x49/ghauri` |
| sqlmap | SQLi (alternative) | `pip install sqlmap` |
| ffuf | SSRF / IDOR / LFI / Redirect | `go install github.com/ffuf/ffuf/v2@latest` |
| qsreplace | Parameter injection helper | `go install github.com/tomnomnom/qsreplace@latest` |
| crlfuzz | CRLF injection | `go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest` |
| nuclei | SSRF / SSTI / Redirect / CMDi templates | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| interactsh-client | OOB callback URL generator | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourhandle/BBRecon.git
cd BBRecon
```

### 2. Install Python dependencies

```bash
pip install playwright
python -m playwright install chromium
```

### 3. Place your recon tools

By default, BBRecon looks for tools in:

```
~/Offensive-Security-Tools/Enumeration/
```

Edit `TOOLS_DIR` at the top of `bbrecon.py` if your tools live elsewhere:

```python
TOOLS_DIR = os.path.expanduser("~/Offensive-Security-Tools/Enumeration")
```

Individual binary paths can also be overridden directly:

```python
SUBFINDER_BIN = f"{TOOLS_DIR}/subfinder"
HTTPX_BIN     = f"{TOOLS_DIR}/httpx"
KATANA_BIN    = f"{TOOLS_DIR}/katana"
NUCLEI_BIN    = f"{TOOLS_DIR}/nuclei"
SECRETFINDER  = f"{TOOLS_DIR}/SecretFinder/SecretFinder.py"
```

Fuzzing tools are resolved by searching `$PATH` first, then falling back to `TOOLS_DIR`:

```python
DALFOX_BIN    = shutil.which("dalfox")    or f"{TOOLS_DIR}/dalfox"
FFUF_BIN      = shutil.which("ffuf")      or f"{TOOLS_DIR}/ffuf"
GHAURI_BIN    = shutil.which("ghauri")    or f"{TOOLS_DIR}/ghauri"
QSREPLACE_BIN = shutil.which("qsreplace") or f"{TOOLS_DIR}/qsreplace"
CRLFUZZ_BIN   = shutil.which("crlfuzz")   or f"{TOOLS_DIR}/crlfuzz"
```

### 4. LFI wordlist (optional)

LFI fuzzing with ffuf requires a wordlist at `<WORDLISTS_DIR>/lfi-payloads.txt`. A compatible list is available in [SecLists](https://github.com/danielmiessler/SecLists) at `Fuzzing/LFI/LFI-Jhaddix.txt`. Set the directory at runtime with `--wordlists-dir`, or edit `WORDLISTS_DIR` in the script:

```python
WORDLISTS_DIR = os.path.expanduser("~/Offensive-Security-Tools/wordlists")
```

If the wordlist is missing, the LFI step falls back to nuclei templates automatically.

---

## Usage

```
python3 bbrecon.py [-d DOMAIN | --scope FILE] [options]
```

### Core arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--domain` | `-d` | — | Single target domain (e.g. `example.com`) |
| `--scope` | — | — | Scope file — one domain per line |
| `--h1-handle` | — | `""` | HackerOne handle; injected as a custom header in Nuclei scans |
| `--output` | `-o` | `./` | Base output directory |
| `--skip-nuclei` | — | false | Skip Step 7 (Nuclei vulnerability scan) |
| `--skip-secretfinder` | — | false | Skip Step 4 (SecretFinder JS secret extraction) |
| `--skip-screenshots` | — | false | Skip Step 6 (screenshots + HTML gallery) |
| `--skip-steps` | — | `""` | Comma-separated step numbers to skip, e.g. `1,4,6,7` |

### Fuzzing arguments (Step 8)

| Argument | Default | Description |
|----------|---------|-------------|
| `--fuzz TYPES` | `""` | Comma-separated vuln types, or `all`. Valid: `xss`, `sqli`, `ssrf`, `idor`, `ssti`, `crlf`, `lfi`, `redir`, `cmdi` |
| `--fuzz-headers HEADERS` | `""` | HTTP headers for all fuzzing tools — semicolon-separated, e.g. `Cookie: s=abc; X-Token: xyz` |
| `--fuzz-rate N` | `50` | Max requests per second across fuzzing tools |
| `--oob-url URL` | `""` | Out-of-band callback URL for blind SSRF and OOB probes |
| `--fuzz-sqli-tool` | `ghauri` | SQLi engine: `ghauri` (faster, better WAF bypass) or `sqlmap` (more thorough) |
| `--wordlists-dir DIR` | `~/Offensive-Security-Tools/wordlists` | Directory containing fuzzing wordlists (needs `lfi-payloads.txt` for LFI) |

### Standalone screenshot mode

| Argument | Description |
|----------|-------------|
| `--screenshots` | Standalone mode — takes screenshots without running the full pipeline |
| `--live-domains-list FILE` | File with live URLs/hosts (one per line) for `--screenshots` mode |

---

## Usage Examples

### Recon only

```bash
# Single domain, full pipeline with HackerOne handle
python3 bbrecon.py -d example.com --h1-handle yourhandle

# Batch from scope file
python3 bbrecon.py --scope scope.txt --h1-handle yourhandle

# Fast recon — skip the slow/heavy steps
python3 bbrecon.py --scope scope.txt --skip-nuclei --skip-screenshots --skip-secretfinder

# Custom output directory
python3 bbrecon.py --scope scope.txt -o /tmp/myrecon

# Skip steps by number (4=SecretFinder, 6=screenshots, 7=nuclei)
python3 bbrecon.py -d example.com --skip-steps 4,6,7

# Scope file, custom output, skip nuclei
python3 bbrecon.py --scope scope.txt -o /data/recon --skip-nuclei
```

### Recon + fuzzing

```bash
# Full pipeline with every fuzzing type
python3 bbrecon.py -d example.com --fuzz all

# Scope file + full fuzzing
python3 bbrecon.py --scope scope.txt --fuzz all

# Target specific vulnerability classes only
python3 bbrecon.py -d example.com --fuzz xss,sqli,ssrf

# Lower request rate — gentler on the target
python3 bbrecon.py -d example.com --fuzz all --fuzz-rate 20

# High-speed fuzzing on a fast target
python3 bbrecon.py -d example.com --fuzz xss,sqli --fuzz-rate 150

# Authenticated fuzzing — session cookie to all fuzz tools
python3 bbrecon.py -d example.com --fuzz xss,sqli \
    --fuzz-headers "Cookie: session=abc123"

# Multiple headers (semicolon-separated)
python3 bbrecon.py -d example.com --fuzz ssrf,xss \
    --fuzz-headers "Cookie: session=abc123; X-Auth-Token: xyz"

# Full pipeline + fuzzing + custom output + HackerOne handle
python3 bbrecon.py -d example.com --h1-handle yourhandle \
    --fuzz all --fuzz-rate 30 -o /tmp/recon
```

### Blind / out-of-band detection

```bash
# Step 1: generate an OOB callback URL (leave this running in another terminal)
interactsh-client -v
# → copies something like: abc123.oast.me

# SSRF fuzzing with OOB URL
python3 bbrecon.py -d example.com --fuzz ssrf \
    --oob-url https://abc123.oast.me

# Authenticated SSRF + OOB
python3 bbrecon.py -d example.com --fuzz ssrf \
    --oob-url https://abc123.oast.me \
    --fuzz-headers "Cookie: session=abc123"

# SSRF + XSS with OOB, rate-limited, custom output
python3 bbrecon.py -d example.com --fuzz ssrf,xss \
    --oob-url https://abc123.oast.me \
    --fuzz-rate 25 -o /tmp/recon
```

### SQLi tool selection

```bash
# Default: ghauri (faster, better WAF bypass)
python3 bbrecon.py -d example.com --fuzz sqli

# Switch to sqlmap for thorough testing
python3 bbrecon.py -d example.com --fuzz sqli --fuzz-sqli-tool sqlmap

# Authenticated SQLi with sqlmap
python3 bbrecon.py -d example.com --fuzz sqli --fuzz-sqli-tool sqlmap \
    --fuzz-headers "Cookie: session=abc123"
```

### LFI with custom wordlist

```bash
# Point to a SecLists LFI wordlist directory
python3 bbrecon.py -d example.com --fuzz lfi \
    --wordlists-dir ~/SecLists/Fuzzing/LFI

# The step looks for: <wordlists-dir>/lfi-payloads.txt
# If not found, falls back to nuclei lfi/traversal templates automatically

# LFI + path traversal parameters + authenticated
python3 bbrecon.py -d example.com --fuzz lfi \
    --wordlists-dir ~/SecLists/Fuzzing/LFI \
    --fuzz-headers "Cookie: session=abc123"
```

### Fuzzing only (skip recon, reuse existing output)

```bash
# Skip all recon, run only fuzzing on previously collected data
python3 bbrecon.py -d example.com --skip-steps 1,2,3,4,5,6,7 --fuzz xss,sqli,ssrf

# Re-run just XSS fuzzing with authentication after the initial recon is done
python3 bbrecon.py -d example.com --skip-steps 1,2,3,4,5,6,7 \
    --fuzz xss --fuzz-headers "Cookie: session=abc123"
```

### Standalone screenshot mode

```bash
# Screenshot a list of live hosts and generate an HTML gallery
python3 bbrecon.py --screenshots --live-domains-list urls.txt -o ./shots

# Screenshot with a custom output directory
python3 bbrecon.py --screenshots --live-domains-list live.txt -o /tmp/gallery
```

### Scope file workflows

```bash
# Full recon + all fuzzing across a scope file
python3 bbrecon.py --scope scope.txt --h1-handle yourhandle --fuzz all -o /data/recon

# Scope file, skip screenshots and secretfinder, fuzz XSS and SSRF
python3 bbrecon.py --scope scope.txt --skip-screenshots --skip-secretfinder \
    --fuzz xss,ssrf --fuzz-rate 40

# Scope file, full recon, no fuzzing, fast
python3 bbrecon.py --scope scope.txt --skip-nuclei --skip-screenshots -o /tmp/quick
```

---

## Pipeline Steps

| # | Tool | Description | Runs |
|---|------|-------------|------|
| 1 | **subfinder** | Subdomain enumeration; root domain always appended | Sequential |
| 2 | **httpx** | HTTP probing — produces `live.txt`, `liveDetailed.txt`, `ips.txt`, CSV | Sequential |
| 3 | **katana** | Endpoint crawling (basic + JS-aware depth-3); extracts parameterized URLs | Parallel (Wave 3) |
| 4 | **SecretFinder** | Scans each discovered JS URL for secrets (API keys, tokens, etc.) | Parallel (Wave 4) |
| 5 | *(grep)* | Classifies parameterized URLs into vulnerability buckets via regex | Parallel (Wave 4) |
| 6 | **Playwright** | Takes 1280×900 headless Chromium screenshots; generates interactive HTML gallery | Parallel (Wave 3) |
| 7 | **nuclei** | Templates tagged `exposure,misconfig,takeover,cve` at medium/high/critical severity | Parallel (Wave 4) |
| 8 | **dalfox / ffuf / ghauri / crlfuzz / nuclei** | Active fuzzing for selected vulnerability types | Sequential (Wave 5) |

Steps 3 and 6 run in parallel (Wave 3). Steps 4, 5, and 7 run in parallel (Wave 4). Step 8 runs sequentially after Wave 4 completes.

---

## Fuzzing Module (Step 8)

Step 8 consumes the pre-classified parameter files produced by Step 5. Each sub-step targets a different vulnerability class.

### Sub-steps

| Sub-step | Vuln | Primary tool | Fallback | Input file |
|----------|------|-------------|---------|-----------|
| 8a | XSS | dalfox (JSON output, reflects + DOM) | kxss | `xss_candidates.txt` |
| 8b | SQLi | ghauri (batch, WAF bypass) | sqlmap | `allparameters.txt` |
| 8c | SSRF | nuclei ssrf-tags + ffuf OOB probe | nuclei only | `ssrf_candidates.txt` |
| 8d | IDOR | ffuf + auto-generated ID range (1–2000) | — | `idor_candidates.txt` |
| 8e | SSTI | nuclei ssti-tags | — | `allparameters.txt` |
| 8f | CRLF | crlfuzz | — | `live.txt` |
| 8g | LFI | ffuf + qsreplace + wordlist, `root:x:` match | nuclei lfi/traversal | `traversal_candidates.txt` |
| 8h | Open Redirect | nuclei redirect-tags + ffuf Location-header check | nuclei only | `redirect_candidates.txt` |
| 8i | CMDi | nuclei rce/cmdi-tags | — | `allparameters.txt` |

### Tool notes

- **dalfox** ships its own XSS payloads — no wordlist needed.
- **crlfuzz** ships its own CRLF payloads — no wordlist needed.
- **IDOR**: ffuf enumerates IDs 1–2000 against each unique URL pattern (capped at 20 patterns per domain to bound runtime).
- **LFI**: requires `<wordlists-dir>/lfi-payloads.txt`. Falls back to nuclei templates if the file is missing.
- **SQLi**: ghauri uses millisecond `--delay`; sqlmap uses second-based `--delay`. Both write findings under `scans/fuzzing/sqli/`.
- **SSRF OOB**: the `--oob-url` value is injected into SSRF-candidate parameters via `qsreplace` and probed with ffuf. Callbacks land on your interactsh / Collaborator server.
- Tools that are not installed log a `[!]` warning and skip gracefully — they do not abort the pipeline.
- Manual exploitation tools (tplmap for SSTI, commix for CMDi) require interactive mode and are not automated; the script logs a hint when findings are detected.

---

## Output Structure

```
<output>/
└── <domain>/
    ├── assets/
    │   ├── subdomains.txt              — all found subdomains
    │   ├── ips.txt                     — unique IPs
    │   ├── <domain>.csv                — full httpx report (CSV)
    │   └── liveSubdomains/
    │       ├── live.txt                — live hosts (bare URLs)
    │       └── liveDetailed.txt        — live hosts with title/tech/status
    └── scans/
        ├── nuclei/
        │   └── <domain>.txt            — nuclei findings
        ├── screenshots/
        │   ├── images/                 — PNG screenshots (Playwright)
        │   ├── urls.txt                — clean URL list used for screenshots
        │   └── report.html             — interactive searchable gallery
        ├── subdomainsEndpoints/
        │   ├── Endpoints/
        │   │   └── endpoints.txt       — crawled endpoints
        │   ├── JavaScript/
        │   │   ├── javascript.txt      — JS URLs from deep crawl
        │   │   └── javascriptSecrets.txt
        │   └── AllParameters/
        │       └── allparameters.txt   — all parameterized URLs
        ├── vulnParameters/
        │   ├── SSRF/ssrf_candidates.txt
        │   ├── IDOR/idor_candidates.txt
        │   ├── XSS/xss_candidates.txt
        │   ├── PT/traversal_candidates.txt
        │   └── OpenRedirect/redirect_candidates.txt
        └── fuzzing/                    — Step 8 output (only when --fuzz used)
            ├── xss/
            │   ├── xss_findings.txt    — dalfox confirmed findings (human-readable)
            │   └── xss_findings.json   — dalfox raw JSON output
            ├── sqli/
            │   └── sqli_findings.txt   — ghauri / sqlmap results
            ├── ssrf/
            │   ├── ssrf_findings.txt   — nuclei findings
            │   └── ssrf_findings_oob.csv — ffuf OOB probe results
            ├── idor/
            │   ├── idor_findings.txt   — aggregated ffuf hits
            │   ├── id_range.txt        — generated 1–2000 wordlist
            │   └── idor_pattern_N.csv  — per-pattern ffuf output
            ├── ssti/
            │   └── ssti_findings.txt
            ├── crlf/
            │   └── crlf_findings.txt
            ├── lfi/
            │   ├── lfi_findings.txt    — nuclei or aggregated ffuf hits
            │   └── lfi.csv             — raw ffuf output
            ├── redir/
            │   ├── redir_findings.txt  — nuclei findings
            │   └── redir_ffuf.csv      — ffuf Location-header hits
            └── cmdi/
                └── cmdi_findings.txt
```

---

## Parameter Classification

Step 5 applies case-insensitive regex to `allparameters.txt`. The resulting files become the direct inputs for Step 8 fuzzing.

| Category | Matched parameter names | Used by |
|----------|------------------------|---------|
| SSRF | `url`, `uri`, `redirect`, `dest`, `src`, `endpoint`, `webhook`, `callback`, `fetch`, `forward` | Step 8c |
| IDOR | `id`, `user_id`, `account`, `order`, `report`, `invoice`, `doc`, `file` | Step 8d |
| XSS | `q`, `search`, `query`, `name`, `msg`, `error`, `term`, `keyword` | Step 8a |
| Path Traversal | `file`, `path`, `dir`, `folder`, `template`, `include`, `page`, `view` | Step 8g |
| Open Redirect | `redirect`, `return`, `next`, `goto`, `continue`, `redir`, `r` | Step 8h |

Pattern format: `[\?&](<param>)=` — matches both `?param=` and `&param=` forms.

SQLi (8b), SSTI (8e), and CMDi (8i) use `allparameters.txt` directly since those vulnerabilities can appear in any parameter.

---

## Screenshots

Step 6 uses **Playwright** (headless Chromium) to capture 1280×900 screenshots of every live host. The resulting `report.html` is a dark-themed, client-side searchable gallery with no external dependencies.

Setup:

```bash
pip install playwright
python -m playwright install chromium
```

The standalone mode lets you screenshot any URL list without running the full pipeline:

```bash
python3 bbrecon.py --screenshots --live-domains-list urls.txt -o ./shots
```

Use `--skip-screenshots` to skip Step 6 entirely.

---

## Nuclei / tmux

When launched **inside a tmux session**, Step 7 opens a new window named `nuclei-<domain>` so the scan runs interactively and can be monitored in real time. When not in tmux (or tmux is unavailable), Nuclei runs as a background process and logs to `<domain>_bg.log`.

The `--h1-handle` flag adds a custom header for HackerOne VDP programs:

```
X-HackerOne-Research: [H1 username <handle>]
```

Nuclei scans templates tagged `exposure`, `misconfig`, `takeover`, and `cve` at `medium`, `high`, and `critical` severity.

---

## Summary Output

After all domains complete, a global summary table is printed:

```
══════════════════════════════════════════════════════════════
  GLOBAL SUMMARY  —  2 domain(s) processed
══════════════════════════════════════════════════════════════

  DOMAIN                    SUBS  LIVE  PARAMS  SHOTS   FUZZ
  ─────────────────────────────────────────────────────────
  example.com                 42    15      89     12      3
  test.com                    28     8      56      8      0
```

The `FUZZ` column totals confirmed findings across all active fuzzing sub-steps. Red indicates findings; dim indicates zero.

---

## Related Files

| File | Description |
|------|-------------|
| `screenshotter.py` | Playwright screenshot module imported by `bbrecon.py` |
| `gallery.py` | HTML gallery builder imported by `bbrecon.py` |
| `bbrecon.explication` | Output structure guide and usage notes |
| `ReconMethodology.txt` | Manual command references for each tool |
| `VulnMatchTechnology.txt` | Technology-to-vulnerability mapping for post-recon prioritization |

---

## Legal

This tool is intended for authorized security testing only. Only use BBRecon against targets you have explicit written permission to test, such as bug bounty programs within their defined scope. The author is not responsible for misuse.
