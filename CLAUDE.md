# CLAUDE.md — BBRecon Developer Context

## Project Overview

`bbrecon.py` is a single-file (~854 lines) automated recon framework for bug bounty work. It runs a 7-step pipeline per domain: subdomain enumeration → HTTP probing → endpoint crawling → secret extraction → parameter classification → screenshots → Nuclei scanning.

Entry point: `main()` at line 806.

---

## Architecture

```
bbrecon.py
├── Constants         (lines 61–68)   TOOLS_DIR and per-binary paths
├── ANSI helpers      (lines 74–116)  C class, log(), sep(), domain_header(), banner()
├── Utilities         (lines 122–167) run(), count_lines(), file_ok(), read_lines(), grep_to(), find_images()
├── setup_dirs()      (lines 173–226) creates directory tree, returns flat path dict p{}
├── Pipeline steps    (lines 232–645) step_subfinder, step_httpx, step_katana, step_secretfinder,
│                                     step_param_classification, step_screenshots, step_nuclei_tmux
│                                     + screenshot helpers (_shoot_gowitness, _shoot_eyewitness, _shoot_httpx)
│                                     + _build_gallery (HTML gallery generator)
├── Summary functions (lines 651–718) print_domain_summary(), print_global_summary()
├── Dependency check  (lines 724–750) check_deps()
├── CLI               (lines 756–800) parse_args(), resolve_domains()
└── main()            (lines 806–851) per-domain loop
```

---

## Tool Path Configuration

All tool paths derive from `TOOLS_DIR` (line 61):

```python
TOOLS_DIR = os.path.expanduser("~/Offensive-Security-Tools/Enumeration")
```

To change where tools are looked up, edit `TOOLS_DIR`. Individual binaries can be overridden on lines 62–68. `gowitness` and `eyewitness` do a `shutil.which()` PATH search first, falling back to `TOOLS_DIR`.

---

## Output Path Convention

`setup_dirs(base_output, domain)` (line 173) creates all directories and returns a **flat dict** `p` mapping semantic keys to absolute file paths:

```python
p["subdomains"]    # assets/subdomains.txt
p["live_txt"]      # assets/liveSubdomains/live.txt
p["live_detailed"] # assets/liveSubdomains/liveDetailed.txt
p["ips_txt"]       # assets/ips.txt
p["csv"]           # assets/<domain>.csv
p["endpoints_txt"] # scans/subdomainsEndpoints/Endpoints/endpoints.txt
p["js_txt"]        # scans/subdomainsEndpoints/JavaScript/javascript.txt
p["js_secrets"]    # scans/subdomainsEndpoints/JavaScript/javascriptSecrets.txt
p["allparams"]     # scans/subdomainsEndpoints/AllParameters/allparameters.txt
p["nuclei_out"]    # scans/nuclei/<domain>.txt
p["ssrf_out"]      # scans/vulnParameters/SSRF/ssrf_candidates.txt
p["idor_out"]      # scans/vulnParameters/IDOR/idor_candidates.txt
p["xss_out"]       # scans/vulnParameters/XSS/xss_candidates.txt
p["pt_out"]        # scans/vulnParameters/PT/traversal_candidates.txt
p["redir_out"]     # scans/vulnParameters/OpenRedirect/redirect_candidates.txt
p["ss_dir"]        # scans/screenshots/
p["ss_img_dir"]    # scans/screenshots/images/
p["ss_urls"]       # scans/screenshots/urls.txt
p["ss_html"]       # scans/screenshots/report.html
```

Always use `p["key"]` for paths inside step functions — never construct paths manually.

---

## Key Utilities to Reuse

| Function | Signature | Description |
|----------|-----------|-------------|
| `run()` | `run(cmd, out_file=None, timeout=None) -> int` | Shell command with optional stdout redirect; suppresses stderr |
| `log()` | `log(step, msg, level="info")` | Timestamped colored output; levels: `info`, `ok`, `warn`, `err`, `step` |
| `file_ok()` | `file_ok(path) -> bool` | True if file exists and is non-empty |
| `read_lines()` | `read_lines(path) -> list` | Stripped non-empty lines from a file |
| `grep_to()` | `grep_to(pattern, src, dst)` | Case-insensitive extended grep from src to dst |
| `count_lines()` | `count_lines(path) -> int` | Non-empty line count; returns 0 on error |
| `find_images()` | `find_images(img_dir) -> list` | Sorted list of PNG/JPG/JPEG Paths in a directory |

---

## Adding a New Pipeline Step

Follow the pattern used by existing steps:

```python
def step_mytool(p: dict, domain: str):
    sep(f"[{domain}]  STEP N — Description  [toolname]")

    # Guard: skip if prerequisite file is missing
    if not file_ok(p["live_txt"]):
        log("mytool", "live.txt empty — skipping.", "warn")
        return

    log("mytool", "Running...", "step")
    run(f'"path/to/tool" -input "{p["live_txt"]}" -output "{p["my_out"]}"')

    n = count_lines(p["my_out"])
    log("mytool", f"{C.GREEN}{n}{C.RESET} results → {p['my_out']}", "ok")
```

Then:
1. Add output file keys to `setup_dirs()` (both the directory entry in `dirs` and the file path in `dirs.update(...)`)
2. Call the step function from `main()` in the per-domain loop
3. Add the output file to the `rows` list in `print_domain_summary()` so it appears in results

---

## Extending Parameter Classification

Parameter categories are defined in `step_param_classification()` at line 372 as a list of `(label, regex, output_path)` tuples:

```python
cats = [
    ("SSRF",         r"[\?&](url|uri|...)=", p["ssrf_out"]),
    ("IDOR",         r"[\?&](id|user_id|...)=", p["idor_out"]),
    ...
]
```

To add a new category:
1. Add the output directory and file path to `setup_dirs()`
2. Append a new tuple to `cats` with a regex matching `[\?&](<param_names>)=`
3. Add the output file to `print_domain_summary()` rows

---

## Dependency Handling Pattern

`check_deps()` (line 724) distinguishes critical tools (abort on missing) from optional (warn and continue):

```python
checks = [
    (SUBFINDER_BIN, "subfinder",    True),   # critical=True
    (NUCLEI_BIN,    "nuclei",       False),  # optional
]
```

For new tools, add to `checks` with `critical=False` if the step can gracefully degrade (check `file_ok()` or `os.path.exists()` inside the step function and log a `"warn"` + return early).

---

## Testing

For a fast end-to-end test without heavy scans:

```bash
# Single domain, skip slow steps
python3 bbrecon.py -d example.com --skip-nuclei --skip-screenshots --skip-secretfinder

# Scope file with multiple domains
echo -e "example.com\ntestphp.vulnweb.com" > /tmp/test_scope.txt
python3 bbrecon.py --scope /tmp/test_scope.txt --skip-nuclei --skip-screenshots -o /tmp/recon_test
```

Verify output by checking:
- `<output>/<domain>/assets/subdomains.txt` — non-empty after Step 1
- `<output>/<domain>/assets/liveSubdomains/live.txt` — non-empty after Step 2
- `<output>/<domain>/scans/subdomainsEndpoints/AllParameters/allparameters.txt` — non-empty after Step 3
- `<output>/<domain>/scans/vulnParameters/` — at least one candidate file populated after Step 5
