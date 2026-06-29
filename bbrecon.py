#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         B B R E C O N  —  Bug Bounty Recon Framework        ║
╚══════════════════════════════════════════════════════════════╝

Runs the full recon pipeline independently for EACH domain in the
scope file.  Output is isolated per domain:

  ./recon_output/
  ├── test.com/
  │   ├── assets/
  │   │   ├── subdomains.txt
  │   │   ├── ips.txt
  │   │   ├── test.com.csv
  │   │   └── liveSubdomains/
  │   │       ├── live.txt
  │   │       └── liveDetailed.txt
  │   └── scans/
  │       ├── nuclei/test.com.txt
  │       ├── screenshots/
  │       │   ├── images/
  │       │   └── report.html
  │       ├── subdomainsEndpoints/
  │       │   ├── Endpoints/endpoints.txt
  │       │   ├── JavaScript/javascript.txt
  │       │   └── AllParameters/allparameters.txt
  │       └── vulnParameters/
  │           ├── SSRF/ssrf_candidates.txt
  │           ├── IDOR/idor_candidates.txt
  │           ├── XSS/xss_candidates.txt
  │           ├── PT/traversal_candidates.txt
  │           └── OpenRedirect/redirect_candidates.txt
  ├── test1.com/
  │   └── ...
  └── test2.com/
      └── ...

Usage:
    python3 bbrecon.py --scope scope.txt --h1-handle davidhs
    python3 bbrecon.py -d example.com --h1-handle davidhs
    python3 bbrecon.py --scope scope.txt --skip-nuclei --skip-screenshots
    python3 bbrecon.py --scope scope.txt -o /tmp/myrecon
"""

import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from gallery import build_gallery
from screenshotter import take_screenshots

_print_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
#  TOOL PATHS  ·  edit TOOLS_DIR if your setup differs
# ─────────────────────────────────────────────────────────────
TOOLS_DIR     = os.path.expanduser("~/Offensive-Security-Tools/Enumeration")
SUBFINDER_BIN = f"{TOOLS_DIR}/subfinder"
HTTPX_BIN     = f"{TOOLS_DIR}/httpx"
KATANA_BIN    = f"{TOOLS_DIR}/katana"
NUCLEI_BIN    = f"{TOOLS_DIR}/nuclei"
SECRETFINDER  = f"{TOOLS_DIR}/SecretFinder/SecretFinder.py"

# ── Fuzzing tools (PATH search first, then TOOLS_DIR fallback) ──
DALFOX_BIN    = shutil.which("dalfox")    or f"{TOOLS_DIR}/dalfox"
KXSS_BIN      = shutil.which("kxss")      or f"{TOOLS_DIR}/kxss"
GHAURI_BIN    = shutil.which("ghauri")    or f"{TOOLS_DIR}/ghauri"
FFUF_BIN      = shutil.which("ffuf")      or f"{TOOLS_DIR}/ffuf"
QSREPLACE_BIN = shutil.which("qsreplace") or f"{TOOLS_DIR}/qsreplace"
CRLFUZZ_BIN   = shutil.which("crlfuzz")   or f"{TOOLS_DIR}/crlfuzz"

WORDLISTS_DIR = os.path.expanduser("~/Offensive-Security-Tools/wordlists")

ALL_FUZZ_TYPES = {"xss", "sqli", "ssrf", "idor", "ssti", "crlf", "lfi", "redir", "cmdi"}


# ─────────────────────────────────────────────────────────────
#  ANSI helpers
# ─────────────────────────────────────────────────────────────
class C:
    RED  = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN   = "\033[96m"; MAGENTA= "\033[95m"
    BOLD = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"


def log(step: str, msg: str, level: str = "info"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    icons = {"info": f"{C.BLUE}[*]{C.RESET}", "ok":   f"{C.GREEN}[+]{C.RESET}",
             "warn": f"{C.YELLOW}[!]{C.RESET}", "err": f"{C.RED}[-]{C.RESET}",
             "step": f"{C.CYAN}{C.BOLD}[>]{C.RESET}"}
    icon  = icons.get(level, icons["info"])
    label = (f"{C.DIM}[{ts}]{C.RESET} {icon} {C.BOLD}{step}{C.RESET}"
             if step else f"{C.DIM}[{ts}]{C.RESET} {icon}")
    with _print_lock:
        print(f"{label} {msg}")


def sep(title: str = ""):
    with _print_lock:
        if title:
            pad = max(0, 56 - len(title))
            print(f"\n{C.CYAN}{C.BOLD}{'─'*3} {title} {'─'*pad}{C.RESET}")
        else:
            print(f"{C.DIM}{'─'*62}{C.RESET}")


def domain_header(domain: str, idx: int, total: int):
    bar = "═" * 62
    print(f"\n{C.MAGENTA}{C.BOLD}{bar}")
    print(f"  DOMAIN [{idx}/{total}] : {domain}")
    print(f"{bar}{C.RESET}\n")


def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝ ████╗  ██║
 ██████╔╝██████╔╝██████╔╝█████╗  ██║      ██╔██╗ ██║
 ██╔══██╗██╔══██╗██╔══██╗██╔══╝  ██║      ██║╚██╗██║
 ██████╔╝██████╔╝██║  ██║███████╗╚██████╗ ██║ ╚████║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}  Bug Bounty Recon Framework  ·  per-domain pipeline
  Tools : {TOOLS_DIR}{C.RESET}
""")


# ─────────────────────────────────────────────────────────────
#  Utility
# ─────────────────────────────────────────────────────────────
def run(cmd: str, out_file: str = None, timeout: int = None) -> int:
    try:
        if out_file:
            with open(out_file, "w") as fh:
                r = subprocess.run(cmd, shell=True, stdout=fh,
                                   stderr=subprocess.DEVNULL, timeout=timeout)
        else:
            r = subprocess.run(cmd, shell=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=timeout)
        return r.returncode
    except subprocess.TimeoutExpired:
        log("", f"Timed out: {cmd[:80]}", "warn"); return 1
    except Exception as e:
        log("", f"Error: {e}", "err"); return 1


def count_lines(path: str) -> int:
    try:
        with open(path) as f:
            return sum(1 for ln in f if ln.strip())
    except Exception:
        return 0


def file_ok(path: str) -> bool:
    p = Path(path)
    return p.exists() and p.stat().st_size > 0


def read_lines(path: str) -> list:
    try:
        with open(path) as f:
            return [ln.strip() for ln in f if ln.strip()]
    except Exception:
        return []


def grep_to(pattern: str, src: str, dst: str):
    subprocess.run(f'grep -Ei "{pattern}" "{src}" > "{dst}" 2>/dev/null || true',
                   shell=True)


def find_images(img_dir: str) -> list:
    d = Path(img_dir)
    return sorted(list(d.rglob("*.png")) + list(d.rglob("*.jpg")) + list(d.rglob("*.jpeg")))


# ─────────────────────────────────────────────────────────────
#  Directory layout  (called once per domain)
# ─────────────────────────────────────────────────────────────
def setup_dirs(base_output: str, domain: str) -> dict:
    """
    base_output  = top-level output dir  (e.g. ./recon_output)
    domain       = e.g. test.com
    Returns a flat dict of every path the pipeline uses.
    """
    b = f"{base_output}/{domain}"   # e.g. ./recon_output/test.com

    dirs = {
        "base":        b,
        "assets":      f"{b}/assets",
        "live_dir":    f"{b}/assets/liveSubdomains",
        "scans":       f"{b}/scans",
        "nuclei_dir":  f"{b}/scans/nuclei",
        "ep_dir":      f"{b}/scans/subdomainsEndpoints/Endpoints",
        "js_dir":      f"{b}/scans/subdomainsEndpoints/JavaScript",
        "param_dir":   f"{b}/scans/subdomainsEndpoints/AllParameters",
        "ssrf_dir":    f"{b}/scans/vulnParameters/SSRF",
        "idor_dir":    f"{b}/scans/vulnParameters/IDOR",
        "xss_dir":     f"{b}/scans/vulnParameters/XSS",
        "pt_dir":      f"{b}/scans/vulnParameters/PT",
        "redir_dir":   f"{b}/scans/vulnParameters/OpenRedirect",
        "ss_dir":      f"{b}/scans/screenshots",
        "ss_img_dir":  f"{b}/scans/screenshots/images",
        # fuzzing sub-directories
        "fuzz_dir":       f"{b}/scans/fuzzing",
        "fuzz_xss_dir":   f"{b}/scans/fuzzing/xss",
        "fuzz_sqli_dir":  f"{b}/scans/fuzzing/sqli",
        "fuzz_ssrf_dir":  f"{b}/scans/fuzzing/ssrf",
        "fuzz_idor_dir":  f"{b}/scans/fuzzing/idor",
        "fuzz_ssti_dir":  f"{b}/scans/fuzzing/ssti",
        "fuzz_crlf_dir":  f"{b}/scans/fuzzing/crlf",
        "fuzz_lfi_dir":   f"{b}/scans/fuzzing/lfi",
        "fuzz_redir_dir": f"{b}/scans/fuzzing/redir",
        "fuzz_cmdi_dir":  f"{b}/scans/fuzzing/cmdi",
    }
    for d in dirs.values():
        Path(d).mkdir(parents=True, exist_ok=True)

    # File paths derived from directory paths
    dirs.update({
        # assets
        "subdomains":    f"{dirs['assets']}/subdomains.txt",
        "live_txt":      f"{dirs['live_dir']}/live.txt",
        "live_detailed": f"{dirs['live_dir']}/liveDetailed.txt",
        "ips_txt":       f"{dirs['assets']}/ips.txt",
        "csv":           f"{dirs['assets']}/{domain}.csv",
        # endpoints
        "endpoints_txt": f"{dirs['ep_dir']}/endpoints.txt",
        "js_txt":        f"{dirs['js_dir']}/javascript.txt",
        "js_secrets":    f"{dirs['js_dir']}/javascriptSecrets.txt",
        "allparams":     f"{dirs['param_dir']}/allparameters.txt",
        # nuclei
        "nuclei_out":    f"{dirs['nuclei_dir']}/{domain}.txt",
        # vuln params
        "ssrf_out":      f"{dirs['ssrf_dir']}/ssrf_candidates.txt",
        "idor_out":      f"{dirs['idor_dir']}/idor_candidates.txt",
        "xss_out":       f"{dirs['xss_dir']}/xss_candidates.txt",
        "pt_out":        f"{dirs['pt_dir']}/traversal_candidates.txt",
        "redir_out":     f"{dirs['redir_dir']}/redirect_candidates.txt",
        # screenshots
        "ss_urls":       f"{dirs['ss_dir']}/urls.txt",
        "ss_html":       f"{dirs['ss_dir']}/report.html",
        # fuzzing output files
        "fuzz_xss_out":   f"{dirs['fuzz_xss_dir']}/xss_findings.txt",
        "fuzz_xss_json":  f"{dirs['fuzz_xss_dir']}/xss_findings.json",
        "fuzz_sqli_out":  f"{dirs['fuzz_sqli_dir']}/sqli_findings.txt",
        "fuzz_ssrf_out":  f"{dirs['fuzz_ssrf_dir']}/ssrf_findings.txt",
        "fuzz_idor_out":  f"{dirs['fuzz_idor_dir']}/idor_findings.txt",
        "fuzz_ssti_out":  f"{dirs['fuzz_ssti_dir']}/ssti_findings.txt",
        "fuzz_crlf_out":  f"{dirs['fuzz_crlf_dir']}/crlf_findings.txt",
        "fuzz_lfi_out":   f"{dirs['fuzz_lfi_dir']}/lfi_findings.txt",
        "fuzz_redir_out": f"{dirs['fuzz_redir_dir']}/redir_findings.txt",
        "fuzz_cmdi_out":  f"{dirs['fuzz_cmdi_dir']}/cmdi_findings.txt",
    })
    return dirs


# ─────────────────────────────────────────────────────────────
#  STEP 1 — Subfinder  (single domain, not a scope file)
# ─────────────────────────────────────────────────────────────
def step_subfinder(p: dict, domain: str):
    sep(f"[{domain}]  STEP 1 — Subdomain Enumeration  [subfinder]")
    log("subfinder", f"Target domain: {C.BOLD}{domain}{C.RESET}", "step")

    # subfinder -d for a single domain
    run(f'"{SUBFINDER_BIN}" -d "{domain}" -silent -o "{p["subdomains"]}"')

    # Also append the root domain itself so httpx probes it too
    existing = set(read_lines(p["subdomains"]))
    if domain not in existing:
        with open(p["subdomains"], "a") as f:
            f.write(domain + "\n")

    n = count_lines(p["subdomains"])
    if n:
        log("subfinder", f"{C.GREEN}{n}{C.RESET} subdomains (incl. root) → {p['subdomains']}", "ok")
    else:
        log("subfinder", "No subdomains found — root domain written. Continuing...", "warn")
    return file_ok(p["subdomains"])


# ─────────────────────────────────────────────────────────────
#  STEP 2 — httpx
# ─────────────────────────────────────────────────────────────
def step_httpx(p: dict, domain: str):
    sep(f"[{domain}]  STEP 2 — HTTP Probing  [httpx]")

    if not file_ok(p["subdomains"]):
        log("httpx", "subdomains.txt empty — skipping.", "warn")
        return False

    log("httpx", "Simple probe (status / title / tech)...", "step")
    run(f'cat "{p["subdomains"]}" | "{HTTPX_BIN}" -silent '
        f'-o "{p["live_txt"]}"')
    _filter_root_urls(p["live_txt"], domain)

    log("httpx", "Detailed probe (+ length / redirects)...", "step")
    run(f'cat "{p["subdomains"]}" | "{HTTPX_BIN}" '
        f'-title -tech-detect -status-code -content-length '
        f'-follow-redirects -o "{p["live_detailed"]}"')
    _filter_root_urls(p["live_detailed"], domain)

    log("httpx", "Extracting IPs...", "step")
    run(f'cat "{p["subdomains"]}" | "{HTTPX_BIN}" -silent -ip 2>/dev/null '
        f'| grep -oE "[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}" '
        f'| sort -u > "{p["ips_txt"]}"')

    log("httpx", "CSV summary...", "step")
    run(f'cat "{p["subdomains"]}" | "{HTTPX_BIN}" -silent '
        f'-title -tech-detect -status-code -content-length '
        f'-follow-redirects -csv -o "{p["csv"]}"')

    # Build clean URL list used by katana / screenshots
    _extract_clean_urls(p["live_txt"], p["ss_urls"])

    n = count_lines(p["live_txt"])
    log("httpx", f"Live hosts: {C.GREEN}{n}{C.RESET} → {p['live_txt']}", "ok")
    return file_ok(p["live_txt"])


def _extract_clean_urls(live_txt: str, out: str):
    """Pull the bare URL (first token) from each httpx output line."""
    urls = []
    for line in read_lines(live_txt):
        parts = line.split()
        if parts and parts[0].startswith("http"):
            urls.append(parts[0])
    with open(out, "w") as f:
        f.write("\n".join(urls) + "\n")


def _filter_root_urls(path: str, domain: str):
    """Remove bare root domain and www.domain entries from an httpx output file."""
    exclude = {
        f"http://{domain}",  f"https://{domain}",
        f"http://www.{domain}", f"https://www.{domain}",
    }
    lines = [ln for ln in read_lines(path)
             if ln.split()[0].rstrip("/") not in exclude]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


# ─────────────────────────────────────────────────────────────
#  STEP 3 — Katana
# ─────────────────────────────────────────────────────────────
def step_katana(p: dict, domain: str):
    sep(f"[{domain}]  STEP 3 — Endpoint Crawling  [katana]")

    if not file_ok(p["live_txt"]):
        log("katana", "live.txt empty — skipping.", "warn")
        return

    log("katana", "Basic crawl...", "step")
    run(f'cat "{p["live_txt"]}" | "{KATANA_BIN}" -silent -o "{p["endpoints_txt"]}"')

    log("katana", "JS-aware deep crawl (depth 3)...", "step")
    run(f'cat "{p["live_txt"]}" | "{KATANA_BIN}" -js-crawl -depth 3 -silent -o "{p["js_txt"]}"')

    log("katana", "Extracting parameterised URLs...", "step")
    subprocess.run(
        f'cat "{p["live_txt"]}" | "{KATANA_BIN}" -silent 2>/dev/null '
        f'| grep "=" | sort -u > "{p["allparams"]}"',
        shell=True)

    log("katana",
        f"Endpoints {C.GREEN}{count_lines(p['endpoints_txt'])}{C.RESET}  "
        f"JS {C.GREEN}{count_lines(p['js_txt'])}{C.RESET}  "
        f"Params {C.GREEN}{count_lines(p['allparams'])}{C.RESET}", "ok")


# ─────────────────────────────────────────────────────────────
#  STEP 4 — SecretFinder
# ─────────────────────────────────────────────────────────────
def step_secretfinder(p: dict, domain: str):
    sep(f"[{domain}]  STEP 4 — Secret Extraction  [SecretFinder]")

    if not os.path.exists(SECRETFINDER):
        log("SecretFinder", f"Not found at {SECRETFINDER} — skipping.", "warn")
        return

    urls = read_lines(p["js_txt"])
    if not urls:
        log("SecretFinder", "No JS URLs — skipping.", "warn")
        return

    log("SecretFinder", f"Scanning {len(urls)} JS URLs...", "step")
    hits = []
    for i, url in enumerate(urls, 1):
        try:
            r = subprocess.run(
                ["python3", SECRETFINDER, "-i", url, "-o", "cli"],
                capture_output=True, text=True, timeout=15)
            if r.stdout.strip():
                hits.append(f"# {url}\n{r.stdout.strip()}\n")
                log("SecretFinder", f"[{i}/{len(urls)}] {C.GREEN}HIT{C.RESET} {url}", "ok")
        except Exception:
            pass

    with open(p["js_secrets"], "w") as f:
        f.write("\n".join(hits))
    log("SecretFinder", f"{C.GREEN}{len(hits)}{C.RESET} URLs with findings → {p['js_secrets']}", "ok")


# ─────────────────────────────────────────────────────────────
#  STEP 5 — Parameter classification
# ─────────────────────────────────────────────────────────────
def step_param_classification(p: dict, domain: str):
    sep(f"[{domain}]  STEP 5 — Parameter Classification")

    if not file_ok(p["allparams"]):
        log("params", "allparameters.txt empty — skipping.", "warn")
        return

    cats = [
        ("SSRF",         r"[\?&](url|uri|redirect|dest|src|endpoint|webhook|callback|fetch|forward)=", p["ssrf_out"]),
        ("IDOR",         r"[\?&](id|user_id|account|order|report|invoice|doc|file)=",                  p["idor_out"]),
        ("XSS",          r"[\?&](q|search|query|name|msg|error|term|keyword)=",                        p["xss_out"]),
        ("PathTraversal", r"[\?&](file|path|dir|folder|template|include|page|view)=",                  p["pt_out"]),
        ("OpenRedirect",  r"[\?&](redirect|return|next|goto|continue|redir|r)=",                       p["redir_out"]),
    ]
    for label, pattern, dst in cats:
        grep_to(pattern, p["allparams"], dst)
        n = count_lines(dst)
        col = C.GREEN if n else C.DIM
        log("params", f"{label:<15} → {col}{n:>4}{C.RESET} candidates", "ok" if n else "info")


# ─────────────────────────────────────────────────────────────
#  STEP 6 — Screenshots
# ─────────────────────────────────────────────────────────────
def step_screenshots(p: dict, domain: str, skip: bool):
    sep(f"[{domain}]  STEP 6 — Visual Recon  [playwright]")

    if skip:
        log("screenshots", "Skipped.", "warn")
        return

    if not file_ok(p["ss_urls"]):
        log("screenshots", "No live hosts — skipping.", "warn")
        return

    n = count_lines(p["ss_urls"])
    log("screenshots", f"Capturing {C.BOLD}{n}{C.RESET} hosts...", "step")

    def _progress(done, total, captured):
        log("screenshots", f"{done}/{total} probed — {C.GREEN}{captured}{C.RESET} captured so far", "info")

    take_screenshots(p["ss_urls"], p["ss_img_dir"], progress_fn=_progress)

    imgs = find_images(p["ss_img_dir"])
    log("screenshots", f"{C.GREEN}{len(imgs)}{C.RESET} screenshots captured.", "ok")
    if imgs:
        build_gallery(imgs, p["ss_html"], p["ss_urls"], domain)
        log("screenshots", f"HTML gallery → {C.GREEN}{p['ss_html']}{C.RESET}", "ok")


# ─────────────────────────────────────────────────────────────
#  STEP 7 — Nuclei  (tmux, one window per domain)
# ─────────────────────────────────────────────────────────────
def step_nuclei_tmux(p: dict, domain: str, h1: str, skip: bool):
    sep(f"[{domain}]  STEP 7 — Nuclei Scan  [tmux]")

    if skip:
        log("nuclei", "Skipped via --skip-nuclei.", "warn"); return
    if not file_ok(p["live_txt"]):
        log("nuclei", "live.txt empty — skipping.", "warn"); return

    h1_flag    = f'-H "X-HackerOne-Research: [H1 username {h1}]"' if h1 else ""
    window_name = f"nuclei-{domain.replace('.', '_')}"
    nuclei_cmd  = (
        f'"{NUCLEI_BIN}" -l "{p["live_txt"]}" '
        f'-tags exposure,misconfig,takeover,cve '
        f'-severity medium,high,critical '
        f'-o "{p["nuclei_out"]}" {h1_flag}; '
        f'echo ""; echo "[DONE] {domain} → {p["nuclei_out"]}"; '
        f'echo "Press Enter to close..."; read'
    )

    in_tmux  = bool(os.environ.get("TMUX"))
    has_tmux = bool(shutil.which("tmux"))

    if has_tmux and in_tmux:
        log("nuclei", f"Opening tmux tab '{window_name}'...", "step")
        script = f"/tmp/nuclei_{domain.replace('.', '_')}.sh"
        with open(script, "w") as f:
            f.write(f"#!/bin/bash\n{nuclei_cmd}\n")
        os.chmod(script, 0o755)
        rc = subprocess.run(["tmux", "new-window", "-n", window_name, script]).returncode
        if rc == 0:
            log("nuclei", f"Running in tmux tab '{window_name}' → {p['nuclei_out']}", "ok")
            return
        log("nuclei", "tmux launch failed — falling back to background.", "warn")
    else:
        reason = "not inside a tmux session" if not in_tmux else "tmux not installed"
        log("nuclei", f"Background mode ({reason}).", "warn")

    log_f = p["nuclei_out"].replace(".txt", "_bg.log")
    subprocess.run(f"bash -c '{nuclei_cmd}' >> \"{log_f}\" 2>&1 &", shell=True)
    log("nuclei", f"Background PID launched — log: {log_f}", "ok")


# ─────────────────────────────────────────────────────────────
#  STEP 8 — Fuzzing helpers
# ─────────────────────────────────────────────────────────────
def _fuzz_tool_ok(bin_path: str, name: str) -> bool:
    """Return True if the binary is executable (by path or on PATH)."""
    return (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)) or bool(shutil.which(name))


def _fuzz_hdr_flags(headers: str) -> str:
    """Convert 'Cookie: a=b; X-Token: z' into '-H "Cookie: a=b" -H "X-Token: z"'."""
    if not headers:
        return ""
    parts = re.split(r';\s+(?=[A-Za-z\-]+:)', headers)
    return " ".join(f'-H "{h.strip()}"' for h in parts if h.strip())


def _json_findings_to_txt(json_path: str, txt_path: str, key_fields: list):
    """Convert dalfox JSONL output to a human-readable txt summary."""
    import json as _json
    lines = []
    for raw in read_lines(json_path):
        try:
            obj = _json.loads(raw)
            parts = [f"{k}={obj.get(k, '')}" for k in key_fields if obj.get(k)]
            lines.append("  ".join(parts))
        except Exception:
            lines.append(raw)
    if lines:
        with open(txt_path, "w") as fh:
            fh.write("\n".join(lines) + "\n")


def _aggregate_ffuf_csv(directory: str, out_file: str):
    """Read all *.csv files written by ffuf and append unique URLs to out_file."""
    import csv as _csv
    urls = set()
    for csv_path in Path(directory).glob("*.csv"):
        try:
            with open(csv_path) as fh:
                reader = _csv.DictReader(fh)
                for row in reader:
                    u = row.get("url") or row.get("input") or ""
                    if u:
                        urls.add(u.strip())
        except Exception:
            pass
    if urls:
        with open(out_file, "a") as fh:
            fh.write("\n".join(sorted(urls)) + "\n")


def _aggregate_sqlmap_results(sqli_dir: str, out_file: str):
    """Collect sqlmap per-host log files into a single findings file."""
    lines = []
    for log_file in Path(sqli_dir).rglob("log"):
        lines.extend(read_lines(str(log_file)))
    if lines:
        with open(out_file, "w") as fh:
            fh.write("\n".join(lines) + "\n")


# ── 8a: XSS ──────────────────────────────────────────────────
def step_fuzz_xss(p: dict, domain: str, hdr: str, rate: int):
    sep(f"[{domain}]  STEP 8a — XSS Fuzzing  [dalfox / kxss]")

    if not file_ok(p["xss_out"]):
        log("fuzz:xss", "xss_candidates.txt empty — skipping.", "warn")
        return

    n_targets = count_lines(p["xss_out"])
    log("fuzz:xss", f"{n_targets} XSS candidate URLs", "step")

    if _fuzz_tool_ok(DALFOX_BIN, "dalfox"):
        delay_ms = max(1, 1000 // rate)
        cmd = (f'"{DALFOX_BIN}" file "{p["xss_out"]}" '
               f'--skip-bav --timeout 10 --delay {delay_ms} '
               f'--format json -o "{p["fuzz_xss_json"]}" {hdr}')
        run(cmd, timeout=600)
        if file_ok(p["fuzz_xss_json"]):
            _json_findings_to_txt(p["fuzz_xss_json"], p["fuzz_xss_out"],
                                  ["param", "payload", "evidence"])
        n = count_lines(p["fuzz_xss_out"])
        log("fuzz:xss", f"{C.GREEN}{n}{C.RESET} XSS findings → {p['fuzz_xss_out']}",
            "ok" if n else "info")
    elif _fuzz_tool_ok(KXSS_BIN, "kxss"):
        log("fuzz:xss", "dalfox not found — using kxss pre-filter.", "warn")
        run(f'cat "{p["xss_out"]}" | "{KXSS_BIN}"', out_file=p["fuzz_xss_out"], timeout=300)
        n = count_lines(p["fuzz_xss_out"])
        log("fuzz:xss", f"{C.GREEN}{n}{C.RESET} kxss reflected-char URLs → {p['fuzz_xss_out']}",
            "ok" if n else "info")
    else:
        log("fuzz:xss", "Neither dalfox nor kxss found — skipping.", "warn")


# ── 8b: SQLi ─────────────────────────────────────────────────
def step_fuzz_sqli(p: dict, domain: str, hdr: str, rate: int, sqli_tool: str):
    sep(f"[{domain}]  STEP 8b — SQLi Fuzzing  [{sqli_tool}]")

    if not file_ok(p["allparams"]):
        log("fuzz:sqli", "allparameters.txt empty — skipping.", "warn")
        return

    n_targets = count_lines(p["allparams"])
    log("fuzz:sqli", f"{n_targets} parameterized URLs", "step")

    if sqli_tool == "ghauri":
        if not _fuzz_tool_ok(GHAURI_BIN, "ghauri"):
            log("fuzz:sqli", "ghauri not found — skipping.", "warn")
            return
        # ghauri uses --header "K: V" instead of -H
        hdr_ghauri = re.sub(r'-H "([^"]+)"', r'--header "\1"', hdr)
        delay_ms = max(0, 1000 // rate - 1)
        cmd = (f'"{GHAURI_BIN}" -m "{p["allparams"]}" '
               f'--dbs --batch --level 1 --delay {delay_ms} '
               f'{hdr_ghauri} --output-dir "{p["fuzz_sqli_dir"]}"')
        run(cmd, timeout=1800)
        _aggregate_sqlmap_results(p["fuzz_sqli_dir"], p["fuzz_sqli_out"])
    else:
        if not bool(shutil.which("sqlmap")):
            log("fuzz:sqli", "sqlmap not found — skipping.", "warn")
            return
        delay_secs = max(0.0, (1000 // rate - 1) / 1000)
        # sqlmap uses --headers not -H
        hdr_sqlmap = re.sub(r'-H "([^"]+)"', r'--headers="\1"', hdr)
        cmd = (f'sqlmap -m "{p["allparams"]}" '
               f'--batch --dbs --level 1 --risk 1 '
               f'--delay {delay_secs:.2f} '
               f'--output-dir "{p["fuzz_sqli_dir"]}" {hdr_sqlmap}')
        run(cmd, timeout=3600)
        _aggregate_sqlmap_results(p["fuzz_sqli_dir"], p["fuzz_sqli_out"])

    n = count_lines(p["fuzz_sqli_out"])
    log("fuzz:sqli", f"{C.GREEN}{n}{C.RESET} SQLi results → {p['fuzz_sqli_out']}",
        "ok" if n else "info")


# ── 8c: SSRF ─────────────────────────────────────────────────
def step_fuzz_ssrf(p: dict, domain: str, hdr: str, rate: int, oob_url: str):
    sep(f"[{domain}]  STEP 8c — SSRF Fuzzing  [nuclei / ffuf+qsreplace]")

    if not file_ok(p["ssrf_out"]):
        log("fuzz:ssrf", "ssrf_candidates.txt empty — skipping.", "warn")
        return

    n_targets = count_lines(p["ssrf_out"])
    log("fuzz:ssrf", f"{n_targets} SSRF candidate URLs", "step")

    if _fuzz_tool_ok(NUCLEI_BIN, "nuclei"):
        log("fuzz:ssrf", "Running nuclei SSRF templates...", "step")
        run(f'"{NUCLEI_BIN}" -l "{p["ssrf_out"]}" -tags ssrf '
            f'-severity medium,high,critical '
            f'-o "{p["fuzz_ssrf_out"]}" -rate-limit {rate} {hdr}',
            timeout=600)

    if oob_url:
        if _fuzz_tool_ok(FFUF_BIN, "ffuf") and _fuzz_tool_ok(QSREPLACE_BIN, "qsreplace"):
            log("fuzz:ssrf", f"Running ffuf OOB probe → {oob_url}", "step")
            oob_csv = p["fuzz_ssrf_out"].replace(".txt", "_oob.csv")
            run(f'cat "{p["ssrf_out"]}" | "{QSREPLACE_BIN}" "{oob_url}" '
                f'| "{FFUF_BIN}" -u FUZZ -w - -mc 200,301,302,307 '
                f'-rate {rate} {hdr} -o "{oob_csv}" -of csv -s',
                timeout=600)
        else:
            log("fuzz:ssrf", "ffuf or qsreplace not found — OOB probe skipped.", "warn")
    else:
        log("fuzz:ssrf", "No --oob-url provided — OOB SSRF probe skipped.", "info")

    n = count_lines(p["fuzz_ssrf_out"])
    log("fuzz:ssrf", f"{C.GREEN}{n}{C.RESET} SSRF findings → {p['fuzz_ssrf_out']}",
        "ok" if n else "info")


# ── 8d: IDOR ─────────────────────────────────────────────────
def step_fuzz_idor(p: dict, domain: str, hdr: str, rate: int):
    sep(f"[{domain}]  STEP 8d — IDOR Fuzzing  [ffuf]")

    if not file_ok(p["idor_out"]):
        log("fuzz:idor", "idor_candidates.txt empty — skipping.", "warn")
        return

    if not _fuzz_tool_ok(FFUF_BIN, "ffuf"):
        log("fuzz:idor", "ffuf not found — skipping.", "warn")
        return

    # Generate numeric ID range wordlist (1–2000)
    id_wordlist = f"{p['fuzz_idor_dir']}/id_range.txt"
    with open(id_wordlist, "w") as fh:
        fh.write("\n".join(str(i) for i in range(1, 2001)) + "\n")

    # Deduplicate URL patterns by replacing numeric param values with FUZZ
    urls = read_lines(p["idor_out"])
    seen_patterns: set = set()
    unique_urls = []
    for url in urls:
        key = re.sub(r'=\d+', '=FUZZ', url)
        if key not in seen_patterns:
            seen_patterns.add(key)
            unique_urls.append(key)

    total = len(unique_urls)
    capped = unique_urls[:20]
    if total > 20:
        log("fuzz:idor", f"{total} IDOR patterns found — capped at 20 to bound runtime.", "warn")
    else:
        log("fuzz:idor", f"{total} unique IDOR patterns to enumerate", "step")

    for i, url_pattern in enumerate(capped, 1):
        out_csv = f"{p['fuzz_idor_dir']}/idor_pattern_{i}.csv"
        run(f'"{FFUF_BIN}" -u "{url_pattern}" -w "{id_wordlist}" '
            f'-mc 200 -rate {rate} {hdr} -o "{out_csv}" -of csv -s',
            timeout=300)

    _aggregate_ffuf_csv(p["fuzz_idor_dir"], p["fuzz_idor_out"])
    n = count_lines(p["fuzz_idor_out"])
    log("fuzz:idor", f"{C.GREEN}{n}{C.RESET} IDOR candidates → {p['fuzz_idor_out']}",
        "ok" if n else "info")


# ── 8e: SSTI ─────────────────────────────────────────────────
def step_fuzz_ssti(p: dict, domain: str, hdr: str, rate: int):
    sep(f"[{domain}]  STEP 8e — SSTI Fuzzing  [nuclei]")

    if not file_ok(p["allparams"]):
        log("fuzz:ssti", "allparameters.txt empty — skipping.", "warn")
        return

    if not _fuzz_tool_ok(NUCLEI_BIN, "nuclei"):
        log("fuzz:ssti", "nuclei not found — skipping. (tplmap available for manual follow-up)", "warn")
        return

    log("fuzz:ssti", "Running nuclei SSTI templates...", "step")
    run(f'"{NUCLEI_BIN}" -l "{p["allparams"]}" -tags ssti '
        f'-o "{p["fuzz_ssti_out"]}" -rate-limit {rate} {hdr}',
        timeout=600)

    n = count_lines(p["fuzz_ssti_out"])
    log("fuzz:ssti", f"{C.GREEN}{n}{C.RESET} SSTI findings → {p['fuzz_ssti_out']}",
        "ok" if n else "info")
    if n:
        log("fuzz:ssti", "Use tplmap for manual exploitation of confirmed endpoints.", "info")


# ── 8f: CRLF ─────────────────────────────────────────────────
def step_fuzz_crlf(p: dict, domain: str, hdr: str, rate: int):
    sep(f"[{domain}]  STEP 8f — CRLF Injection  [crlfuzz]")

    if not file_ok(p["live_txt"]):
        log("fuzz:crlf", "live.txt empty — skipping.", "warn")
        return

    if not _fuzz_tool_ok(CRLFUZZ_BIN, "crlfuzz"):
        log("fuzz:crlf", "crlfuzz not found — skipping.", "warn")
        return

    concurrency = max(1, min(rate // 10, 50))
    log("fuzz:crlf", f"Running crlfuzz on live hosts (concurrency={concurrency})...", "step")
    run(f'"{CRLFUZZ_BIN}" -l "{p["live_txt"]}" '
        f'-c {concurrency} {hdr} -o "{p["fuzz_crlf_out"]}"',
        timeout=600)

    n = count_lines(p["fuzz_crlf_out"])
    log("fuzz:crlf", f"{C.GREEN}{n}{C.RESET} CRLF findings → {p['fuzz_crlf_out']}",
        "ok" if n else "info")


# ── 8g: LFI / Path Traversal ─────────────────────────────────
def step_fuzz_lfi(p: dict, domain: str, hdr: str, rate: int, wl_dir: str):
    sep(f"[{domain}]  STEP 8g — LFI / Path Traversal  [ffuf / nuclei]")

    if not file_ok(p["pt_out"]):
        log("fuzz:lfi", "traversal_candidates.txt empty — skipping.", "warn")
        return

    lfi_wordlist = os.path.join(wl_dir, "lfi-payloads.txt")
    ffuf_ok      = _fuzz_tool_ok(FFUF_BIN, "ffuf")
    qsr_ok       = _fuzz_tool_ok(QSREPLACE_BIN, "qsreplace")
    nuclei_ok    = _fuzz_tool_ok(NUCLEI_BIN, "nuclei")

    if ffuf_ok and qsr_ok and os.path.isfile(lfi_wordlist):
        log("fuzz:lfi", f"Running ffuf with wordlist {lfi_wordlist}...", "step")
        lfi_csv = f"{p['fuzz_lfi_dir']}/lfi.csv"
        run(f'cat "{p["pt_out"]}" | "{QSREPLACE_BIN}" FUZZ '
            f'| "{FFUF_BIN}" -u FUZZ -w "{lfi_wordlist}" '
            f'-mr "root:x:" -rate {rate} {hdr} '
            f'-o "{lfi_csv}" -of csv -s',
            timeout=600)
        _aggregate_ffuf_csv(p["fuzz_lfi_dir"], p["fuzz_lfi_out"])
    else:
        if ffuf_ok and not os.path.isfile(lfi_wordlist):
            log("fuzz:lfi",
                f"LFI wordlist not found at {lfi_wordlist} — falling back to nuclei.", "warn")
        elif not ffuf_ok:
            log("fuzz:lfi", "ffuf not found — falling back to nuclei.", "warn")

        if nuclei_ok:
            log("fuzz:lfi", "Running nuclei lfi/traversal templates...", "step")
            run(f'"{NUCLEI_BIN}" -l "{p["pt_out"]}" -tags lfi,traversal '
                f'-o "{p["fuzz_lfi_out"]}" -rate-limit {rate} {hdr}',
                timeout=600)
        else:
            log("fuzz:lfi", "Neither ffuf nor nuclei available — skipping.", "warn")
            return

    n = count_lines(p["fuzz_lfi_out"])
    log("fuzz:lfi", f"{C.GREEN}{n}{C.RESET} LFI findings → {p['fuzz_lfi_out']}",
        "ok" if n else "info")


# ── 8h: Open Redirect ────────────────────────────────────────
def step_fuzz_redir(p: dict, domain: str, hdr: str, rate: int):
    sep(f"[{domain}]  STEP 8h — Open Redirect  [nuclei / ffuf+qsreplace]")

    if not file_ok(p["redir_out"]):
        log("fuzz:redir", "redirect_candidates.txt empty — skipping.", "warn")
        return

    n_targets = count_lines(p["redir_out"])
    log("fuzz:redir", f"{n_targets} redirect candidate URLs", "step")

    nuclei_ok = _fuzz_tool_ok(NUCLEI_BIN, "nuclei")
    ffuf_ok   = _fuzz_tool_ok(FFUF_BIN, "ffuf")
    qsr_ok    = _fuzz_tool_ok(QSREPLACE_BIN, "qsreplace")

    if not nuclei_ok and not (ffuf_ok and qsr_ok):
        log("fuzz:redir", "No suitable tools found — skipping.", "warn")
        return

    if nuclei_ok:
        log("fuzz:redir", "Running nuclei redirect templates...", "step")
        run(f'"{NUCLEI_BIN}" -l "{p["redir_out"]}" -tags redirect '
            f'-o "{p["fuzz_redir_out"]}" -rate-limit {rate} {hdr}',
            timeout=600)

    if ffuf_ok and qsr_ok:
        REDIR_PAYLOAD = "https://evil.com"
        log("fuzz:redir", "Running ffuf Location-header check...", "step")
        redir_csv = f"{p['fuzz_redir_dir']}/redir_ffuf.csv"
        run(f'cat "{p["redir_out"]}" | "{QSREPLACE_BIN}" "{REDIR_PAYLOAD}" '
            f'| "{FFUF_BIN}" -u FUZZ -w - '
            f'-mr "Location: {REDIR_PAYLOAD}" -mc all '
            f'-rate {rate} {hdr} -o "{redir_csv}" -of csv -s',
            timeout=600)
        _aggregate_ffuf_csv(p["fuzz_redir_dir"], p["fuzz_redir_out"])

    n = count_lines(p["fuzz_redir_out"])
    log("fuzz:redir", f"{C.GREEN}{n}{C.RESET} redirect findings → {p['fuzz_redir_out']}",
        "ok" if n else "info")


# ── 8i: Command Injection ────────────────────────────────────
def step_fuzz_cmdi(p: dict, domain: str, hdr: str, rate: int):
    sep(f"[{domain}]  STEP 8i — Command Injection  [nuclei]")

    if not file_ok(p["allparams"]):
        log("fuzz:cmdi", "allparameters.txt empty — skipping.", "warn")
        return

    if not _fuzz_tool_ok(NUCLEI_BIN, "nuclei"):
        log("fuzz:cmdi",
            "nuclei not found — commix requires interactive mode, skipping.", "warn")
        return

    log("fuzz:cmdi", "Running nuclei rce/cmdi templates...", "step")
    run(f'"{NUCLEI_BIN}" -l "{p["allparams"]}" -tags rce,cmdi '
        f'-severity medium,high,critical '
        f'-o "{p["fuzz_cmdi_out"]}" -rate-limit {rate} {hdr}',
        timeout=600)

    n = count_lines(p["fuzz_cmdi_out"])
    log("fuzz:cmdi", f"{C.GREEN}{n}{C.RESET} cmdi findings → {p['fuzz_cmdi_out']}",
        "ok" if n else "info")
    if n:
        log("fuzz:cmdi", "Use commix for manual exploitation of confirmed endpoints.", "info")


# ── Step 8 dispatcher ─────────────────────────────────────────
def step_fuzz(p: dict, domain: str, fuzz_types: set,
              headers: str = "", rate: int = 50,
              oob_url: str = "", sqli_tool: str = "ghauri",
              wordlists_dir: str = ""):
    sep(f"[{domain}]  STEP 8 — Fuzzing  {sorted(fuzz_types)}")
    hdr    = _fuzz_hdr_flags(headers)
    wl_dir = wordlists_dir or WORDLISTS_DIR

    dispatch = [
        ("xss",   step_fuzz_xss,   (p, domain, hdr, rate)),
        ("sqli",  step_fuzz_sqli,  (p, domain, hdr, rate, sqli_tool)),
        ("ssrf",  step_fuzz_ssrf,  (p, domain, hdr, rate, oob_url)),
        ("idor",  step_fuzz_idor,  (p, domain, hdr, rate)),
        ("ssti",  step_fuzz_ssti,  (p, domain, hdr, rate)),
        ("crlf",  step_fuzz_crlf,  (p, domain, hdr, rate)),
        ("lfi",   step_fuzz_lfi,   (p, domain, hdr, rate, wl_dir)),
        ("redir", step_fuzz_redir, (p, domain, hdr, rate)),
        ("cmdi",  step_fuzz_cmdi,  (p, domain, hdr, rate)),
    ]
    for key, fn, fn_args in dispatch:
        if key in fuzz_types:
            fn(*fn_args)


# ─────────────────────────────────────────────────────────────
#  Per-domain summary
# ─────────────────────────────────────────────────────────────
def print_domain_summary(p: dict, domain: str, elapsed: float) -> dict:
    """Print results for one domain. Returns a stats dict for the global summary."""
    rows = [
        ("Subdomains",     p["subdomains"]),
        ("Live hosts",     p["live_txt"]),
        ("Live detailed",  p["live_detailed"]),
        ("IPs",            p["ips_txt"]),
        ("CSV report",     p["csv"]),
        ("Endpoints",      p["endpoints_txt"]),
        ("JS URLs",        p["js_txt"]),
        ("JS Secrets",     p["js_secrets"]),
        ("All parameters", p["allparams"]),
        ("SSRF",           p["ssrf_out"]),
        ("IDOR",           p["idor_out"]),
        ("XSS",            p["xss_out"]),
        ("Path Traversal", p["pt_out"]),
        ("Open Redirect",  p["redir_out"]),
        ("Nuclei output",  p["nuclei_out"]),
        ("Fuzz: XSS",      p.get("fuzz_xss_out",   "")),
        ("Fuzz: SQLi",     p.get("fuzz_sqli_out",  "")),
        ("Fuzz: SSRF",     p.get("fuzz_ssrf_out",  "")),
        ("Fuzz: IDOR",     p.get("fuzz_idor_out",  "")),
        ("Fuzz: SSTI",     p.get("fuzz_ssti_out",  "")),
        ("Fuzz: CRLF",     p.get("fuzz_crlf_out",  "")),
        ("Fuzz: LFI",      p.get("fuzz_lfi_out",   "")),
        ("Fuzz: Redirect", p.get("fuzz_redir_out", "")),
        ("Fuzz: CMDi",     p.get("fuzz_cmdi_out",  "")),
    ]
    sep(f"[{domain}]  RESULTS")
    print(f"  {'FILE':<22} {'LINES':>7}  PATH")
    print(f"  {'─'*22} {'─'*7}  {'─'*48}")
    stats = {}
    for label, fp in rows:
        n    = count_lines(fp) if file_ok(fp) else 0
        col  = C.GREEN if n else C.DIM
        tick = f"{C.GREEN}✔{C.RESET}" if file_ok(fp) else " "
        print(f"  {tick} {label:<21} {col}{n:>7}{C.RESET}  {C.DIM}{fp}{C.RESET}")
        stats[label] = n

    imgs = find_images(p["ss_img_dir"])
    col  = C.GREEN if imgs else C.DIM
    tick = f"{C.GREEN}✔{C.RESET}" if imgs else " "
    print(f"  {tick} {'Screenshots':<21} {col}{len(imgs):>7}{C.RESET}  {C.DIM}{p['ss_img_dir']}{C.RESET}")
    if file_ok(p["ss_html"]):
        print(f"  {C.GREEN}✔{C.RESET} {'HTML Gallery':<21}         {C.DIM}{p['ss_html']}{C.RESET}")

    mins, secs = divmod(int(elapsed), 60)
    print(f"\n  {C.BOLD}Domain time : {C.RESET}{mins}m {secs}s")
    stats["screenshots"] = len(imgs)
    return stats


# ─────────────────────────────────────────────────────────────
#  Global summary  (after all domains)
# ─────────────────────────────────────────────────────────────
def print_global_summary(all_stats: list, domains: list, total_elapsed: float, base_output: str):
    bar = "═" * 62
    print(f"\n{C.CYAN}{C.BOLD}{bar}")
    print(f"  GLOBAL SUMMARY  —  {len(domains)} domain(s) processed")
    print(f"{bar}{C.RESET}")

    print(f"\n  {'DOMAIN':<25} {'SUBS':>5} {'LIVE':>5} {'PARAMS':>7} {'SHOTS':>6} {'FUZZ':>6}")
    print(f"  {'─'*25} {'─'*5} {'─'*5} {'─'*7} {'─'*6} {'─'*6}")
    fuzz_keys = ["Fuzz: XSS", "Fuzz: SQLi", "Fuzz: SSRF", "Fuzz: IDOR",
                 "Fuzz: SSTI", "Fuzz: CRLF", "Fuzz: LFI", "Fuzz: Redirect", "Fuzz: CMDi"]
    for domain, stats in zip(domains, all_stats):
        subs       = stats.get("Subdomains",     0)
        live       = stats.get("Live hosts",     0)
        params     = stats.get("All parameters", 0)
        shots      = stats.get("screenshots",    0)
        fuzz_total = sum(stats.get(k, 0) for k in fuzz_keys)
        c_live = C.GREEN if live else C.DIM
        c_fuzz = C.RED   if fuzz_total else C.DIM
        print(f"  {domain:<25} {C.GREEN}{subs:>5}{C.RESET} "
              f"{c_live}{live:>5}{C.RESET} "
              f"{C.YELLOW}{params:>7}{C.RESET} "
              f"{C.CYAN}{shots:>6}{C.RESET} "
              f"{c_fuzz}{fuzz_total:>6}{C.RESET}")

    mins, secs = divmod(int(total_elapsed), 60)
    print(f"\n  {C.BOLD}Total time : {C.RESET}{mins}m {secs}s")
    print(f"  {C.BOLD}Output dir : {C.RESET}{base_output}\n")


# ─────────────────────────────────────────────────────────────
#  Dependency check
# ─────────────────────────────────────────────────────────────
def check_deps() -> list:
    sep("Dependency Check")
    checks = [
        (SUBFINDER_BIN, "subfinder",    True),
        (HTTPX_BIN,     "httpx",        True),
        (KATANA_BIN,    "katana",       True),
        (NUCLEI_BIN,    "nuclei",       False),
        (SECRETFINDER,  "SecretFinder", False),
        # Fuzzing tools — all optional
        (DALFOX_BIN,    "dalfox",       False),
        (KXSS_BIN,      "kxss",         False),
        (GHAURI_BIN,    "ghauri",       False),
        (FFUF_BIN,      "ffuf",         False),
        (QSREPLACE_BIN, "qsreplace",    False),
        (CRLFUZZ_BIN,   "crlfuzz",      False),
    ]
    missing_critical = []
    for path, name, critical in checks:
        found = (os.path.isfile(path) and os.access(path, os.X_OK)) or bool(shutil.which(name))
        sym   = f"{C.GREEN}✔{C.RESET}" if found else (f"{C.RED}✘{C.RESET}" if critical else f"{C.YELLOW}~{C.RESET}")
        tag   = "" if critical else f"{C.DIM}(optional){C.RESET}"
        print(f"    {sym}  {name:<20} {C.DIM}{path}{C.RESET} {tag}")
        if not found and critical:
            missing_critical.append(name)

    print(f"    {C.DIM}screenshots via httpx -ss{C.RESET}")
    print()
    return missing_critical


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="BBRecon — per-domain Bug Bounty recon pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Tool paths (TOOLS_DIR = {TOOLS_DIR}):
  subfinder    : {SUBFINDER_BIN}
  httpx        : {HTTPX_BIN}
  katana       : {KATANA_BIN}
  nuclei       : {NUCLEI_BIN}
  SecretFinder : {SECRETFINDER}

Examples:
  python3 bbrecon.py --scope scope.txt --h1-handle davidhs
  python3 bbrecon.py -d example.com   --h1-handle davidhs
  python3 bbrecon.py --scope scope.txt --skip-nuclei
  python3 bbrecon.py --scope scope.txt --skip-screenshots -o /tmp/recon
        """,
    )
    parser.add_argument("-d", "--domain",              help="Single target domain")
    parser.add_argument("--scope",                     help="Scope file — one domain per line")
    parser.add_argument("--h1-handle",    default="",  help="HackerOne handle (nuclei X-header)")
    parser.add_argument("-o", "--output", default="",  help="Base output dir (default: ./recon_output)")
    parser.add_argument("--skip-nuclei",       action="store_true", help="Skip nuclei scan (step 7)")
    parser.add_argument("--skip-secretfinder", action="store_true", help="Skip SecretFinder (step 4)")
    parser.add_argument("--skip-screenshots",  action="store_true", help="Skip screenshots (step 6)")
    parser.add_argument("--skip-steps", default="",
                        help="Comma-separated step numbers to skip, e.g. --skip-steps 4,6,7")
    # ── Fuzzing (Step 8) ──────────────────────────────────────
    parser.add_argument(
        "--fuzz", metavar="TYPES", default="",
        help=("Vuln types to fuzz (comma-separated) or 'all'. "
              "Valid: xss,sqli,ssrf,idor,ssti,crlf,lfi,redir,cmdi  "
              "Example: --fuzz xss,sqli,ssrf  or  --fuzz all")
    )
    parser.add_argument(
        "--fuzz-headers", metavar="HEADERS", default="",
        help="HTTP headers for authenticated fuzzing, e.g. 'Cookie: session=abc; X-Token: xyz'"
    )
    parser.add_argument(
        "--fuzz-rate", type=int, default=50, metavar="N",
        help="Max requests/sec for fuzzing tools (default: 50)"
    )
    parser.add_argument(
        "--oob-url", metavar="URL", default="",
        help="Out-of-band callback URL for blind SSRF/XSS/XXE (e.g. from interactsh-client)"
    )
    parser.add_argument(
        "--fuzz-sqli-tool", choices=["ghauri", "sqlmap"], default="ghauri",
        help="SQLi tool: ghauri (default, faster) or sqlmap (more thorough)"
    )
    parser.add_argument(
        "--wordlists-dir", metavar="DIR", default=WORDLISTS_DIR,
        help=f"Directory containing fuzzing wordlists (default: {WORDLISTS_DIR})"
    )
    # Standalone screenshot mode
    parser.add_argument("--screenshots",       action="store_true",
                        help="Standalone screenshot mode — takes screenshots of hosts in --live-domains-list")
    parser.add_argument("--live-domains-list", metavar="FILE",
                        help="File with live URLs/hosts (one per line) for --screenshots mode")
    return parser.parse_args()


def resolve_domains(args) -> list:
    """Return a clean list of domains to scan."""
    domains = []
    if args.scope:
        if not os.path.exists(args.scope):
            log("", f"Scope file not found: {args.scope}", "err"); sys.exit(1)
        domains = read_lines(args.scope)
        if not domains:
            log("", "Scope file is empty.", "err"); sys.exit(1)
    elif args.domain:
        d = args.domain.strip().rstrip("/")
        for _pfx in ("https://", "http://"):
            if d.startswith(_pfx):
                d = d[len(_pfx):]
                break
        domains = [d]
    else:
        print("Error: supply -d DOMAIN or --scope FILE")
        sys.exit(1)
    return domains


# ─────────────────────────────────────────────────────────────
#  STANDALONE SCREENSHOT MODE
# ─────────────────────────────────────────────────────────────
def run_standalone_screenshots(args):
    """Screenshot a list of live hosts and build an HTML gallery. No pipeline."""
    urls_file = args.live_domains_list
    if not urls_file:
        log("screenshots", "--live-domains-list is required for --screenshots mode.", "err")
        sys.exit(1)
    if not file_ok(urls_file):
        log("screenshots", f"File not found or empty: {urls_file}", "err")
        sys.exit(1)

    img_dir  = os.path.abspath(args.output) if args.output else os.path.abspath("screenshots_output")
    html_out = str(Path(img_dir).parent / "report.html")
    domain   = Path(urls_file).stem  # used as gallery title

    n = count_lines(urls_file)
    sep(f"Standalone Screenshot Mode — {n} hosts  [playwright]")
    log("screenshots", f"Input  : {urls_file}", "info")
    log("screenshots", f"Images : {img_dir}", "info")
    log("screenshots", f"Gallery: {html_out}", "info")
    log("screenshots", f"Capturing {C.BOLD}{n}{C.RESET} hosts...", "step")

    def _progress(done, total, captured):
        log("screenshots", f"{done}/{total} probed — {C.GREEN}{captured}{C.RESET} captured so far", "info")

    take_screenshots(urls_file, img_dir, progress_fn=_progress)

    imgs = find_images(img_dir)
    log("screenshots", f"{C.GREEN}{len(imgs)}{C.RESET} screenshots captured.", "ok")
    if imgs:
        build_gallery(imgs, html_out, urls_file, domain)
        log("screenshots", f"HTML gallery → {C.GREEN}{html_out}{C.RESET}", "ok")
    else:
        log("screenshots", "No screenshots to gallery.", "warn")


# ─────────────────────────────────────────────────────────────
#  MAIN  —  loop per domain
# ─────────────────────────────────────────────────────────────
def main():
    banner()
    args    = parse_args()

    if args.screenshots:
        run_standalone_screenshots(args)
        sys.exit(0)

    t_start = time.time()

    domains     = resolve_domains(args)
    base_output = args.output or "./"
    Path(base_output).mkdir(parents=True, exist_ok=True)

    skip_steps = {int(s.strip()) for s in args.skip_steps.split(",") if s.strip().isdigit()}

    # ── Resolve fuzz types ────────────────────────────────────
    raw_fuzz = args.fuzz.strip().lower()
    if raw_fuzz == "all":
        fuzz_types = set(ALL_FUZZ_TYPES)
    elif raw_fuzz:
        fuzz_types = {t.strip() for t in raw_fuzz.split(",") if t.strip() in ALL_FUZZ_TYPES}
        unknown = {t.strip() for t in raw_fuzz.split(",")
                   if t.strip() and t.strip() not in ALL_FUZZ_TYPES}
        if unknown:
            log("", f"Unknown fuzz types ignored: {unknown}", "warn")
    else:
        fuzz_types = set()

    log("", f"Domains   : {C.BOLD}{len(domains)}{C.RESET} → {domains}", "info")
    log("", f"Output    : {base_output}", "info")
    log("", f"H1 handle : {args.h1_handle or '(none)'}", "info")
    if skip_steps:
        log("", f"Skip steps: {sorted(skip_steps)}", "info")
    if fuzz_types:
        log("", f"Fuzz types : {C.BOLD}{sorted(fuzz_types)}{C.RESET}", "info")
        log("", f"Fuzz rate  : {args.fuzz_rate} req/s", "info")
        if args.fuzz_headers:
            log("", f"Fuzz hdrs  : {args.fuzz_headers}", "info")
        if args.oob_url:
            log("", f"OOB URL    : {args.oob_url}", "info")

    missing = check_deps()
    if missing:
        log("", f"Critical tools missing: {missing}", "err")
        log("", f"Expected in: {TOOLS_DIR}", "err")
        sys.exit(1)

    # ── Per-domain loop ───────────────────────────────────────
    all_stats = []
    for idx, domain in enumerate(domains, 1):
        domain_header(domain, idx, len(domains))
        t_domain = time.time()

        p = setup_dirs(base_output, domain)

        # ── Wave 1: subfinder ─────────────────────────────────
        if 1 not in skip_steps: step_subfinder(p, domain)
        else: log("subfinder", "Skipped via --skip-steps.", "warn")

        # ── Wave 2: httpx ─────────────────────────────────────
        if 2 not in skip_steps: step_httpx(p, domain)
        else: log("httpx", "Skipped via --skip-steps.", "warn")

        # ── Wave 3: katana + screenshots + nuclei (parallel) ──
        w3 = []
        if 3 not in skip_steps:
            w3.append(threading.Thread(target=step_katana, args=(p, domain),
                                       name="katana", daemon=True))
        else:
            log("katana", "Skipped via --skip-steps.", "warn")
        w3.append(threading.Thread(
            target=step_screenshots,
            args=(p, domain, args.skip_screenshots or 6 in skip_steps),
            name="screenshots", daemon=True))
        for t in w3: t.start()
        for t in w3: t.join()

        # ── Wave 4: nuclei + SecretFinder + param classification (parallel) ──
        w4 = []
        w4.append(threading.Thread(
            target=step_nuclei_tmux,
            args=(p, domain, args.h1_handle, args.skip_nuclei or 7 in skip_steps),
            name="nuclei", daemon=True))
        if 4 not in skip_steps and not args.skip_secretfinder:
            w4.append(threading.Thread(target=step_secretfinder, args=(p, domain),
                                       name="SecretFinder", daemon=True))
        else:
            log("SecretFinder", "Skipped.", "warn")
        if 5 not in skip_steps:
            w4.append(threading.Thread(target=step_param_classification, args=(p, domain),
                                       name="params", daemon=True))
        else:
            log("params", "Skipped via --skip-steps.", "warn")
        for t in w4: t.start()
        for t in w4: t.join()

        # ── Wave 5: fuzzing (sequential — runs after param classification) ──
        if fuzz_types and 8 not in skip_steps:
            step_fuzz(p, domain, fuzz_types,
                      headers=args.fuzz_headers,
                      rate=args.fuzz_rate,
                      oob_url=args.oob_url,
                      sqli_tool=args.fuzz_sqli_tool,
                      wordlists_dir=args.wordlists_dir)
        elif 8 in skip_steps:
            log("fuzz", "Skipped via --skip-steps.", "warn")

        stats = print_domain_summary(p, domain, time.time() - t_domain)
        all_stats.append(stats)

    # ── Global summary ────────────────────────────────────────
    print_global_summary(all_stats, domains, time.time() - t_start, base_output)


if __name__ == "__main__":
    main()