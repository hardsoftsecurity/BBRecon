"""
Playwright-based screenshot module for bbrecon.
Imported by bbrecon.py — do not run directly.

Requires: playwright (pip install playwright && python -m playwright install chromium)
"""

import os
import re
from pathlib import Path

from playwright.sync_api import sync_playwright


def _url_to_filename(url: str) -> str:
    """Convert a URL to a safe .png filename."""
    clean = re.sub(r'https?://', '', url).rstrip('/')
    clean = re.sub(r'[^a-zA-Z0-9._-]', '_', clean)
    return clean[:200] + '.png'


def take_screenshots(urls_file: str, img_dir: str, timeout_secs: int = 15,
                     progress_fn=None) -> int:
    """
    Visit each URL in urls_file, take a 1280×900 screenshot, save to img_dir.
    Returns the number of screenshots successfully captured.

    progress_fn(done, total, taken): optional callback for progress updates.
    """
    try:
        urls = [ln.strip() for ln in open(urls_file) if ln.strip()]
    except Exception:
        return 0

    if not urls:
        return 0

    Path(img_dir).mkdir(parents=True, exist_ok=True)
    total = len(urls)
    taken = 0

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage'])
        ctx = browser.new_context(
            viewport={'width': 1280, 'height': 900},
            ignore_https_errors=True,
        )
        ctx.set_default_timeout(timeout_secs * 1000)

        for i, url in enumerate(urls, 1):
            page = ctx.new_page()
            try:
                page.goto(url, timeout=timeout_secs * 1000, wait_until='domcontentloaded')
                out = os.path.join(img_dir, _url_to_filename(url))
                page.screenshot(path=out, timeout=timeout_secs * 1000)
                taken += 1
            except Exception:
                pass
            finally:
                page.close()

            if progress_fn and (i % 10 == 0 or i == total):
                progress_fn(i, total, taken)

        browser.close()

    return taken
