"""
HTML screenshot gallery builder for bbrecon.
Imported by bbrecon.py — do not run directly.
"""

import datetime
import os
import re
import urllib.parse
from pathlib import Path


def _read_lines(path: str) -> list:
    try:
        with open(path) as f:
            return [ln.strip() for ln in f if ln.strip()]
    except Exception:
        return []


def build_gallery(imgs: list, html_path: str, urls_file: str, domain: str):
    urls = _read_lines(urls_file)

    def best_url(img: Path) -> str:
        stem = img.stem
        for u in urls:
            host = re.sub(r"https?://", "", u).rstrip("/")
            if host in stem or stem.startswith(re.sub(r"[^a-zA-Z0-9]", "_", host)[:30]):
                return u
        try:
            return urllib.parse.unquote(stem.replace("__", "://", 1))
        except Exception:
            return stem

    cards = ""
    for img in imgs:
        url    = best_url(img)
        rel    = os.path.relpath(str(img), os.path.dirname(html_path))
        safe   = url.replace('"', "&quot;")
        host   = re.sub(r"https?://", "", url).split("/")[0]
        cards += f"""
    <div class="card" data-url="{safe}">
      <div class="thumb" onclick="window.open('{safe}','_blank')">
        <img src="{rel}" alt="{safe}" loading="lazy"
             onerror="this.parentElement.innerHTML='<div class=no-img>No screenshot</div>'">
        <div class="overlay"><span>↗ Open</span></div>
      </div>
      <div class="meta">
        <div class="host">{host}</div>
        <a href="{safe}" target="_blank" rel="noopener">{url}</a>
      </div>
    </div>"""

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    n  = len(imgs)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Screenshots — {domain}</title>
<style>
:root{{--bg:#0b0d12;--surf:#13161f;--surf2:#1a1e2b;--border:#1f2638;
      --accent:#00e5ff;--accent2:#ff3d6e;--green:#00e676;
      --text:#cdd6f4;--muted:#545c7e;--mono:'Courier New',Courier,monospace}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:13px}}
body::before{{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 4px);
  pointer-events:none;z-index:9999}}
header{{position:sticky;top:0;z-index:100;background:var(--surf);
  border-bottom:1px solid var(--border);padding:14px 28px;
  display:flex;align-items:center;justify-content:space-between;gap:20px}}
.logo{{font-size:15px;font-weight:bold;letter-spacing:3px;color:var(--accent);text-transform:uppercase}}
.logo em{{color:var(--accent2);font-style:normal}}
.counters{{display:flex;gap:28px}}
.cnt{{text-align:center}}
.cnt-n{{font-size:24px;font-weight:bold;color:var(--accent);line-height:1}}
.cnt-l{{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin-top:2px}}
.toolbar{{padding:12px 28px;display:flex;gap:10px;align-items:center;
  background:var(--bg);border-bottom:1px solid var(--border)}}
.search{{flex:1;background:var(--surf);border:1px solid var(--border);border-radius:5px;
  color:var(--text);font-family:var(--mono);font-size:13px;padding:8px 14px;outline:none;transition:border .2s}}
.search:focus{{border-color:var(--accent)}}
.search::placeholder{{color:var(--muted)}}
.btn{{background:var(--surf);border:1px solid var(--border);color:var(--muted);
  font-family:var(--mono);font-size:12px;padding:8px 14px;border-radius:5px;cursor:pointer;transition:border .2s,color .2s}}
.btn:hover{{border-color:var(--accent);color:var(--accent)}}
#rlabel{{color:var(--muted);font-size:11px;white-space:nowrap}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px;padding:22px 28px}}
.card{{background:var(--surf);border:1px solid var(--border);border-radius:8px;overflow:hidden;
  transition:border-color .2s,transform .15s,box-shadow .2s;display:flex;flex-direction:column}}
.card:hover{{border-color:var(--accent);transform:translateY(-3px);box-shadow:0 10px 40px rgba(0,229,255,.1)}}
.thumb{{position:relative;width:100%;height:195px;background:#080a0f;overflow:hidden;cursor:pointer;
  display:flex;align-items:center;justify-content:center}}
.thumb img{{width:100%;height:100%;object-fit:cover;object-position:top;transition:transform .35s}}
.card:hover .thumb img{{transform:scale(1.04)}}
.overlay{{position:absolute;inset:0;background:rgba(0,229,255,0);
  display:flex;align-items:center;justify-content:center;transition:background .2s}}
.overlay span{{color:var(--accent);font-size:13px;letter-spacing:2px;opacity:0;transition:opacity .2s;font-weight:bold}}
.card:hover .overlay{{background:rgba(0,229,255,.08)}}
.card:hover .overlay span{{opacity:1}}
.no-img{{color:var(--muted);font-size:11px;letter-spacing:1px}}
.meta{{padding:10px 14px;border-top:1px solid var(--border);background:var(--surf2)}}
.host{{font-size:12px;font-weight:bold;color:var(--accent);margin-bottom:4px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.meta a{{color:var(--muted);text-decoration:none;font-size:11px;word-break:break-all;display:block;transition:color .15s}}
.meta a:hover{{color:var(--green)}}
.empty{{grid-column:1/-1;text-align:center;color:var(--muted);padding:70px 20px;font-size:14px}}
footer{{border-top:1px solid var(--border);padding:14px 28px;color:var(--muted);font-size:11px;text-align:center;letter-spacing:1px}}
</style>
</head>
<body>
<header>
  <div class="logo">RECON<em>::</em>SHOTS &nbsp;<span style="font-size:11px;color:var(--muted)">{domain}</span></div>
  <div class="counters">
    <div class="cnt"><div class="cnt-n">{n}</div><div class="cnt-l">Total</div></div>
    <div class="cnt"><div class="cnt-n" id="vis-n">{n}</div><div class="cnt-l">Visible</div></div>
    <div class="cnt"><div class="cnt-n" style="color:var(--green)">{ts[:10]}</div><div class="cnt-l">Date</div></div>
  </div>
</header>
<div class="toolbar">
  <input class="search" id="search" type="text" placeholder="Filter by hostname or URL..." autofocus>
  <button class="btn" onclick="document.getElementById('search').value='';filter()">Clear</button>
  <span id="rlabel">{n} results</span>
</div>
<div class="grid" id="grid">
{cards}
</div>
<footer>bbrecon.py &nbsp;·&nbsp; {ts} &nbsp;·&nbsp; {n} hosts &nbsp;·&nbsp; {domain}</footer>
<script>
function filter(){{
  const q=document.getElementById('search').value.toLowerCase();
  let v=0;
  document.querySelectorAll('.card').forEach(c=>{{
    const show=!q||c.dataset.url.toLowerCase().includes(q);
    c.style.display=show?'':'none';
    if(show)v++;
  }});
  document.getElementById('vis-n').textContent=v;
  document.getElementById('rlabel').textContent=v+' results';
  let emp=document.getElementById('__emp');
  if(v===0&&!emp){{emp=document.createElement('div');emp.id='__emp';emp.className='empty';
    emp.textContent='No matches for "'+q+'"';document.getElementById('grid').appendChild(emp);}}
  else if(v>0&&emp)emp.remove();
}}
document.getElementById('search').addEventListener('input',filter);
</script>
</body></html>"""

    with open(html_path, "w") as f:
        f.write(html)
