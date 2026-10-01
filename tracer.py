#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  ADVANCED URL UNSHORTENER / REDIRECT CHAIN CHECKER               ║
║                                                                  ║
║  Author   : @astacbfw                                            ║
║  Tools    : Tools by Asta        → https://t.me/ToolsByAsta      ║
║  Shop     : Asta Shop            → https://t.me/+5KSKziT8millYjVh║
║                                                                  ║
║  Follows: HTTP 3xx  •  <meta refresh>  •  simple JS redirects    ║
║  Detects: loops, known shorteners, dead hops                     ║
║                                                                  ║
║  Requires : pip install requests                                 ║
║  Usage    : python unshorten.py https://bit.ly/xxxx              ║
║             python unshorten.py -f urls.txt --json               ║
║                                                                  ║
║  NOTE: Educational / authorized use only.                        ║
║        Only trace links you are allowed to analyze.              ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException

# ── Attribution & Channels ─────────────────────────────────────────
AUTHOR         = "@astacbfw"
TOOLS_NAME     = "Tools by Asta"
TOOLS_LINK     = "https://t.me/ToolsByAsta"
SHOP_NAME      = "Asta Shop"
SHOP_LINK      = "https://t.me/+5KSKziT8millYjVh"
# ───────────────────────────────────────────────────────────────────

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

KNOWN_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "t.ly", "v.gd",
    "tiny.cc", "lnkd.in", "amzn.to", "youtu.be", "fb.me", "wp.me", "qr.ae",
    "adf.ly", "bc.vc", "sh.st", "clck.ru", "dwz.cn", "short.io", "bl.ink",
    "snip.ly", "u.to", "soo.gd", "x.gd", "qps.ru", "clc.to", "mcaf.ee",
}

C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}
NO_COLOR = False


def col(text: str, color: str) -> str:
    if NO_COLOR or color not in C:
        return text
    return f"{C[color]}{text}{C['reset']}"


# ── HTML parsing helpers ───────────────────────────────────────────
META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
ATTR_RE = re.compile(r'([a-zA-Z\-]+)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))')

JS_PATTERNS = [
    re.compile(r"""window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""location\.replace\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""location\.assign\(\s*['"]([^'"]+)['"]""", re.I),
]


def extract_meta_refresh(html: str) -> Optional[str]:
    for tag in META_TAG_RE.findall(html):
        attrs = {}
        for m in ATTR_RE.finditer(tag):
            key = m.group(1).lower()
            val = m.group(3) or m.group(4) or m.group(5) or ""
            attrs[key] = val
        if attrs.get("http-equiv", "").lower() == "refresh":
            content = attrs.get("content", "")
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.I)
            if m:
                return m.group(1).strip()
    return None


def extract_js_redirect(html: str) -> Optional[str]:
    for pat in JS_PATTERNS:
        m = pat.search(html)
        if m:
            target = m.group(1).strip()
            if target.startswith(("javascript:", "#")) or "${" in target:
                continue
            return target
    return None


def read_snippet(resp, limit: int = 65536) -> str:
    try:
        raw = resp.raw.read(limit, decode_content=True)
    except Exception:
        return ""
    if not raw:
        return ""
    enc = resp.encoding or "utf-8"
    try:
        return raw.decode(enc, errors="ignore")
    except LookupError:
        return raw.decode("utf-8", errors="ignore")


def normalize(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def domain_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_shortener(url: str) -> bool:
    host = domain_of(url)
    return any(host == s or host.endswith("." + s) for s in KNOWN_SHORTENERS)


# ── Tracer ─────────────────────────────────────────────────────────
@dataclass
class Hop:
    step: int
    url: str
    status: Optional[int]
    server: Optional[str]
    elapsed_ms: float
    redirect_to: Optional[str] = None
    note: str = ""
    shortener: bool = False


class RedirectTracer:
    def __init__(self, timeout=10.0, max_hops=15, ua=DEFAULT_UA,
                 verify=True, follow_js=True):
        self.timeout = timeout
        self.max_hops = max_hops
        self.verify = verify
        self.follow_js = follow_js
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        })

    def trace(self, start_url: str) -> dict:
        start_url = normalize(start_url)
        hops: list[Hop] = []
        visited = {start_url}
        current = start_url
        final_url = start_url
        loop = False
        truncated = False
        t_start = time.perf_counter()

        for step in range(1, self.max_hops + 1):
            hop = Hop(step=step, url=current, status=None, server=None,
                      elapsed_ms=0.0, shortener=is_shortener(current))
            t0 = time.perf_counter()
            snippet = ""

            try:
                with self.session.get(
                    current, allow_redirects=False,
                    timeout=self.timeout, stream=True, verify=self.verify,
                ) as r:
                    hop.status = r.status_code
                    hop.server = r.headers.get("Server")
                    loc = r.headers.get("Location")
                    ctype = (r.headers.get("Content-Type") or "").lower()

                    if r.status_code == 200 and "html" in ctype:
                        snippet = read_snippet(r)
                    hop.elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

                    if loc:
                        hop.redirect_to = urljoin(current, loc)
                        hop.note = "http"
                    elif snippet:
                        mr = extract_meta_refresh(snippet)
                        if mr:
                            hop.redirect_to = urljoin(current, mr)
                            hop.note = "meta-refresh"
                        elif self.follow_js:
                            js = extract_js_redirect(snippet)
                            if js:
                                hop.redirect_to = urljoin(current, js)
                                hop.note = "js-redirect"

            except RequestException as e:
                hop.elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
                hop.note = f"error: {type(e).__name__}: {e}"

            hops.append(hop)

            if not hop.redirect_to:
                final_url = hop.url
                break

            nxt = hop.redirect_to
            if nxt in visited:
                loop = True
                hop.note = (hop.note + " loop!").strip()
                final_url = hop.url
                break

            visited.add(nxt)
            current = nxt
            final_url = nxt
        else:
            truncated = True
            final_url = current

        total_ms = round((time.perf_counter() - t_start) * 1000, 1)

        return {
            "_meta": {
                "tool": "URL Unshortener / Redirect Chain Checker",
                "author": AUTHOR,
                "tools_channel": {"name": TOOLS_NAME, "link": TOOLS_LINK},
                "shop_channel":  {"name": SHOP_NAME,  "link": SHOP_LINK},
                "note": "Educational / authorized use only.",
            },
            "input": start_url,
            "final_url": final_url,
            "final_domain": domain_of(final_url),
            "total_hops": len(hops),
            "total_time_ms": total_ms,
            "loop_detected": loop,
            "truncated": truncated,
            "was_shortener": any(h.shortener for h in hops),
            "hops": [asdict(h) for h in hops],
        }


# ── Rendering ──────────────────────────────────────────────────────
def status_color(status: Optional[int]) -> str:
    if status is None:
        return "red"
    if 200 <= status < 300:
        return "green"
    if 300 <= status < 400:
        return "yellow"
    return "red"


def banner():
    if NO_COLOR:
        print("URL UNSHORTENER / REDIRECT CHAIN CHECKER")
        print(f"by {AUTHOR}")
        print(f"Tools → {TOOLS_LINK}")
        print(f"Shop  → {SHOP_LINK}")
        return
    print(col("┌──────────────────────────────────────────────────────────────┐", "cyan"))
    print(col("│  ", "cyan") + col("URL UNSHORTENER / REDIRECT CHAIN CHECKER", "bold") +
          col("             │", "cyan"))
    print(col("│  ", "cyan") + f"by {col(AUTHOR, 'magenta')}"
          + col("                                            │", "cyan"))
    print(col("│  ", "cyan") + col(f"Tools → {TOOLS_LINK}", "blue")
          + col("              │", "cyan"))
    print(col("│  ", "cyan") + col(f"Shop  → {SHOP_LINK}", "green")
          + col("    │", "cyan"))
    print(col("└──────────────────────────────────────────────────────────────┘", "cyan"))


def render(result: dict):
    banner()
    print()
    print(col(f"Target : {result['input']}", "bold"))
    print()

    for h in result["hops"]:
        sc = status_color(h["status"])
        stat = f"{h['status']}" if h["status"] is not None else "ERR"
        tag = col(f"[{h['step']:>2}]", "dim")
        status = col(f"{stat:>3}", sc)
        server = col(f"{(h['server'] or '-'):<18}", "dim")
        ms = col(f"{h['elapsed_ms']:>7.1f} ms", "dim")
        flags = []
        if h["shortener"]:
            flags.append(col("SHORTENER", "magenta"))
        if h["note"]:
            flags.append(col(h["note"], "yellow"))
        flag_str = ("  " + " ".join(flags)) if flags else ""

        print(f"{tag} {status}  {server} {ms}{flag_str}")
        print(f"     {col(h['url'], 'white')}")
        if h["redirect_to"]:
            print(col(f"     └─> {h['redirect_to']}", "blue"))
        print()

    ok = "green" if not result["loop_detected"] else "red"
    print(col("─" * 64, "dim"))
    print(col("FINAL  : ", "bold") + col(result["final_url"], ok))
    print(col("Domain : ", "bold") + result["final_domain"])
    print(col("Hops   : ", "bold") + f"{result['total_hops']}  " +
          col(f"({result['total_time_ms']} ms)", "dim"))
    if result["was_shortener"]:
        print(col("Note   : ", "bold") + col("URL passed through a known shortener", "yellow"))
    if result["loop_detected"]:
        print(col("Warning: ", "bold") + col("redirect loop detected", "red"))
    if result["truncated"]:
        print(col("Warning: ", "bold") + col("max hop limit reached", "red"))
    print()
    print(col(f"by {AUTHOR}", "dim"))
    print(col(f"Tools → {TOOLS_LINK}", "dim"))
    print(col(f"Shop  → {SHOP_LINK}", "dim"))


# ── CLI ────────────────────────────────────────────────────────────
def main():
    global NO_COLOR

    p = argparse.ArgumentParser(
        description=f"Advanced URL unshortener / redirect chain checker — by {AUTHOR}",
        epilog=f"Tools: {TOOLS_LINK}   |   Shop: {SHOP_LINK}",
    )
    p.add_argument("url", nargs="?", help="URL to trace")
    p.add_argument("-f", "--file", help="file with one URL per line")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--max-hops", type=int, default=15)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--ua", default=DEFAULT_UA)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--no-js", action="store_true", help="don't follow JS redirects")
    args = p.parse_args()

    NO_COLOR = args.no_color or args.json or not sys.stdout.isatty()

    if args.insecure:
        import urllib3
        urllib3.disable_warnings()

    targets: list[str] = []
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if args.url:
        targets.append(args.url)

    if not targets:
        banner()
        print()
        p.print_help()
        sys.exit(0)

    tracer = RedirectTracer(
        timeout=args.timeout,
        max_hops=args.max_hops,
        ua=args.ua,
        verify=not args.insecure,
        follow_js=not args.no_js,
    )

    results = []
    for t in targets:
        res = tracer.trace(t)
        results.append(res)
        if args.json:
            continue
        render(res)
        if len(targets) > 1:
            print()

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))


if __name__ == "__main__":
    main()