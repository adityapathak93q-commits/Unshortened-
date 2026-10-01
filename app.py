"""Web version of the URL unshortener / redirect chain checker.
Core tracing logic: tracer.py (original script by @astacbfw)."""
import ipaddress, os, socket, threading, time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from analyze import analyze
from intel import gather
from unwrap import resolve
from inspect_page import PROFILES, inspect_page
from tracer import RedirectTracer

app = Flask(__name__, static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # real client IP behind Render's proxy

MAX_URLS = int(os.getenv("MAX_URLS", 20))
MAX_DEEP = int(os.getenv("MAX_DEEP", 10))  # deep scans per request
RATE_LIMIT = int(os.getenv("RATE_LIMIT", 90))   # URLs per IP per window
RATE_WINDOW = 60
_hits, _lock = defaultdict(deque), threading.Lock()


def is_public(url: str) -> bool:
    """SSRF guard: only http(s) hosts that resolve to public IPs."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        return True  # unresolvable: the request itself reports the error
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


class GuardedTracer(RedirectTracer):
    def __init__(self, **kw):
        super().__init__(**kw)
        orig = self.session.get

        def guarded(url, **k):
            if not is_public(url):
                raise requests.exceptions.InvalidURL("blocked: non-public address")
            return orig(url, **k)

        self.session.get = guarded


def allowed(n: int) -> bool:
    ip, now = request.remote_addr or "?", time.time()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) + n > RATE_LIMIT:
            return False
        q.extend([now] * n)
        return True


def _alt(args):
    u, name, opts = args
    a = GuardedTracer(**{**opts, "ua": PROFILES[name]}).trace(u)
    return {"name": name, "final_url": a["final_url"], "final_domain": a["final_domain"], "hops": a["total_hops"]}


def run(urls, opts, deep=True, unwrap=True):
    def one(u):
        t = GuardedTracer(**opts)
        r = t.trace(u)
        base_dom = r["final_domain"]
        steps, gated, alts = [], False, []
        if unwrap:
            r, steps, gated, alts = resolve(t, r, opts["timeout"])
        r["unwrap"] = {"steps": steps, "gated": gated, "alternatives": alts}
        page = profiles = None
        if deep:
            page = inspect_page(t.session, r["final_url"], opts["timeout"])
            with ThreadPoolExecutor(max_workers=2) as ex2:
                profiles = list(ex2.map(_alt, [(u, n, opts) for n in ("mobile", "googlebot")]))
            reg = lambda d: ".".join(d.split(".")[-2:])
            for p in profiles:
                p["differs"] = reg(p["final_domain"]) != reg(base_dom)
            profiles.insert(0, {"name": "desktop", "final_url": r["final_url"], "final_domain": r["final_domain"],
                                "hops": r["total_hops"], "differs": False})
        intel = gather(r, is_public) if deep else None
        r["analysis"] = analyze(r, page, profiles, intel)
        return r
    with ThreadPoolExecutor(max_workers=4) as ex:
        return list(ex.map(one, urls))


@app.after_request
def headers(resp):
    resp.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                                   "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:",
    })
    return resp


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/healthz")
def healthz():
    return "ok"


@app.route("/api/trace", methods=["GET", "POST"])
def trace():
    data = request.get_json(silent=True) or {}
    raw = request.args.getlist("url") if request.method == "GET" else data.get("urls", [])
    urls = list(dict.fromkeys(u.strip() for u in raw if isinstance(u, str) and u.strip()))[:MAX_URLS]
    if not urls:
        return jsonify(error="Enter at least one URL."), 400
    src = data if request.method == "POST" else request.args
    deep = str(src.get("deep", True)).lower() not in ("0", "false")
    unwrap = str(src.get("unwrap", True)).lower() not in ("0", "false")
    if deep:
        urls = urls[:MAX_DEEP]
    if not allowed(len(urls) * (3 if deep else 1)):
        return jsonify(error="Rate limit reached. Try again in a minute."), 429
    try:
        opts = dict(timeout=min(float(src.get("timeout", 10)), 15),
                    max_hops=min(int(src.get("max_hops", 15)), 25),
                    follow_js=str(src.get("follow_js", True)).lower() not in ("0", "false"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid options."), 400
    return jsonify(results=run(urls, opts, deep, unwrap))


if __name__ == "__main__":
    app.run(debug=False, port=int(os.getenv("PORT", 5000)))
