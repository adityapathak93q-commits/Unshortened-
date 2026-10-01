"""Ad-page unwrapping: when a shortener lands on an interstitial page, look for a destination that the
page itself already contains (skip links, data attributes, script redirects, encoded URLs, link parameters),
verify it by tracing it, and continue the chain. Nothing here solves captchas, fakes timers or replays tokens:
if a shortener keeps the destination server-side until those steps are done, the result is reported as 'gated'."""
import base64, html as htmllib, re
from urllib.parse import parse_qsl, urlparse

from tracer import read_snippet

INTERSTITIAL = {"adf.ly", "j.gs", "q.gs", "linkvertise.com", "link-to.net", "ouo.io", "ouo.press", "shrinkme.io",
                "exe.io", "fc.lc", "shorte.st", "bc.vc", "adfoc.us", "clk.sh", "boost.ink", "mboost.me",
                "rekonise.com", "shrinkearn.com", "droplink.co", "gplinks.co", "gplinks.in", "linksly.co",
                "cutwin.com", "cuty.io", "tii.la", "sub2get.com", "zagl.info"}
WRAPPERS = {"l.facebook.com", "lm.facebook.com", "l.instagram.com", "out.reddit.com", "t.umblr.com",
            "away.vk.com", "slack-redir.net"}
SKIP = re.compile(r"skip ad|please wait|click to continue|get link|continue to (?:link|destination)|"
                  r"you will be redirected|you are leaving|generating link|countdown|human verification", re.I)
CAPTCHA = re.compile(r"recaptcha|hcaptcha|turnstile|cf-challenge", re.I)
NOISE = ("google-analytics", "googletagmanager", "doubleclick", "googlesyndication", "gstatic", "googleapis",
         "cloudflare", "cdnjs", "jsdelivr", "jquery", "bootstrapcdn", "fontawesome", "facebook.net", "w3.org",
         "schema.org", "recaptcha", "hcaptcha", "clarity.ms", "sentry.io", "unpkg.com", "twitter.com/intent")
BAD_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".json")
URLISH = re.compile(r"^https?://[^\s\"'<>]{4,}$", re.I)
KEYWORD = re.compile(r"skip|continue|get.?link|proceed|unlock|go to|download|click here|destination|visit", re.I)


def _host(u):
    return (urlparse(u).hostname or "").lower()


def _reg(h):
    return ".".join(h.split(".")[-2:])


def _clean(raw):
    u = htmllib.unescape(raw).replace("\\/", "/").replace("\\u0026", "&").replace("\\x2F", "/").strip()
    if u.startswith("//"):
        u = "https:" + u
    return u if URLISH.match(u) else None


def _b64(s):
    try:
        d = base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except Exception:
        return None
    return d if URLISH.match(d) else None


def candidates(page, url):
    """Return [(score, method, url)] of external destinations found in the page, best first."""
    base, out = _reg(_host(url)), {}

    def add(raw, method, score):
        u = _clean(raw)
        if not u:
            return
        p = urlparse(u)
        if not p.hostname or _reg(p.hostname.lower()) == base:
            return
        if any(n in u.lower() for n in NOISE) or p.path.lower().endswith(BAD_EXT):
            return
        if score > out.get(u, (0,))[0]:
            out[u] = (score, method)

    for m in re.finditer(r"<a\b([^>]*)>(.*?)</a>", page, re.I | re.S):
        h = re.search(r"href\s*=\s*[\"']([^\"']+)[\"']", m.group(1), re.I)
        if h:
            kw = KEYWORD.search(re.sub(r"<[^>]+>", "", m.group(2)) + " " + m.group(1))
            add(h.group(1), "skip button" if kw else "page link", 60 if kw else 20)
    for m in re.finditer(r"data-(?:href|url|link|target|redirect)\s*=\s*[\"']([^\"']+)[\"']", page, re.I):
        add(m.group(1), "data attribute", 55)
    for m in re.finditer(r"(?:location(?:\.href)?\s*=|location\.replace\(|window\.open\()\s*[\"']([^\"']+)[\"']", page, re.I):
        add(m.group(1), "script redirect", 70)
    for m in re.finditer(r"[\"'](?:url|target|dest|destination|link|long_?url|original_?url|redirect_?url|target_?url)[\"']\s*:\s*[\"']([^\"']+)[\"']", page, re.I):
        add(m.group(1), "embedded data", 65)
    for m in re.finditer(r"atob\(\s*[\"']([A-Za-z0-9+/=_-]{12,})[\"']\s*\)|[\"'](aHR0c[A-Za-z0-9+/=_-]{8,})[\"']", page):
        d = _b64(m.group(1) or m.group(2))
        if d:
            add(d, "encoded (base64)", 75)
    for _, v in parse_qsl(urlparse(url).query):
        d = v if URLISH.match(v) else _b64(v)
        if d:
            add(d, "link parameter", 50)
    return sorted(((s, m, u) for u, (s, m) in out.items()), reverse=True)


def classify(url, page):
    h = _host(url)
    if _reg(h) in INTERSTITIAL:
        return "ad shortener"
    if h in WRAPPERS or (h.endswith("google.com") and urlparse(url).path == "/url"):
        return "link wrapper"
    if len(SKIP.findall(page)) >= 2 and len(page) < 40000:
        return "interstitial"
    return None


def resolve(tracer, result, timeout=10, max_layers=3):
    """Follow interstitial pages. Returns (result, steps, gated, alternatives)."""
    steps, gated, alts = [], False, []
    for _ in range(max_layers):
        last = result["hops"][-1] if result["hops"] else None
        if not last or last["status"] != 200:
            break
        url = result["final_url"]
        try:
            with tracer.session.get(url, allow_redirects=False, timeout=timeout, stream=True) as r:
                if "html" not in (r.headers.get("Content-Type") or "").lower():
                    break
                page = read_snippet(r)
        except Exception:
            break
        kind = classify(url, page)
        if not kind:
            break
        cands = candidates(page, url)
        picked = None
        for score, method, cand in [c for c in cands if c[0] >= 50][:4]:
            r2 = tracer.trace(cand)
            end = r2["hops"][-1] if r2["hops"] else None
            if end and end["status"] is not None and end["status"] < 400 and _reg(r2["final_domain"]) != _reg(_host(url)):
                picked = (method, r2)
                break
        if not picked:
            gated = kind != "interstitial" or bool(CAPTCHA.search(page))
            alts = [c[2] for c in cands if c[0] < 50][:3]
            break
        method, r2 = picked
        r2["hops"][0]["note"] = f"found on {kind} page ({method})"
        result["hops"] += r2["hops"]
        result.update(final_url=r2["final_url"], final_domain=r2["final_domain"], total_hops=len(result["hops"]),
                      total_time_ms=round(result["total_time_ms"] + r2["total_time_ms"], 1),
                      loop_detected=result["loop_detected"] or r2["loop_detected"],
                      truncated=result["truncated"] or r2["truncated"])
        steps.append({"from": _host(url), "to": r2["final_domain"], "method": method, "kind": kind})
    return result, steps, gated, alts
