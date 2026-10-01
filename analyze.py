"""Heuristic link analysis: risk signals, tracking-parameter cleanup."""
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from inspect_page import brand_check

TRACK = {"fbclid", "gclid", "dclid", "msclkid", "yclid", "mc_eid", "igshid",
         "_hsenc", "_hsmi", "ref_src", "twclid", "ttclid", "wbraid", "gbraid"}
BAD_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml",
            "cf", "ga", "work", "rest", "support", "icu", "cyou", "monster"}


def _host(u):
    try:
        return (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""


def _reg(h):
    return ".".join(h.split(".")[-2:])


def strip_tracking(url):
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    is_t = lambda k: k.lower() in TRACK or k.lower().startswith("utm_")
    kept = [(k, v) for k, v in q if not is_t(k)]
    removed = [k for k, _ in q if is_t(k)]
    return urlunparse(p._replace(query=urlencode(kept))), removed


def analyze(r, page=None, profiles=None, intel=None):
    hops, final = r["hops"], r["final_url"]
    hosts = [_host(h["url"]) for h in hops] + [_host(final)]
    fh = r["final_domain"]
    sig = []
    add = lambda w, lvl, t: sig.append((w, lvl, t))

    if r["was_shortener"]:
        add(10, "info", "Starts at a known link shortener")
    if len({_reg(h) for h in hosts if h}) > 1:
        add(10, "warn", "Redirects across different domains")
    if any(a["url"].startswith("https:") and b["url"].startswith("http:")
           for a, b in zip(hops, hops[1:])):
        add(25, "bad", "Downgrades from https to http")
    elif final.startswith("http:"):
        add(15, "warn", "Destination is not encrypted (http)")
    try:
        ipaddress.ip_address(fh)
        add(30, "bad", "Destination is a raw IP address")
    except ValueError:
        pass
    if any(l.startswith("xn--") for h in hosts for l in h.split(".")):
        add(20, "warn", "Uses internationalized (punycode) domain")
    if any("@" in (urlparse(h["url"]).netloc) for h in hops):
        add(20, "bad", "URL hides its host behind an @ sign")
    if fh.rsplit(".", 1)[-1] in BAD_TLDS:
        add(15, "warn", f"Destination uses a frequently abused .{fh.rsplit('.', 1)[-1]} domain")
    if len(fh.split(".")) >= 5:
        add(10, "warn", "Destination has unusually many subdomains")
    if r["total_hops"] >= 5:
        add(10, "warn", f"Long chain ({r['total_hops']} hops)")
    if any(h["note"].startswith(("meta", "js")) for h in hops):
        add(10, "warn", "Uses page-level (meta/script) redirects")
    if r["loop_detected"]:
        add(25, "bad", "Redirect loop detected")
    if r["truncated"]:
        add(15, "bad", "Hop limit reached before a destination")
    if hops and hops[-1]["status"] is None:
        add(10, "warn", "Last hop could not be reached")
    elif hops and hops[-1]["status"] and hops[-1]["status"] >= 400:
        add(10, "warn", f"Destination returned HTTP {hops[-1]['status']}")

    if any(re.search(r"https?(?::|%3A)(?:/|%2F){2}", urlparse(h["url"]).query, re.I) for h in hops):
        add(10, "warn", "Link carries another URL in its parameters (open-redirect pattern)")
    bc = brand_check(fh) if fh else None
    if bc:
        kind, brand = bc
        add(35 if kind == "impersonation" else 30, "bad",
            f"Domain looks like it impersonates {brand.title()}" if kind == "impersonation"
            else f"Domain is one character off {brand.title()} (typosquat)")
    if profiles and any(p["differs"] for p in profiles):
        add(35, "bad", "Cloaking: destination changes by device or crawler")
    if page and not page.get("error"):
        if page["external_forms"]:
            add(25, "bad", "Page submits a form to another domain")
        if page["password"]:
            add(15, "warn", "Destination asks for a password")
        if page["lure"]:
            add(10, "warn", "Page uses account-verification lure wording")
        if page["obfuscation"] >= 3:
            add(15, "warn", "Heavily obfuscated scripts on the page")
        if page["iframes"] >= 2:
            add(10, "warn", "Page embeds several iframes")
        if page["risky_file"]:
            add(30, "bad", "Destination is an executable or script file")
        elif page["download"]:
            add(15, "warn", "Destination forces a file download")

    if intel:
        age, tls, gsb, vt = intel.get("age_days"), intel.get("tls"), intel.get("gsb"), intel.get("vt")
        if age is not None and age < 30:
            add(35 if age < 7 else 25, "bad", f"Domain was registered only {age} day{'s' if age != 1 else ''} ago")
        elif age is not None and age < 90:
            add(10, "warn", f"Young domain ({age} days old)")
        if tls and not tls["valid"]:
            add(25, "bad", f"TLS certificate is invalid: {tls['error']}")
        elif tls and tls["age_days"] < 7:
            add(10, "warn", f"TLS certificate issued {tls['age_days']} days ago")
        if gsb and gsb["flagged"]:
            add(60, "bad", "Google Safe Browsing flags this URL: " + ", ".join(gsb["types"]))
        if vt and vt.get("known"):
            if vt["malicious"] >= 3:
                add(50, "bad", f"{vt['malicious']} VirusTotal engines flag this URL")
            elif vt["malicious"] + vt["suspicious"] >= 1:
                add(25, "warn", "Some VirusTotal engines flag this URL")

    clean, removed = strip_tracking(final)
    if removed:
        add(0, "info", f"Tracking parameters found: {', '.join(sorted(set(removed)))}")
    if not sig:
        add(0, "ok", "No warning signs found")
    score = min(100, sum(w for w, _, _ in sig))
    return {"score": score,
            "level": "low" if score < 15 else "medium" if score < 35 else "high",
            "signals": [{"level": l, "text": t} for _, l, t in sig],
            "clean_url": clean, "stripped_params": removed, "page": page, "profiles": profiles or [], "intel": intel}
