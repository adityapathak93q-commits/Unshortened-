"""Deep-scan helpers: page inspection (parse only, never execute) and brand checks."""
import re
from urllib.parse import urlparse

from tracer import DEFAULT_UA, read_snippet

PROFILES = {
    "desktop": DEFAULT_UA,
    "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
}
DL_EXT = (".exe", ".msi", ".apk", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".zip", ".rar", ".7z", ".iso", ".dmg", ".ps1", ".lnk")
RISKY_EXT = (".exe", ".msi", ".apk", ".scr", ".bat", ".cmd", ".vbs", ".jar", ".ps1", ".lnk")
DL_TYPES = {"application/octet-stream", "application/x-msdownload", "application/vnd.android.package-archive",
            "application/zip", "application/x-rar-compressed", "application/x-7z-compressed"}
LURE = re.compile(r"verify your|confirm your (?:account|identity)|account (?:suspended|locked)|seed phrase|"
                  r"update (?:your )?payment|unusual activity|claim your|wallet connect", re.I)
OBF = re.compile(r"\beval\(|\batob\(|unescape\(|fromCharCode|document\.write\(", re.I)

BRANDS = {
    "paypal": ["paypal.com"], "google": ["google.com", "goo.gl", "gstatic.com"], "youtube": ["youtube.com", "youtu.be"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com"], "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amzn.to", "amazon.co.uk", "amazon.de"], "facebook": ["facebook.com", "fb.me"],
    "instagram": ["instagram.com"], "netflix": ["netflix.com"], "binance": ["binance.com"], "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"], "whatsapp": ["whatsapp.com", "wa.me"], "telegram": ["telegram.org", "t.me"],
    "dropbox": ["dropbox.com"], "linkedin": ["linkedin.com", "lnkd.in"], "github": ["github.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "usps": ["usps.com"], "chase": ["chase.com"], "docusign": ["docusign.com", "docusign.net"],
}


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_check(host):
    """Return ('impersonation'|'typosquat', brand) or None."""
    for brand, official in BRANDS.items():
        if any(host == d or host.endswith("." + d) for d in official):
            return None
    labels = host.split(".")[:-1]
    for brand in BRANDS:
        if any(brand in l for l in labels):
            return "impersonation", brand
    for l in labels:
        for brand in BRANDS:
            if len(brand) >= 5 and l != brand and _lev(l, brand) <= 1:
                return "typosquat", brand
    return None


def inspect_page(sess, url, timeout=8):
    out = {"content_type": "", "title": "", "password": False, "external_forms": [], "iframes": 0,
           "obfuscation": 0, "lure": False, "download": False, "risky_file": False}
    path = urlparse(url).path.lower()
    out["download"] = path.endswith(DL_EXT)
    out["risky_file"] = path.endswith(RISKY_EXT)
    try:
        with sess.get(url, allow_redirects=False, timeout=timeout, stream=True) as r:
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            out["content_type"] = ct
            if "attachment" in (r.headers.get("Content-Disposition") or "").lower() or ct in DL_TYPES:
                out["download"] = True
            if r.status_code == 200 and "html" in ct:
                html = read_snippet(r)
                m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
                out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
                out["password"] = bool(re.search(r"type\s*=\s*[\"']?password", html, re.I))
                host = (urlparse(url).hostname or "").lower()
                for a in re.findall(r"<form[^>]*\baction\s*=\s*[\"']?(https?://[^\"' >]+)", html, re.I):
                    fh = (urlparse(a).hostname or "").lower()
                    if fh and fh != host and fh not in out["external_forms"]:
                        out["external_forms"].append(fh)
                out["iframes"] = len(re.findall(r"<iframe\b", html, re.I))
                out["obfuscation"] = len(OBF.findall(html))
                out["lure"] = bool(LURE.search(html))
    except Exception as e:
        out["error"] = type(e).__name__
    return out
