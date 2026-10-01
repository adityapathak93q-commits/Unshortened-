"""Threat-intel lookups: domain age (RDAP), TLS certificate, optional Safe Browsing / VirusTotal."""
import base64, datetime as dt, ipaddress, os, re, socket, ssl, time
from concurrent.futures import ThreadPoolExecutor

import requests

SLD = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _reg(host):
    p = host.split(".")
    return ".".join(p[-3:] if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in SLD else p[-2:])


def domain_age(host):
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    reg = _reg(host)
    if not re.fullmatch(r"[a-z0-9.-]+", reg):
        return None
    try:
        r = requests.get(f"https://rdap.org/domain/{reg}", timeout=6, headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None
        for e in r.json().get("events", []):
            if e.get("eventAction") == "registration":
                d = dt.datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                return max(0, (dt.datetime.now(dt.timezone.utc) - d).days)
    except Exception:
        pass
    return None


def tls_info(host):
    try:
        with socket.create_connection((host, 443), timeout=5) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=host) as ss:
                c = ss.getpeercert()
        now = time.time()
        issuer = dict(x[0] for x in c["issuer"]).get("organizationName", "unknown CA")
        return {"valid": True, "age_days": int((now - ssl.cert_time_to_seconds(c["notBefore"])) / 86400),
                "expires_days": int((ssl.cert_time_to_seconds(c["notAfter"]) - now) / 86400), "issuer": issuer}
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": e.verify_message}
    except Exception:
        return None


def safe_browsing(url):
    key = os.getenv("GSB_API_KEY")
    if not key:
        return None
    body = {"client": {"clientId": "unshorten", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        m = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key},
                          json=body, timeout=6).json().get("matches", [])
        return {"flagged": bool(m), "types": sorted({x["threatType"] for x in m})}
    except Exception:
        return None


def virustotal(url):
    key = os.getenv("VT_API_KEY")
    if not key:
        return None
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key}, timeout=6)
        if r.status_code != 200:
            return {"known": False}
        st = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"known": True, "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0)}
    except Exception:
        return None


def gather(r, is_public):
    host, url = r["final_domain"], r["final_url"]
    with ThreadPoolExecutor(max_workers=4) as ex:
        age = ex.submit(domain_age, host)
        tls = ex.submit(lambda: tls_info(host) if url.startswith("https:") and is_public(url) else None)
        gsb, vt = ex.submit(safe_browsing, url), ex.submit(virustotal, url)
        return {"age_days": age.result(), "tls": tls.result(), "gsb": gsb.result(), "vt": vt.result()}
