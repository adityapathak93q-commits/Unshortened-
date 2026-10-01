# Unshorten

Follow redirect chains (HTTP, meta-refresh, JS), score risk, strip tracking params.

## Run locally
    pip install -r requirements.txt
    python app.py        # http://localhost:5000

## Deploy on Render
1. Push this folder to a GitHub repo.
2. Render dashboard → New → Blueprint → pick the repo (it reads `render.yaml`).
   Or New → Web Service with: Build `pip install -r requirements.txt`,
   Start `gunicorn app:app --workers 2 --threads 4 --timeout 60 --bind 0.0.0.0:$PORT`.
3. Optional env vars: `RATE_LIMIT` (URLs/IP/minute), `MAX_URLS` (per request).

## API
    GET  /api/trace?url=bit.ly/x&url=t.co/y&max_hops=15
    POST /api/trace  {"urls": [...], "max_hops": 15, "timeout": 10, "follow_js": true}
    GET  /healthz

Add `&deep=0` / `"deep": false` to skip cloaking + page inspection (3x fewer requests).

## Optional reputation feeds
Set `GSB_API_KEY` (Google Safe Browsing) and/or `VT_API_KEY` (VirusTotal) in Render → Environment.
Domain age (RDAP) and TLS certificate checks run automatically in deep scans.
Deep scans are capped by `MAX_DEEP` (default 10 links per request).

## Skipping ad pages
With "Skip ad pages" on, if a shortener lands on an interstitial that already contains the destination
(skip button, data attribute, script redirect, base64 URL, link parameter), the app verifies it by tracing it
and continues the chain. Shorteners that withhold the destination until a captcha/timer is completed are reported as such.
