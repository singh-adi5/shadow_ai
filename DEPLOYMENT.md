# Deploying to Render

This repo is set up to deploy as-is via Render's Blueprint flow
(`render.yaml` + `Dockerfile`, both in the repo root). You need a Render
account (free) and this repo pushed to GitHub — nothing else.

## 1. Push to GitHub

If you haven't already:

```bash
cd shadow_ai_detector          # this directory, i.e. the repo root
git init
git add .
git status                     # double-check nothing sensitive is staged —
                                # .gitignore already excludes .env/audit.log/
                                # threat_model_output/, but verify before committing
git commit -m "Shadow AI Detector"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

## 2. Create the Blueprint on Render

1. Go to <https://dashboard.render.com/blueprints> and click **New Blueprint Instance**.
2. Connect your GitHub account if you haven't, then select this repository.
3. Render detects `render.yaml` automatically and shows the one service it
   defines (`shadow-ai-detector`, Docker runtime, free plan).
4. Click **Apply**. Render will:
   - Build the image from `Dockerfile` (regex-fallback mode — no spaCy
     model download, so the build stays fast on the free plan; see
     "Full NLP mode" below if you want Presidio's ML detection instead).
   - Generate a random `SHADOW_AI_API_KEY` and store it as a secret env var
     (see `render.yaml`) — you do not set this yourself.
   - Deploy and run a health check against `/health`.
5. Once it's live, open the assigned `https://shadow-ai-detector-xxxx.onrender.com`
   URL — it redirects to `/dashboard`, which auto-seeds with 150 synthetic
   demo records on first boot.

## 3. Get your API key

Render → your service → **Environment** tab → `SHADOW_AI_API_KEY` (click
the eye icon to reveal it). You need this to call `/scan` or `/scan-file`:

```bash
curl -X POST https://<your-service>.onrender.com/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <the key from the Environment tab>" \
  -d '{"logs": [{"timestamp":"2026-01-01T00:00:00","source_ip":"10.0.0.1","user_id":"emp_0001","department":"Finance","destination_url":"api.openai.com","http_method":"POST","path":"/v1/chat/completions","payload":"card 4111-1111-2222-3333","response_code":200,"response_time_ms":200}]}'
```

`/dashboard`, `/dashboard/stats`, `/health`, `/config` need no key — see
`SECURITY.md` for why that's deliberate.

## Notes on the free plan

- **Cold starts**: Render's free web services spin down after ~15 minutes
  of no traffic and take a few seconds to wake on the next request. Fine
  for a portfolio demo; upgrade to a paid instance type for an always-on
  service.
- **Single instance**: `API_WORKERS=1`, no Redis — the in-process rate
  limiter is correct for exactly this topology (see `render.yaml` comments
  and `SECURITY.md`). If you scale to more than one instance, add a
  Render Key Value (Redis-compatible) instance and point the app at it
  before doing so, or the rate limiter will under-count.
- **Ephemeral disk**: the dashboard's alert history is SQLite-backed
  (`dashboard_store.py`, `config.DASHBOARD_DB_PATH`) and survives a plain
  *restart* — but Render's free plan filesystem is wiped on every
  *redeploy* (new build), so the DB file resets then. Add a
  [Render persistent disk](https://render.com/docs/disks) and point
  `DASHBOARD_DB_PATH` at a path under its mount if you want history to
  survive redeploys too; not needed just to survive normal restarts/sleep
  cycles.

## Full NLP mode (optional)

The default build skips the spaCy language model and runs on the regex
fallback — fully functional, just less accurate on natural-language
payloads than Presidio's NLP path (see `SECURITY.md` → "PII Detection
Coverage"). To build with the full model instead, either:

- Change `dockerfilePath`/add a build arg in the Render dashboard's
  service settings: set **Docker Build Args** → `ENABLE_PRESIDIO_MODEL=true`, or
- Edit the `Dockerfile`'s `ARG ENABLE_PRESIDIO_MODEL=false` default to `true`
  and redeploy.

This adds real build time and a few hundred MB to the image — comfortable
on a paid Render plan, likely to hit resource/time limits on the free tier.

## Deploying elsewhere

The `Dockerfile` is platform-agnostic (reads `PORT`/`API_HOST` from env,
see `config.py`) — it runs the same way on Fly.io, Railway, a plain VM, etc.
`render.yaml` is Render-specific; translate its env vars to the target
platform's equivalent config, and re-read the `TRUSTED_PROXIES=*` note in
`SECURITY.md` before reusing it — that setting is only safe when the
platform guarantees the container is unreachable except through its own
edge proxy.
