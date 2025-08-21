# am2alertapi

Adapter that translates Prometheus Alertmanager webhooks to the University of Washington AlertAPI (v2).

Runs as a small Quart web service. You can deploy it with systemd or as a container.

## What it does
- Receives Alertmanager webhook payloads (POST /)
- Translates to AlertAPI v2 payload and forwards to AlertAPI
- Optional watchdog endpoint (POST /watchdog) to manage AlertAPI keepalives
- Exposes health and Prometheus metrics endpoints

## Requirements
- Python 3.10+ (for local/systemd) or a container runtime
- Network egress to the AlertAPI endpoint
- These environment variables (required unless noted):
	- ALERTAPI_TOKEN: Bearer token for AlertAPI access
	- ALERTAPI_URL: Base URL for AlertAPI (no trailing path)
	- ALERT_ORGANIZATION: ServiceNow organization name
	- LOG_LEVEL: Optional. DEBUG, INFO, WARNING, ERROR, CRITICAL (default INFO)
	- PROMETHEUS_MULTIPROC_DIR: Required when running multiple workers (Dockerfile sets /tmp/metric-multi)

## Endpoints
- POST /
	- Accepts a standard Alertmanager webhook JSON body.
	- On success, forwards to AlertAPI /v2/alert and returns the upstream status (typically 202).
	- Returns 406 if required labels/annotations are missing; 400 for malformed JSON; 5xx on upstream timeout/connect errors.

- POST /watchdog
	- Accepts the same payload, forwards to AlertAPI /v2/keepalive.
	- Label watchdog_timeout (minutes) can override the default of 5.

- GET /healthz → 200

- GET /metrics → Prometheus metrics (am2alertapi_responses_total{api_endpoint,status_code}).

## Alert payload expectations (from Alertmanager)
The translator builds an AlertAPI payload per alert using:
- labels:
	- alertname → component.name (required)
	- focus → maps to urgency when status == "firing". Mapping: 1→1, 2→1, 3→2, 4→3
	- hostname | cluster | ci_name → sets ci.name (at least one strongly recommended)
	- ci_sysid → sets ci.sysid (optional)
	- kba → sets knowledge base article number (optional)
	- watchdog_timeout → minutes for keepalive (optional; watchdog endpoint)
- annotations:
	- summary → title (required)
	- description → message prefix (required)
- generatorURL → appended to message as "source: …"

If required fields are missing, the service returns 406 with a helpful error message.

See example payloads in `tests/` for quick testing:
- `tests/alertmanager-alert-firing.json`
- `tests/alertmanager-alert-ok.json`
- `tests/alertmanager-alert-watchdog.json`

## Run locally (dev)
Use the helper script (creates a venv, installs deps, starts Hypercorn on :3080):

1) Edit `run_locally` and set ALERTAPI_URL, ALERT_ORGANIZATION, and a valid ALERTAPI_TOKEN
2) Then source it:

```bash
source ./run_locally
```

Now try the health check and a sample POST from `tests/`:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3080/healthz
curl -s -H "Content-Type: application/json" \
	--data @tests/alertmanager-alert-firing.json \
	-o /dev/null -w "%{http_code}\n" \
	http://127.0.0.1:3080/
```

## Container
This repo includes a `Dockerfile` that runs the app with Hypercorn (2 workers) and Prometheus multiprocess metrics configured.

Build locally (example with podman):

```bash
podman build -t am2alertapi:dev .
```

Run locally (env-file example):

```bash
# create testing.env with required vars
# ALERT_ORGANIZATION=UW-IT
# ALERTAPI_URL=https://api.alerts-test.s.uw.edu
# ALERTAPI_TOKEN=YOURTOKEN

podman run --env-file=testing.env --network=host am2alertapi:dev
```

Google Cloud Build (examples):

```bash
gcloud --project <PROJECT> builds submit \
	--tag gcr.io/<PROJECT>/am2alertapi:dev-$(date +"%Y%m%d%H%M") .

gcloud --project <PROJECT> builds submit \
	--tag gcr.io/<PROJECT>/am2alertapi:rel-$(date +"%Y%m%d%H%M") .
```

A convenience script `run_container_locally` shows a ready-to-run `podman run` example against an artifact registry image.

## Systemd deployment
There are example unit and environment files in `systemd-deployment/`. The `Standalone-deploy` script shows a minimal flow to clone, create a venv, install requirements, and install the unit.

Files:
- `systemd-deployment/etc.systemd.system.am2alertapi.service`
- `systemd-deployment/etc.sysconfig.am2alertapi`

Notes:
- The unit binds to 127.0.0.1:3080 by default and runs as nobody.
- Set ALERTAPI_TOKEN, ALERTAPI_URL, and ALERT_ORGANIZATION in `/etc/sysconfig/am2alertapi`.
- After copying files, run: `systemctl daemon-reload && systemctl enable --now am2alertapi`.

## Observability
- Logging via standard Python logging. Control with `LOG_LEVEL` (default INFO).
- Prometheus metrics: `GET /metrics` includes a Counter named `am2alertapi_responses_total` labeled by endpoint and status code. When running multiple workers, ensure `PROMETHEUS_MULTIPROC_DIR` is set (container does this for you).

## Troubleshooting
- 400 on POST: request body isn’t valid JSON.
- 406 on POST: missing required labels/annotations; check `focus`, `alertname`, `summary`, `description`, and `generatorURL`.
- 5xx on POST: upstream AlertAPI timeout or connect error; verify `ALERTAPI_URL` and network access.
- Metrics empty when using multiple workers: check `PROMETHEUS_MULTIPROC_DIR` is set and writable.

## License
See `LICENSE` for details.
