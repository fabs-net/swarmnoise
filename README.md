# swarmnoise

Automated collector for GreyNoise Project Swarm sensor data, scoped to Fortinet-targeted attack traffic observed by a sensor in Frankfurt, Germany.

## How it works

A GitHub Actions scheduler workflow fires **every hour**. Each day at midnight UTC it:

1. Picks a random number between **1 and 10** — the number of fetches for that day
2. Distributes those fetches randomly across the remaining hours of the day
3. Persists the schedule in `state/today.json`

Each subsequent hourly check compares the current time against the day's schedule and fires a fetch when due.

This means the commit pattern is **organic and unpredictable** — anywhere from 1 to 10 commits per day, at random times.

## Data collected

Every fetch queries the GreyNoise Swarm Session API filtered to:
- Your specific sensor (`SENSOR_ID`)
- Fortinet profile sessions only (`gnMetadata.persona.name:Fortinet*`)

Results are written to `data/` as JSON. Run metadata (counts, timing, errors) is always written to `runs/`.

## Repository structure

```
swarmnoise/
├── .github/workflows/
│   └── scheduler.yml          # Hourly trigger, randomized schedule logic + fetch
├── scripts/
│   └── fetch_sessions.py      # GreyNoise Swarm API fetch + write
├── data/                      # Session JSON files (one per run, if sessions found)
├── runs/                      # Run log JSON files (always written)
├── state/
│   └── today.json             # Daily schedule state
├── requirements.txt
└── README.md
```

## GitHub Secrets required

Set these in your repo under **Settings → Secrets and variables → Actions**:

| Secret | Description |
|---|---|
| `GREYNOISE_API_KEY` | Your GreyNoise API key |
| `SENSOR_ID` | Your Swarm sensor UUID (from viz.greynoise.io → Observe → Sensors) |
| `GH_PAT` | GitHub Personal Access Token with `repo` scope (needed to push commits from Actions) |

## Data file schema

**`data/YYYY-MM-DD_HHMM.json`**
```json
{
  "fetch_timestamp": "2026-05-04T09:03:00Z",
  "sensor_id": "...",
  "filter": "gnMetadata.persona.name:Fortinet*",
  "time_window_start": "2026-05-04T05:47:00Z",
  "time_window_end": "2026-05-04T09:03:00Z",
  "session_count": 12,
  "sessions": [ ... ]
}
```

**`runs/YYYY-MM-DD_HHMM_run_log.json`**
```json
{
  "timestamp": "2026-05-04T09:03:00Z",
  "sensor_id": "...",
  "sessions_found": 12,
  "duration_seconds": 3.2,
  "error": null
}
```

## Privacy note

The `data/` files contain attacker source IPs and session metadata from your sensor. This repo is private — keep it that way if you want to avoid exposing the raw session data publicly.

## Querying data locally

```bash
# Count total sessions across all data files
jq '[.[].session_count] | add' data/*.json

# List all unique source IPs
jq -r '[.[].sessions[].source.ip] | unique[]' data/*.json

# Show sessions by classification
jq '.sessions[] | select(.classification == "malicious")' data/*.json
```

## Endpoint note

If the fetch script returns a 404, the GreyNoise Swarm session API endpoint may differ from the one used in the script. To find the correct endpoint:
1. Log into viz.greynoise.io
2. Open browser DevTools → Network tab
3. Navigate to Observe → Explore and run a search
4. Look for the API call and copy the endpoint URL
5. Update `SWARM_API_BASE` in `scripts/fetch_sessions.py`
