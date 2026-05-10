# Architecture

## Collection architecture

The collector uses two GreyNoise API paths per run:

| | Full feed | Filtered feed |
|---|---|---|
| API | v1 Swarm (`/v1/workspaces/{id}/sensors/activity`) | v3 Sessions (`/v3/sessions`) |
| Filter | none | `classification:malicious OR classification:suspicious` |
| Page size | 1000 | 100 |
| Pagination | 30-minute chunk windows | page-based (6-hour chunks) |
| Metadata depth | basic (first/last seen, sensor attribution) | enriched (tags, CVEs, geo, signatures, sensor attribution) |

A third feed is derived from the filtered metadata:

| | High-confidence feed |
|---|---|
| Source | Derived from `filtered_metadata.json` |
| Filter | `multi_sensor: true` OR `classification: malicious` |
| Confidence | Highest (lowest false-positive risk) |

### First run bootstrap

If `feeds/ip_metadata.json` does not exist, bootstrap mode fetches the last 30 days automatically.

### Pagination constraints

The v1 scroll token is too large to reuse safely in request paths/headers, so v1 collection runs in 30-minute time chunks. This keeps feed convergence high and operationally stable under API limits.

---

## Scheduler behavior

Workflow: `.github/workflows/scheduler.yml`

- Hourly cron trigger (`0 * * * *`)
- Daily random plan generated in Berlin time (`Europe/Berlin`)
- Randomized target: 1 to 10 runs/day
- Scheduled hours persisted in `state/today.json`
- Missed-hour catch-up logic included (overdue hour handling)
- On failure, automatic retry at next cron tick
- `workflow_dispatch` bypasses schedule gating and forces a fetch

Result: organic, hard-to-predict update timing rather than rigid fixed intervals.

---

## Monthly archive snapshots

Workflow: `.github/workflows/monthly_archive.yml`

- Triggered daily at `23:00 UTC`
- Executes only on the last day of month (manual dispatch can bypass guard)
- Runs `scripts/archive_month.py`
- Writes `archive/YYYY-MM/` with:
  - `filtered_metadata.json`
  - `ip_metadata.json`
  - `summary.json`

This provides durable month-end snapshots independent of the rolling 30-day live window.

---

## File schemas

### `feeds/ip_metadata.json` (rolling 30-day index)

```json
{
  "192.0.2.1": {
    "first_seen": "2026-04-05T09:00:00Z",
    "last_seen": "2026-05-05T10:26:00Z",
    "seen_by": ["berlin", "tokyo"]
  }
}
```

### `feeds/filtered_metadata.json` (enriched filtered-feed metadata)

```json
{
  "192.0.2.1": {
    "first_seen": "2026-04-05T09:00:00Z",
    "last_seen": "2026-05-05T10:26:00Z",
    "classification": "malicious",
    "tags": ["Mirai TCP Scanner", "Mirai"],
    "tag_categories": ["worm"],
    "tag_intentions": ["malicious"],
    "cves": [],
    "country": "United States",
    "country_code": "US",
    "asn": "AS64496",
    "org": "Example ISP",
    "is_vpn": false,
    "is_tor": false,
    "is_bot": false,
    "rdns": "host.example.com",
    "destination_ports": [23, 80],
    "protocols": ["tcp"],
    "suricata_signatures": ["Mirai TCP Scanner"],
    "seen_by": ["berlin", "tokyo"],
    "multi_sensor": true
  }
}
```

### `runs/YYYY-MM-DD_HHMM_run_log.json` (always written)

```json
{
  "timestamp": "2026-05-05T12:00:00Z",
  "time_window_start": "2026-05-05T06:00:00Z",
  "time_window_end": "2026-05-05T12:00:00Z",
  "sessions_found": 412,
  "feed_ip_count": 1349,
  "filtered_ip_count": 87,
  "high_confidence_ip_count": 42,
  "sensor_count": 3,
  "duration_seconds": 8.3,
  "error": null
}
```

### `archive/YYYY-MM/summary.json` (monthly snapshot)

```json
{
  "month": "2026-05",
  "generated_at": "2026-05-31T23:00:00Z",
  "totals": {
    "sessions": 12450,
    "full_feed_ips": 1349,
    "filtered_ips": 87,
    "multi_sensor_ips": 23,
    "runs": 7
  },
  "by_country": { "US": 120, "CN": 85 },
  "by_tag": { "Mirai TCP Scanner": 45 },
  "by_tag_category": { "worm": 45 },
  "by_org": { "Example ISP": 30 },
  "by_destination_port": { "80": 120 },
  "by_classification": { "malicious": 60, "suspicious": 27 },
  "by_sensor": { "berlin": 75, "tokyo": 50 },
  "flags": { "is_vpn": 5, "is_tor": 3, "is_bot": 12 }
}
```
