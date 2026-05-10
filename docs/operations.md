# Operations

## Operator playbook

1. Start with `threat_feed_high_confidence.txt` in production deny policies (lowest false-positive risk)
2. Track feed growth and churn using `runs/*_run_log.json`
3. Review `filtered_metadata.json` tags/CVEs before adding custom block automation
4. Use monthly `archive/YYYY-MM/summary.json` for trend baselining
5. Use `threat_feed.txt` for broader detection-focused controls where acceptable
6. Use `seen_by` in metadata to identify geographic attack patterns — IPs hitting multiple sensors suggest broader scanning campaigns

---

## Querying data locally

```bash
# Count full-feed IPs
wc -l feeds/threat_feed.txt

# Count filtered-feed IPs
wc -l feeds/threat_feed_filtered.txt

# Count high-confidence IPs
wc -l feeds/threat_feed_high_confidence.txt

# Inspect enriched metadata
jq '.' feeds/filtered_metadata.json

# Inspect latest monthly snapshot summary
jq '.' archive/$(date -u +%Y-%m)/summary.json

# Find IPs corroborated by multiple sensors
jq 'to_entries[] | select(.value.multi_sensor == true) | .key' feeds/filtered_metadata.json

# List sensors that observed a specific IP
jq '.["192.0.2.1"].seen_by' feeds/filtered_metadata.json

# Count IPs per sensor
jq '[.[] | .seen_by[]] | group_by(.) | map({sensor: .[0], count: length})' feeds/filtered_metadata.json
```

---

## Troubleshooting

### No feed updates visible

- Check latest run in Actions (`Scheduler - Randomized Daily Fetch`)
- Verify `state/today.json` has scheduled hours and completed runs
- Confirm required secrets are set (`GREYNOISE_API_KEY`, `WORKSPACE_ID`, `SENSOR_IDS` or `SENSOR_ID`, `GH_PAT`)

### Workflow runs but no sessions found

- This can be legitimate for low-activity windows
- Check run log `error` field and time window coverage
- Manual dispatch can force an immediate run for validation

### Archive did not appear

- Archive workflow only writes on last day of month unless manually triggered
- Check `.github/workflows/monthly_archive.yml` logs for guard decision output

### `seen_by` is empty for all IPs

- The GreyNoise API may not return a sensor identifier per session
- Set `DEBUG_SESSION_KEYS=1` as a GitHub Actions secret and trigger a manual run
- Check the run log for `v1 session keys: [...]` and `v3 session keys: [...]`
- The high-confidence feed still works based on `classification: malicious` alone

---

## Security notes

- Never commit API keys or PAT tokens — keep all credentials in GitHub Actions secrets
- **Keep the repository private (recommended).** Forking as a private repo prevents your sensor's attacker activity from being publicly visible. Use a fine-grained GitHub PAT with `Contents: Read-only` scope on your firewall for feed access — see [Firewall Integration](firewall-integration.md)
- The `GH_PAT` Actions secret (write access, used by workflows to commit feed updates) and the firewall PAT (read-only, used to pull feeds) should be **separate tokens** with separate scopes
- If you choose to make the repository public, feed files are publicly accessible — this is intentional for firewall consumption, but be aware your sensor's observed attacker activity will be visible to anyone
- The `SENSOR_IDS` and `SENSOR_ID` secrets contain sensor UUIDs that are account-specific identifiers — they are never committed to the repository
