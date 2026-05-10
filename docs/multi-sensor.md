# Multi-Sensor Setup

SwarmNoise supports multiple GreyNoise Swarm sensors per workspace. When configured, IPs observed by multiple sensors are flagged in the metadata and a high-confidence feed is generated automatically.

---

## Configuration

### `SENSOR_IDS` secret format

Set the `SENSOR_IDS` GitHub Actions secret to a comma-separated list of `uuid:label` pairs:

```
SENSOR_IDS=a1b2c3d4-e5f6-7890-abcd-ef1234567890:berlin,c3d4e5f6-7890-abcd-ef12-345678901234:tokyo
```

- **uuid** — The GreyNoise Swarm sensor UUID
- **label** — A human-readable name (used in metadata output)

### Single sensor (backward compatible)

If you have only one sensor, either format works:

```
SENSOR_IDS=a1b2c3d4-e5f6-7890-abcd-ef1234567890:default
```

Or keep the legacy `SENSOR_ID` secret — SwarmNoise will automatically use it with the label `"default"`.

### Where to set it

`Settings → Secrets and variables → Actions` in your GitHub fork. Add or update the `SENSOR_IDS` secret.

---

## How it works

### `seen_by` field

Every IP in `feeds/ip_metadata.json` and `feeds/filtered_metadata.json` includes a `seen_by` field listing the sensor labels that observed that IP:

```json
{
  "192.0.2.1": {
    "first_seen": "2026-04-05T09:00:00Z",
    "last_seen": "2026-05-05T10:26:00Z",
    "seen_by": ["berlin", "tokyo"]
  }
}
```

### `multi_sensor` flag

In `filtered_metadata.json`, each IP also has a `multi_sensor` boolean:

```json
{
  "192.0.2.1": {
    "...": "...",
    "seen_by": ["berlin", "tokyo"],
    "multi_sensor": true
  }
}
```

Set to `true` when the IP was observed by 2 or more sensors.

---

## High-confidence feed

A third feed file is generated automatically:

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed_high_confidence.txt
```

This feed includes IPs that meet **either** of these criteria:

- Observed by **2 or more sensors** (`multi_sensor: true`)
- Classified as **malicious** by GreyNoise

### Why use it

Multi-sensor corroboration significantly reduces false positives. An IP seen attacking sensors in multiple locations is almost certainly engaged in broad scanning or exploitation campaigns, not a one-off misconfiguration.

For single-sensor users, this feed still has value: it includes all `malicious`-classified IPs from the filtered feed, providing a tighter subset than `threat_feed_filtered.txt` (which also includes `suspicious`).

### Use in production

This is the recommended feed for production deny policies:

| Feed | False-positive risk | Coverage | Recommended for |
|------|-------------------|----------|----------------|
| `threat_feed.txt` | Higher | Broadest | Detection, monitoring |
| `threat_feed_filtered.txt` | Medium | Malicious + suspicious | Staged blocking |
| `threat_feed_high_confidence.txt` | Lowest | Multi-sensor + malicious | **Production deny** |

---

## Querying sensor attribution

```bash
# Find IPs corroborated by multiple sensors
jq 'to_entries[] | select(.value.multi_sensor == true) | .key' feeds/filtered_metadata.json

# List all sensors that observed a specific IP
jq '.["192.0.2.1"].seen_by' feeds/filtered_metadata.json

# Count IPs per sensor
jq '[.[] | .seen_by[]] | group_by(.) | map({sensor: .[0], count: length})' feeds/filtered_metadata.json

# IPs seen by a specific sensor only
jq 'to_entries[] | select(.value.seen_by == ["berlin"]) | .key' feeds/filtered_metadata.json
```

---

## Diagnostic: Verifying sensor field detection

The GreyNoise API must return a sensor identifier per session for `seen_by` to work. To verify this on your first run:

1. Set a `DEBUG_SESSION_KEYS` GitHub Actions secret to `1`
2. Trigger a `workflow_dispatch` run
3. Check the run log — it will include `v1 session keys: [...]` and `v3 session keys: [...]`
4. If a sensor field is present, `seen_by` will be populated automatically
5. Remove the `DEBUG_SESSION_KEYS` secret after verification

If the API does not return a sensor field, `seen_by` will be empty (`[]`) for all IPs. The high-confidence feed will still work based on `classification: malicious` alone.
