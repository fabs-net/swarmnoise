# Firewall Integration

SwarmNoise produces three newline-separated IP threat feeds compatible with any firewall or security platform that supports external IP block lists.

---

## Available feeds

| Feed | URL path | Description |
|------|----------|-------------|
| Full | `feeds/threat_feed.txt` | All attacker IPs (rolling 30-day) |
| Filtered | `feeds/threat_feed_filtered.txt` | Malicious + suspicious only |
| High-confidence | `feeds/threat_feed_high_confidence.txt` | Multi-sensor corroborated or malicious |

Replace the path in the full URL:

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/<feed-file>
```

All feeds are:
- One IP per line (no comments, no headers)
- Rolling 30-day window (auto-pruned)
- Updated at randomized times each day

---

## Feed selection guide

| Feed | False-positive risk | Coverage | Recommended for |
|------|-------------------|----------|----------------|
| `threat_feed.txt` | Higher | Broadest | Detection, monitoring |
| `threat_feed_filtered.txt` | Medium | Malicious + suspicious | Staged blocking |
| `threat_feed_high_confidence.txt` | Lowest | Multi-sensor + malicious | **Production deny** |

For lower false-positive tolerance, substitute a stricter feed in any URL below.

---

## Generic configuration

| Field | Value |
|---|---|
| Format | One IP per line, no headers |
| Authentication | HTTP Basic Auth with a GitHub PAT (private repo, recommended) or none (public repo) |
| Recommended refresh | 60 min |

---

## Private repo access (recommended)

Keep your fork **private**. This prevents your sensor's attacker activity from being publicly visible while still allowing your firewall to pull the feeds directly over HTTPS.

GitHub's `raw.githubusercontent.com` endpoint accepts a Personal Access Token (PAT) as an HTTP Basic Auth password. Most firewall platforms expose username/password fields in their external connector or threat feed configuration — this maps cleanly to that model.

### Create a dedicated read-only PAT for your firewall

1. Go to `GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens`
2. Click **Generate new token**
3. Set **Resource owner** to your account (or org)
4. Under **Repository access**, select **Only select repositories** → choose your swarmnoise fork
5. Under **Permissions → Repository permissions**, set **Contents** to `Read-only`
6. Leave all other permissions at `No access`
7. Generate and copy the token (`github_pat_...`)

> This token is separate from the `GH_PAT` Actions secret (which needs write access to commit feed updates). The firewall PAT is strictly read-only and scoped to a single repository.

### Configure your firewall

| Field | Value |
|---|---|
| Username | `x-token` (any string is accepted by GitHub) |
| Password | `github_pat_xxxxxxxxxxxx` (your fine-grained PAT) |

GitHub validates the token and serves the raw file. No proxy or self-hosted infrastructure is required.

**Public repo alternative:** If you are comfortable with your sensor activity being publicly visible, make the fork public. No authentication is required — the feed URLs work directly with no credentials.

---

## Platform examples

### FortiGate — `Security Fabric → External Connectors → Threat Feeds → IP Address`

Private repo (recommended):

| Field | Value |
|---|---|
| Name | `swarmnoise` |
| URI | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| HTTP basic auth | on |
| Username | `x-token` |
| Password | `github_pat_xxxxxxxxxxxx` |
| Refresh rate | 60 min |

Public repo:

| Field | Value |
|---|---|
| Name | `swarmnoise` |
| URI | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| HTTP basic auth | off |
| Refresh rate | 60 min |

### Palo Alto Networks (EDL) — `Objects → External Dynamic Lists`

| Field | Value |
|---|---|
| Type | IP List |
| Source | `https://x-token:github_pat_xxxxxxxxxxxx@raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| Repeat | Every hour |

> Palo Alto EDL sources do not have separate credential fields — embed credentials directly in the URL as shown. For public repos, use the plain URL without credentials.

### pfSense / OPNsense — `Firewall → Aliases → URLs`

| Field | Value |
|---|---|
| Type | URL Table (IPs) |
| URL | `https://x-token:github_pat_xxxxxxxxxxxx@raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| Refresh | 1 day (or use cron for hourly) |

> pfSense and OPNsense URL alias fields do not have separate credential fields — embed credentials in the URL as shown. For public repos, use the plain URL without credentials.

---

## Using the high-confidence feed

For any platform above, replace `threat_feed.txt` with `threat_feed_high_confidence.txt` in the URI/URL. This is the recommended feed for production deny policies — see [Multi-Sensor Setup](multi-sensor.md) for details.
