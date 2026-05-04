#!/usr/bin/env python3
"""
fetch_sessions.py

Queries the GreyNoise Project Swarm Session API for Fortinet-targeted
attack traffic observed by the configured sensor. Writes session data
to data/ and a run log to runs/.

Environment variables required:
  GREYNOISE_API_KEY  — GreyNoise API key
  SENSOR_ID          — Swarm sensor UUID
  TIME_WINDOW_START  — ISO8601 UTC start of fetch window (optional,
                       defaults to 6 hours ago)
  TIME_WINDOW_END    — ISO8601 UTC end of fetch window (optional,
                       defaults to now)
"""

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# NOTE: If you get a 404, find the correct endpoint by inspecting the
# Network tab in browser DevTools while using the Session Explorer UI at
# viz.greynoise.io → Observe → Explore. Update this constant accordingly.
# ---------------------------------------------------------------------------
SWARM_API_BASE = "https://api.greynoise.io"
SESSIONS_ENDPOINT = f"{SWARM_API_BASE}/v1/workspaces/{{workspace_id}}/sessions/search"
WORKSPACE_ENDPOINT = f"{SWARM_API_BASE}/v1/workspaces"

PAGE_SIZE = 1000
FORTINET_FILTER = "gnMetadata.persona.name:Fortinet*"


def get_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"[error] Missing required environment variable: {name}", file=sys.stderr)
        sys.exit(1)
    return value


def get_workspace_id(api_key: str) -> str:
    """Fetch the workspace ID associated with the current API key."""
    headers = {
        "key": api_key,
        "Accept": "application/json",
    }
    try:
        resp = requests.get(WORKSPACE_ENDPOINT, headers=headers, timeout=30)
        if resp.status_code == 404:
            print(
                "[error] Workspace endpoint returned 404. The API endpoint may have changed.\n"
                "        Check the README for instructions on finding the correct endpoint.",
                file=sys.stderr,
            )
            sys.exit(1)
        resp.raise_for_status()
        data = resp.json()
        workspaces = data.get("workspaces") or data.get("data") or []
        if not workspaces:
            # Some API versions return the workspace directly
            if "id" in data:
                return data["id"]
            print("[error] No workspaces found in API response.", file=sys.stderr)
            sys.exit(1)
        return workspaces[0]["id"]
    except requests.RequestException as exc:
        print(f"[error] Failed to fetch workspace: {exc}", file=sys.stderr)
        sys.exit(1)


def fetch_sessions(
    api_key: str,
    workspace_id: str,
    sensor_id: str,
    window_start: datetime,
    window_end: datetime,
) -> list:
    """Fetch all Fortinet-filtered sessions for the sensor within the time window."""
    headers = {
        "key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    # Combine sensor filter with Fortinet persona filter
    query = (
        f"gnMetadata.sensor.id:{sensor_id} AND {FORTINET_FILTER}"
    )

    endpoint = SESSIONS_ENDPOINT.format(workspace_id=workspace_id)

    sessions = []
    scroll = None
    page = 0

    while True:
        page += 1
        payload = {
            "query": query,
            "size": PAGE_SIZE,
            "start_time": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if scroll:
            payload["scroll"] = scroll

        try:
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=60)

            if resp.status_code == 404:
                print(
                    "[error] Sessions endpoint returned 404. The API endpoint may differ.\n"
                    "        Check the README for instructions on finding the correct endpoint.\n"
                    f"        Tried: POST {endpoint}",
                    file=sys.stderr,
                )
                sys.exit(1)

            if resp.status_code == 401:
                print(
                    "[error] Authentication failed (401). Check your GREYNOISE_API_KEY.",
                    file=sys.stderr,
                )
                sys.exit(1)

            resp.raise_for_status()
            data = resp.json()

        except requests.RequestException as exc:
            print(f"[error] Request failed on page {page}: {exc}", file=sys.stderr)
            sys.exit(1)

        page_sessions = data.get("data") or data.get("sessions") or []
        sessions.extend(page_sessions)

        print(f"  [page {page}] fetched {len(page_sessions)} sessions "
              f"(total so far: {len(sessions)})")

        # Pagination
        meta = data.get("request_metadata") or data.get("metadata") or {}
        complete = meta.get("complete", True)
        scroll = meta.get("scroll")

        if complete or not scroll or not page_sessions:
            break

    return sessions


def write_outputs(
    sessions: list,
    sensor_id: str,
    window_start: datetime,
    window_end: datetime,
    fetch_ts: datetime,
    duration: float,
    error: str | None,
) -> None:
    """Write data file (if sessions found) and run log (always)."""
    ts_str = fetch_ts.strftime("%Y-%m-%d_%H%M")
    repo_root = Path(__file__).parent.parent

    data_dir = repo_root / "data"
    runs_dir = repo_root / "runs"
    data_dir.mkdir(exist_ok=True)
    runs_dir.mkdir(exist_ok=True)

    # Run log — always written
    run_log = {
        "timestamp": fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sensor_id": sensor_id,
        "filter": FORTINET_FILTER,
        "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_window_end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sessions_found": len(sessions),
        "duration_seconds": round(duration, 2),
        "error": error,
    }
    run_log_path = runs_dir / f"{ts_str}_run_log.json"
    run_log_path.write_text(json.dumps(run_log, indent=2))
    print(f"[+] Run log written: {run_log_path.name}")

    # Session data — only if we have sessions
    if sessions:
        data_payload = {
            "fetch_timestamp": fetch_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sensor_id": sensor_id,
            "filter": FORTINET_FILTER,
            "time_window_start": window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "time_window_end": window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "session_count": len(sessions),
            "sessions": sessions,
        }
        data_path = data_dir / f"{ts_str}.json"
        data_path.write_text(json.dumps(data_payload, indent=2))
        print(f"[+] Session data written: {data_path.name} ({len(sessions)} sessions)")
    else:
        print("[~] No Fortinet sessions found in this window — data file skipped.")


def main() -> None:
    api_key = get_env("GREYNOISE_API_KEY")
    sensor_id = get_env("SENSOR_ID")

    now = datetime.now(timezone.utc)

    # Time window: use env vars if provided (for precise non-overlapping windows),
    # otherwise default to last 6 hours
    window_start_str = os.environ.get("TIME_WINDOW_START")
    window_end_str = os.environ.get("TIME_WINDOW_END")

    if window_start_str and window_end_str:
        window_start = datetime.fromisoformat(window_start_str.replace("Z", "+00:00"))
        window_end = datetime.fromisoformat(window_end_str.replace("Z", "+00:00"))
    else:
        window_end = now
        window_start = now - timedelta(hours=6)

    print(f"[*] GreyNoise Swarm — Fortinet session fetch")
    print(f"    Sensor  : {sensor_id}")
    print(f"    Filter  : {FORTINET_FILTER}")
    print(f"    Window  : {window_start.strftime('%Y-%m-%dT%H:%M:%SZ')} → "
          f"{window_end.strftime('%Y-%m-%dT%H:%M:%SZ')}")

    start_time = time.monotonic()
    error = None
    sessions = []

    try:
        print("[*] Resolving workspace ID...")
        workspace_id = get_workspace_id(api_key)
        print(f"    Workspace: {workspace_id}")

        print("[*] Fetching sessions...")
        sessions = fetch_sessions(
            api_key, workspace_id, sensor_id, window_start, window_end
        )
    except SystemExit:
        raise
    except Exception as exc:
        error = str(exc)
        print(f"[error] Unexpected error: {exc}", file=sys.stderr)

    duration = time.monotonic() - start_time
    write_outputs(sessions, sensor_id, window_start, window_end, now, duration, error)

    print(f"[*] Done in {duration:.1f}s — {len(sessions)} sessions collected.")


if __name__ == "__main__":
    main()
