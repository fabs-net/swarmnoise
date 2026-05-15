import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import scripts.archive_month as archive


@pytest.fixture(autouse=True)
def _isolate_paths(tmp_path, monkeypatch):
    """Redirect all module-level path constants to tmp_path for every test."""
    feeds_dir = tmp_path / "feeds"
    runs_dir = tmp_path / "runs"
    archive_dir = tmp_path / "archive"
    for d in (feeds_dir, runs_dir, archive_dir):
        d.mkdir()
    monkeypatch.setattr(archive, "FEEDS_DIR", feeds_dir)
    monkeypatch.setattr(archive, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(archive, "ARCHIVE_DIR", archive_dir)
    return {"feeds": feeds_dir, "runs": runs_dir, "archive": archive_dir}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ip_meta(
    country_code="DE",
    org="Test ISP",
    tags=None,
    tag_categories=None,
    destination_ports=None,
    classification="malicious",
    is_vpn=False,
    is_tor=False,
    is_bot=False,
    multi_sensor=False,
    seen_by=None,
):
    return {
        "country_code": country_code,
        "org": org,
        "tags": tags or ["Mirai"],
        "tag_categories": tag_categories or ["worm"],
        "destination_ports": destination_ports or [23],
        "classification": classification,
        "is_vpn": is_vpn,
        "is_tor": is_tor,
        "is_bot": is_bot,
        "multi_sensor": multi_sensor,
        "seen_by": seen_by or ["berlin"],
    }


def _make_run_log(month="2026-05", sessions=100):
    return {
        "timestamp": f"{month}-10T12:00:00Z",
        "sessions_found": sessions,
    }


# ---------------------------------------------------------------------------
# build_summary
# ---------------------------------------------------------------------------

def test_build_summary_basic():
    filtered = {
        "1.2.3.4": _make_ip_meta(country_code="DE", org="ISP A", tags=["Mirai"],
                                  tag_categories=["worm"], destination_ports=[23],
                                  classification="malicious"),
        "5.6.7.8": _make_ip_meta(country_code="US", org="ISP B", tags=["Scanner"],
                                  tag_categories=["scanner"], destination_ports=[80, 443],
                                  classification="suspicious"),
    }
    run_logs = [_make_run_log("2026-05", 50), _make_run_log("2026-05", 75)]
    result = archive.build_summary(filtered, {}, run_logs, "2026-05", "2026-05-31T23:00:00Z")

    assert result["month"] == "2026-05"
    assert result["totals"]["filtered_ips"] == 2
    assert result["totals"]["sessions"] == 125
    assert result["totals"]["runs"] == 2
    assert result["by_country"]["DE"] == 1
    assert result["by_country"]["US"] == 1
    assert result["by_tag"]["Mirai"] == 1
    assert result["by_tag"]["Scanner"] == 1
    assert result["by_destination_port"]["23"] == 1
    assert result["by_destination_port"]["80"] == 1
    assert result["by_classification"]["malicious"] == 1
    assert result["by_classification"]["suspicious"] == 1
    assert result["by_org"]["ISP A"] == 1


def test_build_summary_empty_feeds():
    result = archive.build_summary({}, {}, [], "2026-05", "2026-05-31T23:00:00Z")

    assert result["totals"]["filtered_ips"] == 0
    assert result["totals"]["full_feed_ips"] == 0
    assert result["totals"]["sessions"] == 0
    assert result["totals"]["runs"] == 0
    assert result["by_country"] == {}
    assert result["by_tag"] == {}
    assert result["flags"] == {"is_vpn": 0, "is_tor": 0, "is_bot": 0}


def test_build_summary_run_log_month_filter():
    run_logs = [
        _make_run_log("2026-05", 10),   # current month — included
        _make_run_log("2026-04", 999),  # prior month — excluded
        _make_run_log("2026-05", 20),   # current month — included
    ]
    result = archive.build_summary({}, {}, run_logs, "2026-05", "2026-05-31T23:00:00Z")

    assert result["totals"]["runs"] == 2
    assert result["totals"]["sessions"] == 30


def test_build_summary_missing_optional_fields():
    """IPs with null/missing fields must not raise and fall back gracefully."""
    filtered = {
        "1.2.3.4": {
            "country_code": None,
            "org": None,
            "tags": None,
            "tag_categories": None,
            "destination_ports": None,
            "classification": None,
            "multi_sensor": False,
            "seen_by": None,
        },
        "5.6.7.8": {},  # completely empty
    }
    result = archive.build_summary(filtered, {}, [], "2026-05", "2026-05-31T23:00:00Z")

    assert result["by_country"].get("unknown", 0) == 2
    assert result["by_org"].get("unknown", 0) == 2
    assert result["by_classification"].get("unknown", 0) == 2


def test_build_summary_flags():
    filtered = {
        "1.1.1.1": _make_ip_meta(is_vpn=True),
        "2.2.2.2": _make_ip_meta(is_tor=True),
        "3.3.3.3": _make_ip_meta(is_bot=True),
        "4.4.4.4": _make_ip_meta(is_vpn=True, is_tor=True),
        "5.5.5.5": _make_ip_meta(),  # no flags
    }
    result = archive.build_summary(filtered, {}, [], "2026-05", "2026-05-31T23:00:00Z")

    assert result["flags"]["is_vpn"] == 2
    assert result["flags"]["is_tor"] == 2
    assert result["flags"]["is_bot"] == 1


def test_build_summary_multi_sensor():
    filtered = {
        "1.1.1.1": _make_ip_meta(multi_sensor=True, seen_by=["berlin", "tokyo"]),
        "2.2.2.2": _make_ip_meta(multi_sensor=False, seen_by=["berlin"]),
        "3.3.3.3": _make_ip_meta(multi_sensor=True, seen_by=["berlin", "london"]),
    }
    result = archive.build_summary(filtered, {}, [], "2026-05", "2026-05-31T23:00:00Z")

    assert result["totals"]["multi_sensor_ips"] == 2
    assert result["by_sensor"]["berlin"] == 3
    assert result["by_sensor"]["tokyo"] == 1
    assert result["by_sensor"]["london"] == 1


# ---------------------------------------------------------------------------
# load_run_logs
# ---------------------------------------------------------------------------

def test_load_run_logs_empty_dir(_isolate_paths):
    result = archive.load_run_logs(_isolate_paths["runs"])
    assert result == []


def test_load_run_logs_skips_bad_files(_isolate_paths, capsys):
    runs_dir = _isolate_paths["runs"]
    # Valid log
    (runs_dir / "2026-05-10_run_log.json").write_text(
        json.dumps({"timestamp": "2026-05-10T12:00:00Z", "sessions_found": 42})
    )
    # Malformed JSON
    (runs_dir / "2026-05-11_run_log.json").write_text("not valid json{{")

    result = archive.load_run_logs(runs_dir)

    assert len(result) == 1
    assert result[0]["sessions_found"] == 42
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()


# ---------------------------------------------------------------------------
# load_json
# ---------------------------------------------------------------------------

def test_load_json_exits_on_missing_file(tmp_path):
    with pytest.raises(SystemExit) as exc_info:
        archive.load_json(tmp_path / "nonexistent.json")
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# main() — end-to-end
# ---------------------------------------------------------------------------

def test_main_writes_archive_files(_isolate_paths):
    feeds_dir = _isolate_paths["feeds"]
    runs_dir = _isolate_paths["runs"]
    archive_dir = _isolate_paths["archive"]

    filtered = {"1.2.3.4": _make_ip_meta()}
    ip_meta = {"1.2.3.4": {"first_seen": "2026-05-01T00:00:00Z"}}
    (feeds_dir / "filtered_metadata.json").write_text(json.dumps(filtered))
    (feeds_dir / "ip_metadata.json").write_text(json.dumps(ip_meta))
    (runs_dir / "2026-05-10_run_log.json").write_text(
        json.dumps({"timestamp": "2026-05-10T12:00:00Z", "sessions_found": 10})
    )

    fixed_now = datetime(2026, 5, 31, 23, 0, 0, tzinfo=timezone.utc)
    with patch("scripts.archive_month.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        mock_dt.now.side_effect = None
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        archive.main()

    out_dir = archive_dir / "2026-05"
    assert (out_dir / "filtered_metadata.json").exists()
    assert (out_dir / "ip_metadata.json").exists()
    assert (out_dir / "summary.json").exists()

    summary = json.loads((out_dir / "summary.json").read_text())
    assert summary["totals"]["filtered_ips"] == 1
    assert summary["totals"]["full_feed_ips"] == 1


def test_main_exits_if_filtered_metadata_missing(_isolate_paths):
    feeds_dir = _isolate_paths["feeds"]
    (feeds_dir / "ip_metadata.json").write_text("{}")
    # filtered_metadata.json intentionally absent

    with pytest.raises(SystemExit) as exc_info:
        archive.main()
    assert exc_info.value.code == 1


def test_main_exits_if_ip_metadata_missing(_isolate_paths):
    feeds_dir = _isolate_paths["feeds"]
    (feeds_dir / "filtered_metadata.json").write_text("{}")
    # ip_metadata.json intentionally absent

    with pytest.raises(SystemExit) as exc_info:
        archive.main()
    assert exc_info.value.code == 1
