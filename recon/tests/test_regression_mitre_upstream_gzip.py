"""MITRE CVE year files come from upstream's gzip copies, and an absent year is
not re-requested on every scan.

Found by the fix-regression end-to-end run (testing/guinea_pigs/
recon fix-regression lab): every year download 404'd. Upstream CVE2CAPEC now
publishes each year as database/CVE-<year>.jsonl.gz and no longer serves the
plain .jsonl, so no year could be fetched or refreshed. And because a missing
year is fetched even within the TTL, the same 404s repeated on every scan.

Every test points MITRE_DATABASE_PATH at a tmp dir and mocks requests.get; the
real downloader never runs and the tracked data files are never touched.
"""

from __future__ import annotations

import gzip
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import add_mitre  # noqa: E402

TTL_H = 24
YEAR = 2007
LINE = b'{"CVE-2007-5395": {"CWE": ["119"], "CAPEC": ["100"]}}\n'


def _settings(tmp_path):
    return {"MITRE_DATABASE_PATH": str(tmp_path / "mitre_db"), "MITRE_CACHE_TTL_HOURS": TTL_H}


def _fresh_db(tmp_path):
    db = tmp_path / "mitre_db"
    (db / "database").mkdir(parents=True)
    (db / "resources").mkdir(parents=True)
    for res in add_mitre.RESOURCE_FILES:
        (db / res).write_text("{}")
    (db / ".last_update").write_text(datetime.now().isoformat())
    return db


def _resp(content=b"", status=200):
    r = MagicMock()
    r.content = content
    r.status_code = status
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f"{status} Client Error")
    else:
        r.raise_for_status.return_value = None
    return r


def _get_router(gz=None, plain=None):
    """requests.get that answers the .gz and the plain year URL separately."""
    calls = []

    def get(url, timeout=None):
        calls.append(url)
        if url.endswith(".jsonl.gz"):
            return gz if gz is not None else _resp(status=404)
        if url.endswith(".jsonl"):
            return plain if plain is not None else _resp(status=404)
        return _resp(b"{}")
    return get, calls


def _update(tmp_path, get):
    with patch.object(add_mitre.requests, "get", side_effect=get):
        return add_mitre.update_database([f"CVE-{YEAR}-5395"], settings=_settings(tmp_path))


def test_regression_mitre_year_comes_from_upstream_gzip(tmp_path):
    db = _fresh_db(tmp_path)
    get, calls = _get_router(gz=_resp(gzip.compress(LINE)))
    assert _update(tmp_path, get) is True
    assert calls == [f"{add_mitre.CVE2CAPEC_RAW_BASE}/database/CVE-{YEAR}.jsonl.gz"]
    # Stored decompressed, under the plain name the reader opens.
    assert (db / "database" / f"CVE-{YEAR}.jsonl").read_bytes() == LINE


def test_the_plain_file_is_still_the_fallback(tmp_path):
    db = _fresh_db(tmp_path)
    get, calls = _get_router(plain=_resp(LINE))
    _update(tmp_path, get)
    assert [c.rsplit("/", 1)[-1] for c in calls] == [f"CVE-{YEAR}.jsonl.gz", f"CVE-{YEAR}.jsonl"]
    assert (db / "database" / f"CVE-{YEAR}.jsonl").read_bytes() == LINE


def test_regression_mitre_absent_year_not_refetched_every_scan(tmp_path):
    db = _fresh_db(tmp_path)
    get, calls = _get_router()                       # upstream lacks the year entirely
    _update(tmp_path, get)
    assert len(calls) == 2                           # tried once: .gz then plain
    assert not (db / "database" / f"CVE-{YEAR}.jsonl").exists()
    get2, calls2 = _get_router()
    _update(tmp_path, get2)                          # the next scan, still within the TTL
    assert calls2 == []


def test_an_absent_year_is_retried_once_the_ttl_has_passed(tmp_path):
    db = _fresh_db(tmp_path)
    stale = (datetime.now() - timedelta(hours=TTL_H + 1)).isoformat()
    (db / add_mitre._UNAVAILABLE_YEARS_FILE).write_text(json.dumps({str(YEAR): stale}))
    get, calls = _get_router(gz=_resp(gzip.compress(LINE)))
    _update(tmp_path, get)
    assert calls and calls[0].endswith(f"CVE-{YEAR}.jsonl.gz")
    # It downloaded, so it is forgotten rather than skipped next time.
    remembered = json.loads((db / add_mitre._UNAVAILABLE_YEARS_FILE).read_text())
    assert str(YEAR) not in remembered


def test_a_healthy_fresh_db_still_makes_no_request(tmp_path):
    db = _fresh_db(tmp_path)
    (db / "database" / f"CVE-{YEAR}.jsonl").write_bytes(LINE)
    get, calls = _get_router()
    assert _update(tmp_path, get) is True
    assert calls == []
    assert not (db / ".unavailable_years.json").exists()
