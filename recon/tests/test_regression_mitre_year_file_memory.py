"""MITRE CVE year files are never held whole in memory.

Found by the AI-in-Pipeline live check (testing/guinea_pigs/serialized_target): a
full IP-mode recon was OOM-killed (exit 137) in MITRE enrichment. Since the years
come from upstream's gzip copies, a run fetches the current files, and the recent
ones are huge (CVE-2026.jsonl ~1 GB, CVE-2025 ~600 MB). The reader parsed a whole
year into a dict to look up a handful of CVEs (5-8x the file in RAM), and the
downloader inflated the gzip in one piece: both past the scan container's memory.

Every test works in a tmp dir and mocks requests.get; the real downloader never
runs and the tracked data files are never touched.
"""

from __future__ import annotations

import gzip
import json
import sys
import tracemalloc
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import add_mitre  # noqa: E402

YEAR = 2026


def _line(cve_id: str, cwe: str = "79", capec_count: int = 3) -> bytes:
    data = {"CWE": [cwe], "CAPEC": [str(i) for i in range(capec_count)]}
    return (json.dumps({cve_id: data}) + "\n").encode()


def _db_with_year(tmp_path, lines) -> add_mitre.MITREDatabase:
    db = tmp_path / "mitre_db"
    (db / "database").mkdir(parents=True)
    (db / "database" / f"CVE-{YEAR}.jsonl").write_bytes(b"".join(lines))
    return add_mitre.MITREDatabase(db_path=db)


def _full_parse(path: Path) -> dict:
    """The oracle: every line parsed, every CVE key kept, a later line winning."""
    out = {}
    for raw in path.read_text().splitlines():
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            out.update({k.upper(): v for k, v in entry.items() if k.upper().startswith("CVE-")})
    return out


def _peak_bytes(fn):
    tracemalloc.start()
    try:
        result = fn()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# --------------------------------------------------------------------------- #
# Reader: a lookup returns what a full parse would, without one
# --------------------------------------------------------------------------- #
def test_every_cve_reads_back_as_a_full_parse_would(tmp_path):
    mdb = _db_with_year(tmp_path, [
        _line(f"CVE-{YEAR}-0001"),
        b"\n",
        _line(f"cve-{YEAR}-0002", cwe="89"),                     # lower-case key
        b'{"CVE-%d-0003": {"CWE": [\n' % YEAR,                      # truncated line
        b' { "CVE-%d-0004" : {"CWE": ["22"]}}\n' % YEAR,            # spaced key
        b'["CVE-%d-0006"]\n' % YEAR,                                # not an object
        _line(f"CVE-{YEAR}-0005", capec_count=500),
        _line(f"CVE-{YEAR}-0001", cwe="787"),                    # a later duplicate wins
    ])
    expected = _full_parse(mdb.db_path / "database" / f"CVE-{YEAR}.jsonl")
    assert len(expected) == 4

    for cve_id, data in expected.items():
        assert mdb.get_cve_data(cve_id) == data
        assert mdb.get_cve_data(cve_id.lower()) == data
    assert mdb.get_cve_data(f"CVE-{YEAR}-0001")["CWE"] == ["787"]
    assert mdb.get_cve_data(f"CVE-{YEAR}-0003") is None
    assert mdb.get_cve_data(f"CVE-{YEAR}-0006") is None
    assert mdb.get_cve_data(f"CVE-{YEAR}-9999") is None


def test_regression_a_year_file_is_never_parsed_whole(tmp_path):
    # ~7 MB of upstream-shaped lines; the whole-file parse peaked near 10x that.
    mdb = _db_with_year(tmp_path, [_line(f"CVE-{YEAR}-{i:05d}", capec_count=600) for i in range(2000)])
    size = (mdb.db_path / "database" / f"CVE-{YEAR}.jsonl").stat().st_size
    wanted = [f"CVE-{YEAR}-00007", f"CVE-{YEAR}-01000", f"CVE-{YEAR}-01999"]

    found, peak = _peak_bytes(lambda: [mdb.get_cve_data(c) for c in wanted])

    assert [len(d["CAPEC"]) for d in found] == [600, 600, 600]
    assert peak < size / 4, f"peak {peak} B for a {size} B year file"


def test_missing_year_and_malformed_ids_return_none(tmp_path):
    mdb = _db_with_year(tmp_path, [_line(f"CVE-{YEAR}-0001")])
    assert mdb.get_cve_data("CVE-2031-0001") is None             # no file for that year
    assert mdb.get_cve_data("garbage") is None
    assert mdb.get_cve_data("CVE-x-1") is None


def test_a_year_replaced_after_indexing_never_yields_another_cves_data(tmp_path):
    # Concurrent scans share the bind-mounted DB, and a refresh os.replace()s a
    # year file under a run that already indexed it. Same-length lines in a new
    # order put each stale offset exactly on the OTHER CVE's line.
    a, b = f"CVE-{YEAR}-0001", f"CVE-{YEAR}-0002"
    mdb = _db_with_year(tmp_path, [_line(a, cwe="11"), _line(b, cwe="22")])
    mdb.index_cve_year(YEAR)
    (mdb.db_path / "database" / f"CVE-{YEAR}.jsonl").write_bytes(
        _line(b, cwe="33") + _line(a, cwe="44"))

    assert mdb.get_cve_data(a) is None
    assert mdb.get_cve_data(b) is None


# --------------------------------------------------------------------------- #
# Downloader: the upstream gzip is inflated in chunks, still atomically
# --------------------------------------------------------------------------- #
def _resp(content=b"", status=200):
    r = MagicMock()
    r.content = content
    if status >= 400:
        r.raise_for_status.side_effect = requests.HTTPError(f"{status} Client Error")
    else:
        r.raise_for_status.return_value = None
    return r


def _get(gz_resp):
    """requests.get answering the .gz year URL with gz_resp, and 404 otherwise."""
    return lambda url, timeout=None: gz_resp if url.endswith(".jsonl.gz") else _resp(status=404)


def test_regression_the_gzip_year_is_inflated_in_chunks(tmp_path):
    (tmp_path / "database").mkdir()
    payload = b"".join(_line(f"CVE-{YEAR}-{i:05d}", capec_count=300) for i in range(9000))
    assert len(payload) > 16 << 20
    gz = _resp(gzip.compress(payload))

    with patch.object(add_mitre.requests, "get", side_effect=_get(gz)):
        ok, peak = _peak_bytes(lambda: add_mitre.download_cve_database_year(tmp_path, YEAR))

    assert ok is True
    assert (tmp_path / "database" / f"CVE-{YEAR}.jsonl").read_bytes() == payload
    assert peak < len(payload) / 4, f"peak {peak} B for a {len(payload)} B year"


def test_a_truncated_gzip_leaves_the_existing_year_file_intact(tmp_path):
    (tmp_path / "database").mkdir()
    target = tmp_path / "database" / f"CVE-{YEAR}.jsonl"
    target.write_bytes(b"complete previous copy\n")
    payload = b"".join(_line(f"CVE-{YEAR}-{i:05d}") for i in range(5000))
    gz = _resp(gzip.compress(payload)[:-64])

    with patch.object(add_mitre.requests, "get", side_effect=_get(gz)):
        assert add_mitre.download_cve_database_year(tmp_path, YEAR) is False

    assert target.read_bytes() == b"complete previous copy\n"
    assert [p.name for p in (tmp_path / "database").iterdir()] == [target.name]
