"""The serialized-object assessment on Jev (plan §19).

What it locks in:
- the agent sees bounded, typed items, and never the deterministic format, so the
  agreement it records is independent of the signature's verdict;
- candidates that share every Jev-visible field collapse to one question set; a
  different location is a different blob;
- the closed format set is exactly what the detector can emit, so a new detector
  family cannot reach Jev unannounced;
- per-scan cap and wall-clock budget; a failed batch is a fallback, never a crash,
  never re-asked; a malformed answer is a fallback;
- SHADOW (the shipped rollout) changes nothing on the candidates or their order and
  records Jev's answer next to the signature's format; ACT annotates and ranks,
  never drops a candidate and never rewrites deser_format (part of the graph id);
- stdout carries counts and indexes only, so no line can move the recon drawer;
- the hook sits in run_serialized_scan, the entry the full pipeline and partial
  recon share, before the result is built.
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.helpers.ai_planner import serialized_assess as sa

REPO = Path(__file__).resolve().parents[2]

#: The drawer's phase regexes (recon_orchestrator/container_manager.py PHASE_PATTERNS).
_DRAWER = re.compile(r"port.*scan|http.*prob|resource.*enum|vuln.*scan|domain.*discovery|"
                     r"nuclei|mitre|cwe|capec|ai_surface_recon", re.I)


@pytest.fixture(autouse=True)
def _fresh_breakers():
    """The agent_jev breaker is process-wide; a failure test must not pause the next one."""
    cb.reset_registry()
    yield
    cb.reset_registry()


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _finding(i=0, **over):
    f = {"endpoint_url": f"http://h{i}.example.test/login", "http_method": "GET",
         "baseurl": f"http://h{i}.example.test", "path": "/login", "confidence": 0.9,
         "source": "serialized_scan", "deser_language": "java", "deser_format": "native_java",
         "deser_transport": "cookie", "deser_location": f"session_{i}",
         "deser_encoding_layers": ["base64"], "deser_magic": "rO0AB",
         "evidence_snippet": f"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA{i}"}
    f.update(over)
    return f


def _echo_post(label=("native_java", 80, 60), status=200, per_location=None):
    """A fake requests.post for /jev/serialized-classify. `per_location` maps a
    location to its own (format, confidence, exploitability)."""
    calls = []

    def post(url, json=None, headers=None, timeout=None):
        calls.append(json)
        if status != 200:
            return _resp(status, {"error_type": "jev_timeout"})
        labels = []
        for blob in json["blobs"]:
            fmt, conf, reach = (per_location or {}).get(blob["location"], label)
            labels.append({"format": fmt, "format_confidence": conf, "exploitability": reach})
        return _resp(200, {"labels": labels, "model": "jev-1.13.0"})
    return calls, post


# ---------------------------------------------------------------------------
# Items, keys, the closed set
# ---------------------------------------------------------------------------

def test_the_request_item_is_bounded_typed_and_never_carries_the_baseline():
    big = _finding(evidence_snippet="s" * 900, deser_magic="m" * 300, deser_location="l" * 900,
                   deser_transport="smtp", deser_encoding_layers=["rot13", "url"] + ["hex"] * 20)
    blob = sa._blob(big)
    assert set(blob) == {"snippet", "magic", "transport", "location", "encoding_layers"}
    assert len(blob["snippet"]) == sa.SNIPPET_CHARS == 200
    assert len(blob["magic"]) == sa._MAGIC_CHARS and len(blob["location"]) == sa._LOCATION_CHARS
    assert blob["transport"] == ""                                   # outside the closed set
    assert blob["encoding_layers"] == ["url"] + ["hex"] * (sa._MAX_LAYERS - 1)
    assert "native_java" not in str(blob)                            # no anchoring on the signature


def test_identical_blobs_share_a_key_and_a_different_location_does_not():
    a, b = _finding(0), _finding(0, endpoint_url="http://other.example.test/x")
    assert sa.cache_key(a) == sa.cache_key(b)                        # same blob on two endpoints
    assert sa.cache_key(a) != sa.cache_key(_finding(0, deser_location="other_cookie"))


@pytest.mark.parametrize("finding,ok", [
    (_finding(), True),
    (_finding(evidence_snippet=""), True),                           # the magic alone is a signal
    (_finding(deser_magic=""), True),
    (_finding(evidence_snippet="", deser_magic=""), False),
])
def test_a_candidate_without_any_signal_is_never_asked_about(finding, ok):
    assert sa._assessable(finding) is ok


def test_the_closed_set_is_exactly_what_the_detector_can_emit():
    from recon.serialized_scan import signatures
    emitted = {row[1] for row in signatures._TEXT + signatures._BYTES + signatures._HEADER_VALUES}
    assert set(sa.FORMATS) == emitted
    assert sa.LABELS == frozenset(sa.FORMATS) | {"none"}


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

def test_the_shipped_rollout_is_shadow():
    assert sa.ROLLOUT == jev_shadow.SHADOW


def test_shadow_records_and_leaves_the_candidates_alone(capsys):
    findings = [_finding(i) for i in range(3)]
    before = [dict(f) for f in findings]
    data = {}
    calls, post = _echo_post(per_location={"session_1": ("none", 90, 5)})
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = sa.run_serialized_assess_pass(findings, user_id="u1", project_id="p1", recon_data=data)
    assert stats["candidates"] == 3 and stats["asked"] == 3 and stats["assessed"] == 3
    assert findings == before                                       # nothing written, order kept
    assert calls[0]["user_id"] == "u1" and calls[0]["project_id"] == "p1"
    shadow = data["jev_shadow"]["serialized_assess"]
    assert shadow["rollout"] == "shadow" and shadow["model"] == "jev-1.13.0"
    rec = {r["item"]: r for r in shadow["records"]}
    assert rec["blob_0"]["jev"] == "native_java" and rec["blob_0"]["agreed"] is True
    assert rec["blob_1"]["jev"] == "none" and rec["blob_1"]["agreed"] is False
    assert rec["blob_1"]["baseline"] == "native_java" and rec["blob_1"]["exploitability"] == 5
    assert rec["blob_1"]["location"] == "session_1"                 # the records keep the item
    out = capsys.readouterr().out
    assert "example.test" not in out and "session_" not in out and "rO0AB" not in out
    assert not _DRAWER.search(out), out
    assert "jev-shadow serialized_assess: summary decisions=3 agreed=67%" in out


def test_act_annotates_and_ranks_without_dropping_or_rewriting_the_format(monkeypatch):
    monkeypatch.setattr(sa, "ROLLOUT", jev_shadow.ACT)
    findings = [_finding(i) for i in range(4)]
    findings.append(_finding(9, evidence_snippet="", deser_magic=""))   # no signal: never asked
    reach = {"session_0": ("native_java", 80, 20), "session_1": ("none", 95, 5),
             "session_2": ("viewstate", 70, 90), "session_3": ("native_java", 85, 60)}
    _, post = _echo_post(per_location=reach)
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        sa.run_serialized_assess_pass(findings, user_id="u", project_id="p", recon_data={})
    assert len(findings) == 5                                       # never drops
    assert [f["deser_location"] for f in findings] == \
        ["session_2", "session_3", "session_0", "session_1", "session_9"]
    assert all(f["deser_format"] == "native_java" for f in findings)   # the floor stands
    top = findings[0]
    assert (top["deser_jev_format"], top["deser_jev_format_confidence"],
            top["deser_jev_exploitability"], top["deser_jev_source"]) == \
        ("viewstate", 70, 90, "jev_classifier")
    assert "deser_jev_format" not in findings[-1]                   # unanswered keeps no annotation


def test_identical_blobs_are_asked_once_and_all_get_the_answer():
    findings = [_finding(0, endpoint_url=f"http://e{i}.example.test/") for i in range(30)]
    data = {}
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = sa.run_serialized_assess_pass(findings, user_id="u", project_id="p", recon_data=data)
    assert sum(len(c["blobs"]) for c in calls) == 1
    assert stats["assessed"] == 30
    assert len(data["jev_shadow"]["serialized_assess"]["records"]) == 30


def test_batches_are_bounded():
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        sa.run_serialized_assess_pass([_finding(i) for i in range(10)], user_id="u", project_id="p")
    assert [len(c["blobs"]) for c in calls] == [4, 4, 2]


def test_the_per_scan_cap_bounds_the_blobs_asked(monkeypatch, capsys):
    monkeypatch.setattr(sa, "MAX_BLOBS_PER_SCAN", 5)
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = sa.run_serialized_assess_pass([_finding(i) for i in range(12)], user_id="u", project_id="p")
    assert sum(len(c["blobs"]) for c in calls) == 5
    assert stats["not_asked"] == 7
    assert "7 candidates not asked (cap 5 distinct blobs per scan" in capsys.readouterr().out


def test_the_shipped_bounds():
    assert sa.MAX_BLOBS_PER_SCAN == 200 and sa.TIME_BUDGET_S == 60
    # Each blob is its own TypeSafe request (up to 5 s): a batch must fit the timeout.
    assert sa.BATCH_SIZE * 5 <= sa.TIMEOUT


def test_the_time_budget_stops_the_pass(capsys):
    ticks = iter([0, 0, 61, 61, 61])
    calls, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = sa.run_serialized_assess_pass([_finding(i) for i in range(12)], user_id="u",
                                              project_id="p", clock=lambda: next(ticks))
    assert len(calls) == 1
    assert stats["not_asked"] == 8
    assert "Time budget of 60s reached" in capsys.readouterr().out


def test_a_failed_batch_falls_back_and_is_never_re_asked():
    data = {}
    calls, post = _echo_post(status=503)
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = sa.run_serialized_assess_pass([_finding(i) for i in range(20)], user_id="u",
                                              project_id="p", recon_data=data)
    # One call per batch, never per candidate; after three failures in a row the
    # Jev breaker pauses and the remaining batches fall back without a request.
    assert len(calls) == 3
    assert stats["failed_batches"] == 5 and stats["assessed"] == 0
    assert data["jev_shadow"]["serialized_assess"]["summary"]["fallbacks"] == 5


@pytest.mark.parametrize("bad", [
    {"labels": []},                                                         # wrong length
    {"labels": [{"format": "pickle_rick", "format_confidence": 90, "exploitability": 9}]},
    {"labels": [{"format": "native_java", "format_confidence": 101, "exploitability": 9}]},
    {"labels": [{"format": "native_java", "format_confidence": 90, "exploitability": -1}]},
    {"labels": [{"format": "native_java", "format_confidence": True, "exploitability": 9}]},
    {"labels": [{"format": "native_java", "format_confidence": 90.5, "exploitability": 9}]},
    {"labels": [{"format": ["native_java"], "format_confidence": 90, "exploitability": 9}]},
    {"labels": "native_java"}, [], None,
])
def test_a_malformed_answer_is_a_fallback(bad):
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, bad)):
        stats = sa.run_serialized_assess_pass([_finding()], user_id="u", project_id="p")
    assert stats["assessed"] == 0 and stats["failed_batches"] == 1


def test_an_unexpected_error_never_escapes_the_pass(capsys):
    findings = [_finding()]
    with mock.patch.object(sa, "jev_post", side_effect=KeyError("boom")):
        sa.run_serialized_assess_pass(findings, user_id="u", project_id="p")
    assert findings == [_finding()]
    assert "Pass failed (KeyError) - candidates left as flagged." in capsys.readouterr().out


def test_the_printed_baseline_is_clamped_to_the_closed_set(capsys):
    """deser_format reaches stdout on the shadow line; anything outside the closed set
    prints as "unknown", so no string can move the drawer."""
    _, post = _echo_post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        sa.run_serialized_assess_pass([_finding(deser_format="port 22 scan")], user_id="u", project_id="p")
    out = capsys.readouterr().out
    assert "baseline=unknown" in out and not _DRAWER.search(out)


# ---------------------------------------------------------------------------
# Gate and call site
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ai,flag,on", [(True, True, True), (True, False, False), (False, True, False)])
def test_the_hook_needs_both_switches(ai, flag, on):
    assert sa.jev_serialized_rank_enabled({"AI_IN_PIPELINE": ai, "SERIALIZED_SCAN_JEV_RANK": flag}) is on


def test_run_for_scan_does_nothing_when_off_or_with_no_candidates():
    on = {"AI_IN_PIPELINE": True, "SERIALIZED_SCAN_JEV_RANK": True}
    with mock.patch.object(sa, "run_serialized_assess_pass") as run:
        sa.run_for_scan([_finding()], {"AI_IN_PIPELINE": True}, {})
        sa.run_for_scan([], on, {})
    run.assert_not_called()


def test_run_for_scan_reads_the_owner_from_the_environment(monkeypatch):
    monkeypatch.setenv("USER_ID", "owner-1")
    monkeypatch.setenv("PROJECT_ID", "proj-1")
    with mock.patch.object(sa, "run_serialized_assess_pass") as run:
        sa.run_for_scan([_finding()], {"AI_IN_PIPELINE": True, "SERIALIZED_SCAN_JEV_RANK": True}, {})
    assert run.call_args.kwargs["user_id"] == "owner-1"
    assert run.call_args.kwargs["project_id"] == "proj-1"


def test_run_for_scan_never_raises():
    with mock.patch.object(sa, "run_serialized_assess_pass", side_effect=RuntimeError("x")):
        sa.run_for_scan([_finding()], {"AI_IN_PIPELINE": True, "SERIALIZED_SCAN_JEV_RANK": True}, {})


def test_the_hook_runs_in_the_shared_entry_before_the_result_is_built():
    source = (REPO / "recon/serialized_scan/scanner.py").read_text()
    entry = source.index("def run_serialized_scan(")
    call = source.index("serialized_assess.run_for_scan(findings, settings, combined_result)")
    build = source.index('combined_result["serialized_scan"] = normalizers.build_result(findings)')
    assert entry < call < build


def test_partial_recon_reaches_the_hook_through_the_same_entry():
    source = (REPO / "recon/partial_recon_modules/serialized_scanning.py").read_text()
    assert "run_serialized_scan(recon_data, settings)" in source


def test_end_to_end_through_the_scanner_in_shadow(monkeypatch):
    """A real scan of a Java Set-Cookie: the hook asks Jev, records the decision in the
    recon output, and leaves the candidate exactly as the signatures produced it."""
    from recon.serialized_scan.scanner import run_serialized_scan
    monkeypatch.setenv("USER_ID", "owner-1")
    monkeypatch.setenv("PROJECT_ID", "proj-1")
    corpus = {"http_probe": {"by_url": {"https://t.example.test/": {
        "headers": "Set-Cookie: sess=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; Path=/\nServer: nginx"}}}}
    settings = {"SERIALIZED_SCAN_ENABLED": True, "AI_IN_PIPELINE": True, "SERIALIZED_SCAN_JEV_RANK": True}
    calls, post = _echo_post(label=("native_java", 88, 77))
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        run_serialized_scan(corpus, settings)
    findings = corpus["serialized_scan"]["findings"]
    assert findings and all(f["deser_format"] == "native_java" for f in findings)
    assert all("deser_jev_format" not in f for f in findings)        # shadow writes nothing
    assert calls and calls[0]["user_id"] == "owner-1"
    shadow = corpus["jev_shadow"]["serialized_assess"]
    assert shadow["summary"]["decisions"] == len(findings)
    assert all(r["jev"] == "native_java" and r["agreed"] for r in shadow["records"])


def test_end_to_end_with_the_hook_off_never_calls_the_agent():
    from recon.serialized_scan.scanner import run_serialized_scan
    corpus = {"http_probe": {"by_url": {"https://t.example.test/": {
        "headers": "Set-Cookie: sess=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; Path=/"}}}}
    with mock.patch.object(jev_shadow.requests, "post") as post:
        run_serialized_scan(corpus, {"SERIALIZED_SCAN_ENABLED": True, "AI_IN_PIPELINE": True})
    post.assert_not_called()
    assert corpus["serialized_scan"]["findings"] and "jev_shadow" not in corpus
