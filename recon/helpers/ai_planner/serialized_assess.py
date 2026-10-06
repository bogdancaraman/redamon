"""
Serialized-object assessment on TypeSafe Jev
============================================
The serialized-object scan flags blobs by deterministic signatures (magic bytes
and text markers). This hook asks Jev two typed questions about each distinct
flagged blob: which serialization format it is (a choice over a closed set,
with a confidence), and how likely it is to be an attacker-reachable
deserialization sink (a noul). The format answer annotates; the reachability
answer ranks the candidates for the agent's confirmation.

It only annotates and ranks. It never drops a candidate and never rewrites the
format the signatures matched: `deser_format` is part of the candidate's graph
id (`_vuln_id`), so changing it would split one sink into two nodes across runs.
Jev's answer lands in separate `deser_jev_*` fields instead.

Candidates whose Jev-visible fields are identical (snippet, magic, transport,
location, encoding layers) collapse to one question set, so a session cookie that
rides on every endpoint is asked about once; a failed batch is remembered too, so
a failure never re-asks per candidate. Distinct blobs are bounded per scan
(MAX_BLOBS_PER_SCAN) and the whole pass by a wall-clock budget.

Kind B (no LLM twin), gated by AI_IN_PIPELINE and SERIALIZED_SCAN_JEV_RANK at the
call site. ROLLOUT is SHADOW: Jev is asked every run and each decision is
recorded next to the deterministic format (recon JSON
`jev_shadow.serialized_assess`), while the candidates stay exactly as the
signatures produced them. ACT adds the `deser_jev_*` annotations and orders the
candidates by reachability; persisting those annotations to the graph lands with
the ACT flip, which is a separate change made after reviewing the agreement data.

Log lines carry counts and indexes only. The recon drawer moves to whichever
phase a stdout line names (`port.*scan` among them), and `transport` contains
"port", so neither a transport nor any target string ever reaches stdout.
"""

import hashlib
import os
import time
from typing import Dict, List, Optional, Tuple

from recon.helpers.ai_planner.jev_shadow import ACT, SHADOW, ShadowRecorder, jev_model, jev_post

ROLLOUT = SHADOW

HOOK = "serialized_assess"
_TAG = "Serialized-Jev"

#: The detector's deser_format vocabulary, and the agent's closed choice set
#: (jev_hooks.SERIALIZED_FORMATS). "none" is Jev saying the blob is not a
#: serialized object at all; it can lower a rank, never remove a candidate.
FORMATS = (
    "native_java", "jackson_json", "fastjson", "xmldecoder", "xstream", "snakeyaml",
    "hessian", "php_serialize", "phar", "python_pickle", "dotnet_binaryformatter",
    "viewstate", "ruby_marshal",
)
LABELS = frozenset(FORMATS + ("none",))

#: Literals, not frozensets: the agent's contract test reads them from this file
#: and holds them equal to its request model's closed sets.
TRANSPORTS = ("cookie", "header", "param", "body")
LAYERS = ("url", "base64", "gzip", "zlib", "hex", "truncated")

#: Distinct blobs asked about per scan; past this the rest get no assessment.
MAX_BLOBS_PER_SCAN = 200
#: Blobs per agent call. The agent asks about each blob in its own TypeSafe
#: request, so 4 stay inside TIMEOUT even when slow, and the time budget,
#: checked between calls, is overrun by at most one call.
BATCH_SIZE = 4
#: Wall-clock budget for the whole pass. It runs before the candidates are handed
#: to the graph writer, so it must never stall the pipeline.
TIME_BUDGET_S = 60
TIMEOUT = 30

SNIPPET_CHARS = 200
_MAGIC_CHARS = 64
_LOCATION_CHARS = 200
_MAX_LAYERS = 8


def _blob(finding: dict) -> dict:
    """The agent request item for one candidate: bounded, every field typed.

    The deterministic format is deliberately absent: Jev answers from the blob,
    so the agreement it records is independent of the signature's verdict.
    """
    transport = str(finding.get("deser_transport") or "")
    layers = finding.get("deser_encoding_layers")
    return {
        "snippet": str(finding.get("evidence_snippet") or "")[:SNIPPET_CHARS],
        "magic": str(finding.get("deser_magic") or "")[:_MAGIC_CHARS],
        "transport": transport if transport in TRANSPORTS else "",
        "location": str(finding.get("deser_location") or "")[:_LOCATION_CHARS],
        "encoding_layers": [str(x) for x in (layers if isinstance(layers, list) else [])
                            if str(x) in LAYERS][:_MAX_LAYERS],
    }


def cache_key(finding: dict) -> str:
    """Exactly the fields Jev sees, so two candidates that share them share the answer."""
    blob = _blob(finding)
    parts = [blob["snippet"], blob["magic"], blob["transport"], blob["location"],
             ",".join(blob["encoding_layers"])]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def _assessable(finding: dict) -> bool:
    """A candidate with neither a snippet nor a magic marker gives Jev nothing to read."""
    return bool(finding.get("evidence_snippet") or finding.get("deser_magic"))


def _pct(value) -> Optional[int]:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
        return None
    return value


def _validate(data, n: int) -> Optional[List[Tuple[str, int, int]]]:
    if not isinstance(data, dict) or not isinstance(data.get("labels"), list) or len(data["labels"]) != n:
        return None
    out = []
    for label in data["labels"]:
        if not isinstance(label, dict):
            return None
        fmt = label.get("format")
        if not isinstance(fmt, str) or fmt not in LABELS:
            return None
        conf, reach = _pct(label.get("format_confidence")), _pct(label.get("exploitability"))
        if conf is None or reach is None:
            return None
        out.append((fmt, conf, reach))
    return out


def jev_serialized_rank_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get('AI_IN_PIPELINE') and settings.get('SERIALIZED_SCAN_JEV_RANK'))


def run_serialized_assess_pass(findings: List[dict], *, user_id: str, project_id: str,
                               recon_data: Optional[dict] = None, clock=time.monotonic) -> dict:
    """Assess the flagged candidates. Never raises. Returns a count summary.

    `findings` is the scan's candidate list, mutated in place in ACT only: each
    answered candidate gets `deser_jev_format`, `deser_jev_format_confidence`,
    `deser_jev_exploitability` and `deser_jev_source`, and the list is re-ordered
    by reachability (answered first, the rest after in their original order). In
    SHADOW nothing on the candidates or their order changes.
    """
    recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
    stats = {"candidates": 0, "asked": 0, "assessed": 0, "not_asked": 0,
             "skipped_no_signal": 0, "failed_batches": 0}
    try:
        groups: Dict[str, List[int]] = {}
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict) or not _assessable(finding):
                stats["skipped_no_signal"] += 1
                continue
            stats["candidates"] += 1
            groups.setdefault(cache_key(finding), []).append(i)

        keys = list(groups)
        if len(keys) > MAX_BLOBS_PER_SCAN:
            stats["not_asked"] = sum(len(groups[k]) for k in keys[MAX_BLOBS_PER_SCAN:])
            keys = keys[:MAX_BLOBS_PER_SCAN]
        print(f"[*][{_TAG}] {stats['candidates']} candidates, {len(keys)} distinct blobs to ask")

        answers: Dict[str, Tuple[str, int, int]] = {}
        started = clock()
        for start in range(0, len(keys), BATCH_SIZE):
            if clock() - started > TIME_BUDGET_S:
                left = keys[start:]
                stats["not_asked"] += sum(len(groups[k]) for k in left)
                print(f"[!][{_TAG}] Time budget of {TIME_BUDGET_S}s reached - "
                      f"{len(left)} distinct blobs left unassessed")
                break
            batch = keys[start:start + BATCH_SIZE]
            blobs = [_blob(findings[groups[k][0]]) for k in batch]
            data = jev_post("serialized-classify",
                            {"blobs": blobs, "user_id": user_id, "project_id": project_id},
                            _TAG, TIMEOUT)
            labels = _validate(data, len(batch)) if data is not None else None
            if labels is None:
                if data is not None:
                    print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
                stats["failed_batches"] += 1
                recorder.fallback()
                continue
            recorder.model = jev_model(data)
            stats["asked"] += len(batch)
            for k, label in zip(batch, labels):
                answers[k] = label

        if stats["not_asked"]:
            print(f"[!][{_TAG}] {stats['not_asked']} candidates not asked (cap {MAX_BLOBS_PER_SCAN} "
                  f"distinct blobs per scan, or the time budget)")

        for k in keys:
            if k not in answers:
                continue
            fmt, conf, reach = answers[k]
            for i in groups[k]:
                finding = findings[i]
                stats["assessed"] += 1
                # The baseline is printed on the shadow line; clamp it to the closed set.
                baseline = finding.get("deser_format")
                baseline = baseline if baseline in LABELS else "unknown"
                recorder.decision(f"blob_{i}", fmt, conf, baseline,
                                  exploitability=reach,
                                  transport=finding.get("deser_transport"),
                                  location=finding.get("deser_location"),
                                  endpoint=finding.get("endpoint_url"))
                if ROLLOUT != SHADOW:
                    finding["deser_jev_format"] = fmt
                    finding["deser_jev_format_confidence"] = conf
                    finding["deser_jev_exploitability"] = reach
                    finding["deser_jev_source"] = "jev_classifier"
        if ROLLOUT == ACT:
            _rank_in_place(findings)
        print(f"[+][{_TAG}] {stats['assessed']} candidates assessed, {stats['failed_batches']} "
              f"batches fell back")
    except Exception as e:  # noqa: BLE001 - an assessment is never worth losing a candidate
        print(f"[!][{_TAG}] Pass failed ({type(e).__name__}) - candidates left as flagged.")
        recorder.fallback()
    finally:
        recorder.finish(recon_data)
    return stats


def _rank_in_place(findings: List[dict]) -> None:
    """Answered candidates first by reachability, the rest after in their original
    order. Re-orders only; never drops. Never raises."""
    try:
        findings.sort(key=lambda f: (0, -f["deser_jev_exploitability"])
                      if isinstance(f, dict) and isinstance(f.get("deser_jev_exploitability"), int)
                      else (1, 0))
    except Exception:  # noqa: BLE001 - an order is never worth breaking the scan
        pass


def run_for_scan(findings: List[dict], settings: dict, recon_data: Optional[dict]) -> None:
    """The call-site entry: gate, then the pass. Never raises."""
    try:
        if not findings or not jev_serialized_rank_enabled(settings):
            return
        run_serialized_assess_pass(findings,
                                   user_id=os.environ.get('USER_ID', ''),
                                   project_id=os.environ.get('PROJECT_ID', ''),
                                   recon_data=recon_data)
    except Exception as e:  # noqa: BLE001
        print(f"[!][{_TAG}] Skipped ({type(e).__name__}).")
