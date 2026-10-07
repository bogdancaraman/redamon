"""End-to-end case test: the serialized-object scan and its Jev ranking, run through MCP.

Against this lab (172.25.0.92), driven the way an external agent would drive it:

    python3 validate_jev_e2e.py setup               # create the project, toggle Jev, start recon
    python3 validate_jev_e2e.py verify <projectId>  # after the recon has finished

setup proves the MCP surface: describe_recon_settings lists serializedScanJevRank as a
settable field and its notes explain the Jev-only ranking; a fresh project stores it
false; update_recon_settings turns it on and off, and preflight_scope_check follows
(serialized_assess: off -> jev -> off); then it is switched on and the recon starts.
It needs a Jev token on the MCP token owner's account: without one, switching the
flag on is refused and setup fails at that check.

verify proves the run: every family in expected_results.yaml's
live_in_memory_formats is a serialized_scan candidate in the graph (the other
required families ride only in a deeper endpoint's response header or Set-Cookie,
outside the in-memory corpus: they are reported as a known gap, and finding one
fails until that list is updated); no sink is flagged twice for one format (base64
Java matches as rO0AB text and as decoded AC ED 00 05 bytes, and must stay one
candidate); the recon output records Jev's assessment under
jev_shadow.serialized_assess (rollout act, model jev-1.13.0, at least one decision,
no fallback, every answer from the closed set); every candidate in the graph carries
Jev's deser_jev_* annotation; and the deserialization skill's own candidate query
returns them most reachable first. Jev's agreement with the signatures is printed,
not asserted: Jev's format is a second opinion, not a test oracle.

Exit 0 only when every assertion holds. The MCP token is read from the repo .env and
never printed.
"""
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mcp_client as mcp  # noqa: E402

TARGET = "172.25.0.92"
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PROMPT = os.path.join(REPO, "agentic", "prompts", "deserialization_prompts.py")
CLOSED_SET = {"native_java", "jackson_json", "fastjson", "xmldecoder", "xstream", "snakeyaml",
              "hessian", "php_serialize", "phar", "python_pickle", "dotnet_binaryformatter",
              "viewstate", "ruby_marshal", "none"}

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def find_key(obj, key):
    """The first value stored under `key` anywhere in a nested JSON value."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            hit = find_key(v, key)
            if hit is not None:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = find_key(v, key)
            if hit is not None:
                return hit
    return None


def expected_list(key):
    """One top-level list of expected_results.yaml, without a YAML dependency."""
    out, inside = [], False
    with open(os.path.join(HERE, "expected_results.yaml")) as fh:
        for line in fh:
            if line.startswith(f"{key}:"):
                inside = True
                continue
            if inside:
                if line.startswith("  - "):
                    out.append(line[4:].split("#")[0].strip())
                elif line.strip() and not line.startswith((" ", "#")):
                    break
    return out


def hook_effective(pid):
    out, _ = mcp.call("preflight_scope_check", {"projectId": pid})
    hooks = find_key(out, "aiHooks") or []
    return next((h.get("effective") for h in hooks if h.get("hook") == "serialized_assess"), None)


def stored_flag(pid):
    out, _ = mcp.call("get_recon_settings", {"projectId": pid})
    return find_key(out, "serializedScanJevRank")


def report():
    width = max(len(n) for n, _, _ in results) if results else 0
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    sys.exit(0 if results and passed == len(results) else 1)


def setup():
    mcp.init()
    catalog, err = mcp.call("describe_recon_settings", {})
    text = json.dumps(catalog)
    check("describe_recon_settings lists serializedScanJevRank", not err and '"serializedScanJevRank"' in text)
    notes = json.dumps(find_key(catalog, "notes") or [])
    check("its notes explain the Jev-only ranking",
          "serializedScanJevRank" in notes and "deser_jev_exploitability" in notes)

    created, err = mcp.call("create_project", {
        "name": "serialized-jev-e2e (temp)",
        "description": "E2E: serialized-object scan + Jev ranking against the serialized_target lab",
        "engagementKind": "internal",
        "targetIps": [TARGET],
        "settings": {
            "serializedScanEnabled": True,
            "aiInPipeline": True,
            # The serialized scan runs in GROUP 5b: nothing after JS recon is needed,
            # CVE/MITRE enrichment loads whole CVE year files into memory, and Nmap's
            # NSE vuln scripts take minutes while HTTP probing only needs the open port.
            "scanModules": ["port_scan", "http_probe", "resource_enum", "js_recon"],
            "cveLookupEnabled": False,
            "mitreEnabled": False,
            "nmapEnabled": False,
        },
        "idempotencyKey": f"serialized-jev-e2e-{int(time.time())}",
    })
    pid = find_key(created, "id") or find_key(created, "projectId")
    check("create_project (internal, IP mode) via MCP", not err and isinstance(pid, str), f"projectId={pid}")
    if not pid:
        report()

    check("a fresh project stores serializedScanJevRank false", stored_flag(pid) is False)
    check("preflight reports serialized_assess off", hook_effective(pid) == "off")

    _, err = mcp.call("update_recon_settings", {"projectId": pid, "settings": {"serializedScanJevRank": True}})
    check("update_recon_settings turns it on (owner has a Jev token)", not err)
    check("get_recon_settings reads it back true", stored_flag(pid) is True)
    check("preflight reports serialized_assess on Jev", hook_effective(pid) == "jev")

    _, err = mcp.call("update_recon_settings", {"projectId": pid, "settings": {"serializedScanJevRank": False}})
    check("update_recon_settings turns it off", not err and stored_flag(pid) is False)
    check("preflight follows it back to off", hook_effective(pid) == "off")

    _, err = mcp.call("update_recon_settings", {"projectId": pid, "settings": {"serializedScanJevRank": True}})
    check("switched on again for the run", not err and hook_effective(pid) == "jev")

    started, err = mcp.call("start_recon", {"projectId": pid})
    check("start_recon via MCP", not err, json.dumps(started)[:120])
    print(f"\nprojectId: {pid}\nWhen the recon finishes:  python3 validate_jev_e2e.py verify {pid}\n")
    report()


def verify(pid):
    mcp.init()
    status, _ = mcp.call("get_recon_status", {"projectId": pid})
    state = find_key(status, "status")
    check("the recon finished", str(state).lower() in ("completed", "complete", "done", "finished", "success"),
          f"status={state}")

    rows_out, err = mcp.call("query_graph", {"projectId": pid, "cypher": (
        "MATCH (v:Vulnerability) WHERE v.source = 'serialized_scan' "
        "RETURN v.deser_format AS fmt, count(*) AS n, "
        "sum(CASE WHEN v.deser_jev_format IS NOT NULL THEN 1 ELSE 0 END) AS annotated")})
    rows = find_key(rows_out, "records") or []
    found = {r.get("fmt"): r for r in rows if isinstance(r, dict)}
    live = expected_list("live_in_memory_formats")
    for fmt in live:
        check(f"candidate for {fmt}", fmt in found, f"n={found.get(fmt, {}).get('n', 0)}")
    # The rest ride only in a deeper endpoint's response header or Set-Cookie, which
    # the in-memory corpus never holds. Reported, not counted; finding one anyway
    # means the corpus grew, so it fails until the live list is updated.
    gaps = [fmt for fmt in expected_list("required_formats") if fmt not in live]
    for fmt in gaps:
        if fmt in found:
            check(f"UNEXPECTED candidate for {fmt}: move it to live_in_memory_formats", False,
                  f"n={found[fmt].get('n')}")
    known_gap = [fmt for fmt in gaps if fmt not in found]
    check("every candidate carries Jev's deser_jev_* annotation",
          not err and rows and all(r.get("annotated") == r.get("n") for r in rows),
          ", ".join(f"{r.get('fmt')} {r.get('annotated')}/{r.get('n')}" for r in rows))

    # The deserialization skill's own step-1 order, read from its prompt so the two
    # cannot drift: most reachable first, a "none" answer and an unranked one last.
    order = re.search(r"ORDER BY (CASE v\.deser_jev_format .*? END DESC, v\.id)",
                      open(PROMPT).read()).group(1)
    ranked_out, ranked_err = mcp.call("query_graph", {"projectId": pid, "cypher": (
        "MATCH (v:Vulnerability {source:'serialized_scan'}) WHERE v.needs_agent_confirmation = true "
        "AND NOT (:ChainFinding)-[:CONFIRMS]->(v) RETURN v.deser_jev_format AS jev_fmt, "
        f"v.deser_jev_exploitability AS jev_reach ORDER BY {order}")})
    ranked = find_key(ranked_out, "records") or []
    keys = [-1 if r.get("jev_fmt") == "none" else (r.get("jev_reach") if r.get("jev_reach") is not None else -1)
            for r in ranked]
    check("the agent reads the candidates most reachable first",
          not ranked_err and ranked and keys == sorted(keys, reverse=True), f"reach order {keys}")

    twins_out, twins_err = mcp.call("query_graph", {"projectId": pid, "cypher": (
        "MATCH (v:Vulnerability) WHERE v.source = 'serialized_scan' "
        "WITH v.matched_at AS at, v.deser_transport AS t, v.deser_location AS loc, "
        "v.deser_format AS fmt, count(*) AS n WHERE n > 1 RETURN at, t, loc, fmt, n")})
    twins = find_key(twins_out, "records") or []
    check("one candidate per sink and format", not twins_err and not twins,
          f"{len(twins)} sink(s) flagged more than once")

    path = os.path.join(REPO, "recon", "output", f"recon_{pid}.json")
    try:
        with open(path) as fh:
            shadow = (json.load(fh).get("jev_shadow") or {}).get("serialized_assess")
    except (OSError, ValueError) as e:
        shadow = None
        check("recon output readable", False, type(e).__name__)
    check("recon output has jev_shadow.serialized_assess", isinstance(shadow, dict))
    if isinstance(shadow, dict):
        summary = shadow.get("summary") or {}
        records = shadow.get("records") or []
        check("rollout is act", shadow.get("rollout") == "act")
        check("answered by the pinned model", shadow.get("model") == "jev-1.13.0", f"model={shadow.get('model')}")
        check("Jev made at least one decision", summary.get("decisions", 0) > 0, f"decisions={summary.get('decisions')}")
        check("no call fell back", summary.get("fallbacks") == 0, f"fallbacks={summary.get('fallbacks')}")
        check("every answer is from the closed set", all(r.get("jev") in CLOSED_SET for r in records))
        print(f"\nJev vs signatures: agreed {summary.get('agreed_pct')}%, mean confidence "
              f"{summary.get('mean_conf')}, {summary.get('decisions')} decisions")
        per = {}
        for r in records:
            per.setdefault(r.get("baseline"), []).append(r)
        for fmt in sorted(per, key=str):
            rs = per[fmt]
            answers = sorted({r.get("jev") for r in rs}, key=str)
            reach = round(sum(r.get("exploitability", 0) for r in rs) / len(rs))
            print(f"  {str(fmt).ljust(24)} jev={','.join(map(str, answers)).ljust(28)} "
                  f"reach~{reach}  ({len(rs)} candidate(s))")
        print()
    if known_gap:
        print(f"KNOWN GAP (not counted): {len(known_gap)} families ride only in a deeper "
              f"endpoint's response header or Set-Cookie, outside the in-memory corpus: "
              f"{', '.join(known_gap)}\n")
    report()


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "setup":
        setup()
    elif len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify(sys.argv[2])
    else:
        sys.exit("usage: validate_jev_e2e.py setup | verify <projectId>")
