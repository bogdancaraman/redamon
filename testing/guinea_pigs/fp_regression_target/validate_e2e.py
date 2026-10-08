"""End-to-end assertions for the false-positive lab, run entirely over MCP.

Run after e2e_fp.py:   python3 validate_e2e.py <projectId>

Every check is read-only Cypher through query_graph (tenant-scoped by the
server) and prints PASS / FAIL with what the graph actually holds. Exit 0 only
when every assertion holds. Case ids match README.md.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fix_regression_target"))
import mcp_client as mcp  # noqa: E402

if len(sys.argv) != 2:
    sys.exit("usage: validate_e2e.py <projectId>")
P = sys.argv[1]
NET = "192.88.94"
APEX = "fplab.test"
results = []


def q(cypher):
    out, err = mcp.call("query_graph", {"projectId": P, "cypher": cypher})
    if err or not isinstance(out, dict):
        raise RuntimeError(f"query failed: {json.dumps(out)[:500]}")
    return out.get("records", [])


def check(case, ok, detail):
    results.append((case, bool(ok), detail))


# --------------------------------------------------------------------------- VHost
def vhosts(ip):
    rows = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip = '{ip}'
                 RETURN v.hostname AS h, v.layer AS layer, v.severity AS sev ORDER BY h, layer""")
    return sorted((r["h"], r["layer"]) for r in rows), rows


got, _ = vhosts(f"{NET}.10")
check("V-01/V-02/V-03", got == [(f"admin.{APEX}", "L7"), (f"wiki.{APEX}", "L7")],
      f"Fastly-like edge: {got} (expect admin + wiki, L7, nothing from the 19 catch-all names)")
got, _ = vhosts(f"{NET}.11")
check("V-04/V-05", got == [(f"admin.{APEX}", "L4")], f"Cloudflare-like edge: {got} (expect the SNI-routed admin only)")
got, _ = vhosts(f"{NET}.12")
check("V-07", got == [], f"provider redirect: {got}")
got, _ = vhosts(f"{NET}.13")
check("V-08", got == [], f"Akamai-style deny page: {got}")
got, _ = vhosts(f"{NET}.14")
check("V-09/V-10", got == [(f"admin.{APEX}", "L7")],
      f"rate-limited edge: {got} (expect admin kept despite its 429 on the second probe, no 429 names)")
got = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.ip IN ['{NET}.15', '{NET}.20']
            RETURN v.ip AS ip, v.hostname AS h""")
check("V-catch-all", got == [], f"catch-all app hosts (cache, SPA): {got}")
got = q("""MATCH (v:Vulnerability) WHERE v.source = 'vhost_sni_enum' AND v.severity = 'high'
           RETURN v.ip AS ip, v.hostname AS h""")
check("V-06", got == [], f"vhost findings rated high: {got}")
got = q(f"""MATCH (i:IP) WHERE i.address IN ['{NET}.10', '{NET}.13']
            RETURN i.address AS ip, i.vhost_sni_suppressed_by_control AS supp""")
check("V-controls", all((r.get("supp") or 0) >= 15 for r in got) and len(got) == 2,
      f"control-suppressed names per edge: {got}")


# --------------------------------------------------------------------------- JS: DOM sinks
def sinks(file_name):
    rows = q(f"""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dom_sink' AND f.source_url ENDS WITH '/{file_name}'
                 RETURN f.title AS t, f.severity AS sev, f.confidence AS conf, f.user_source AS src,
                        f.vendor AS vendor, f.third_party AS tp, f.evidence AS ev, f.id AS id
                 ORDER BY t, sev""")
    return sorted((r["t"], r["sev"]) for r in rows), rows


got, rows = sinks("main.4f2a9c.js")
check("J-01/J-02/J-03/J-05/J-06",
      got == [("innerHTML", "high"), ("innerHTML", "low"), ("location.href", "low")],
      f"main bundle sinks: {got} (expect the hash->innerHTML bug high, the sourceless sink and the "
      f"navigation write low, no Function/eval/__proto__ from the shim or the guards)")
high = [r for r in rows if r["sev"] == "high"]
check("X-04", high and "location.hash" in (high[0].get("ev") or "") and "!function" not in (high[0].get("ev") or ""),
      f"evidence of the real bug: {(high[0].get('ev') if high else None)!r:.160}")
got, _ = sinks("msg.7c8d.js")
check("J-04", got == [("eval", "critical")], f"minified message handler: {got}")
got, _ = sinks("proto.6a7b.js")
check("J-07", got == [("__proto__", "low")], f"prototype writes: {got} (expect the write through __proto__, not the shim)")
got, rows = sinks("vendor.3c1d.js")
check("J-08", got == [("innerHTML", "info")] and all(r.get("vendor") for r in rows), f"vendor bundle: {got}")
got, _ = sinks("jquery.prettyPhoto.js")
check("J-10", got == [("innerHTML", "high")], f"hash-reading plugin: {got}")
got, rows = sinks("loader.js")
if rows:
    check("J-09", all(r["sev"] == "info" and r.get("tp") for r in rows), f"third-party loader: {got}")
else:
    check("J-09 (not crawled)", True, "the third-party loader was not collected by the crawl; nothing to judge")


# --------------------------------------------------------------------------- JS: source maps
def maps():
    rows = q("""MATCH (f:JsReconFinding) WHERE f.finding_type IN ['source_map_exposure', 'source_map_reference']
                RETURN f.source_url AS js, f.finding_type AS t, f.severity AS sev, f.map_url AS map,
                       f.fetch_result AS fr, f.first_party_files AS fp, f.has_sources_content AS sc""")
    return {r["js"].rsplit("/", 1)[-1]: r for r in rows}


m = maps()
r = m.get("main.4f2a9c.js")
check("M-01", r and r["t"] == "source_map_exposure" and r["sev"] == "high" and r["fp"] == 2
      and (r["map"] or "").endswith("main.4f2a9c.js.map"), f"served map with own source: {r}")
r = m.get("lib.8e1f.js")
check("M-02", r and r["t"] == "source_map_exposure" and r["sev"] == "low" and r["fp"] == 0, f"library-only map: {r}")
check("M-03", "shell.2b7a.js" not in m, f"map answered by the SPA shell: {m.get('shell.2b7a.js')}")
r = m.get("private.9c3d.js")
check("M-04", r and r["t"] == "source_map_reference" and r["sev"] == "info" and r["fr"] == "http_403",
      f"map behind a 403: {r}")
r = m.get("buildref.7a8b.js")
check("M-05", r and r["t"] == "source_map_reference" and r["fr"] in ("unreachable", "unsafe")
      and f"{NET}.99" in (r["map"] or ""), f"map on another unreachable host: {r}")
r = m.get("inline.5e6f.js")
check("M-06", r and r["t"] == "source_map_exposure" and (r["map"] or "").startswith("data:application/json;base64,…")
      and len(r["map"] or "") < 300, f"inline map stored as a label: {r}")


# --------------------------------------------------------------------------- JS: secrets
secrets = q("""MATCH (s:Secret) WHERE s.source = 'js_recon'
               RETURN s.secret_type AS t, s.matched_text AS mt, s.sample AS sample""")
types_ = sorted(r["t"] for r in secrets)
blob = json.dumps(secrets)
noise = [w for w in ("Forgot your", "auth.form", "#password-input", "/account/reset-password",
                     "Keep this secret", "localhost", "devapi", "debug") if w in blob]
check("K-01", not noise, f"UI text / dev literals stored as secrets: {noise}")
check("K-04/K-05", "AWS Access Key ID" in types_ and "Generic API Key" in types_
      and sum(1 for t in types_ if t in ("Generic Secret", "Hardcoded Password")) >= 2,
      f"Secret types: {types_} (expect the AWS key, the API key, 'Summer 2024!' and '$ecureP4ss2024')")
refs = q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'dev_reference'
            RETURN f.title AS t, f.evidence AS ev, f.severity AS sev ORDER BY t""")
got = sorted((r["t"], r["sev"]) for r in refs)
check("K-02", got == [("Debug Flag", "info"), ("Internal/Staging URL", "info"), ("Localhost with Port", "info")]
      and any("devapi.fplab.test" in (r["ev"] or "") for r in refs), f"developer references: {refs}")
check("K-03", "developer.vendor.test" not in json.dumps(refs) + blob, "documentation host not reported")
ext = sorted(r["d"] for r in q("""MATCH (f:JsReconFinding) WHERE f.finding_type = 'external_domain'
                                   RETURN f.title AS d"""))
own = {f"{NET}.{n}" for n in (10, 11, 12, 13, 14, 15, 20)}
check("X-05", f"{NET}.99" in ext and not own.intersection(ext),
      f"external domains: {ext} (expect the unreachable map host, never a scanned target IP)")


# --------------------------------------------------------------------------- Shodan
shodan = q(f"""MATCH (i:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)
               WHERE v.source IN ['shodan_api', 'internetdb', 'shodan'] AND i.address STARTS WITH '{NET}.'
               RETURN i.address AS ip, v.name AS cve, v.source AS src, v.detection_method AS dm,
                      v.severity AS sev, v.target_port AS port, v.product AS product, v.verified AS verified""")
by = {(r["ip"], r["cve"]): r for r in shodan}
api = any(r["src"] == "shodan_api" for r in shodan)
check("H-04", not [r for r in shodan if r["ip"] in (f"{NET}.11", f"{NET}.12")],
      f"CVE rows on the Vercel / cdn-tagged hosts: {[r for r in shodan if r['ip'] in (f'{NET}.11', f'{NET}.12')]}")
r = by.get((f"{NET}.10", "CVE-2021-23017"))
if api:
    check("H-01", r and r["dm"] == "passive_version_match" and r["sev"] == "high" and r["port"] == 80
          and r["product"] == "nginx", f"banner CVE: {r}")
    r2 = by.get((f"{NET}.13", "CVE-2014-0160"))
    check("H-02", r2 and r2["dm"] == "passive_verified" and r2["verified"] is True and r2["port"] == 443,
          f"verified banner CVE: {r2}")
else:
    check("H-01/H-02 (InternetDB path)", r and r["dm"] == "passive_catalog",
          f"no Shodan key configured, so only InternetDB answered: {r}")
r = by.get((f"{NET}.10", "CVE-2019-11043"))
check("H-03", r and r["dm"] == "passive_catalog" and not r.get("sev"), f"catalog-only CVE: {r}")


# --------------------------------------------------------------------------- Cache
cache = q(f"""MATCH (v:Vulnerability) WHERE v.source = 'cache_poisoning'
              RETURN coalesce(v.endpoint_url, v.url, v.matched_at) AS url, v.cache_impact AS impact,
                     v.confidence_tier AS tier""")
urls = json.dumps(cache)
check("C-02", "/promo" not in urls, f"A/B page reported as poisoned: {[c for c in cache if '/promo' in json.dumps(c)]}")
check("C-01", "/home" in urls, f"real unkeyed-header poisoning on /home: {cache}")


# --------------------------------------------------------------------------- Priority Board
# query_graph scopes every query to the tenant through a labelled node, so the
# two finding kinds are read separately rather than through one unlabelled MATCH.
tiers = q("""MATCH (n:JsReconFinding) WHERE n.finding_type IN ['dom_sink', 'dev_reference']
             RETURN 'JsReconFinding' AS label, n.finding_type AS kind, n.title AS name,
                    n.severity AS sev, n.triage_tier AS tier""")
tiers += q("""MATCH (n:Vulnerability) WHERE n.source IN ['shodan_api', 'internetdb']
              RETURN 'Vulnerability' AS label, n.source AS kind, n.name AS name,
                     n.severity AS sev, n.triage_tier AS tier""")
scored = [t for t in tiers if t.get("tier")]
bad = [t for t in scored if t["tier"] in ("T1", "T2")]
check("X-01a", scored and not bad, f"{len(scored)} scored; in T1/T2: {bad}")
cat = [t for t in scored if t["kind"] in ("shodan_api", "internetdb") and t["name"] == "CVE-2019-11043"]
check("X-01b", cat and all(t["tier"] == "T4" for t in cat), f"catalog-only CVE tier: {cat}")
refs_t = [t for t in scored if t["kind"] == "dev_reference"]
check("X-01c", refs_t and all(t["tier"] == "T4" for t in refs_t), f"developer reference tiers: {refs_t}")


# --------------------------------------------------------------------------- report
width = max(len(c) for c, _, _ in results)
for case, ok, detail in results:
    print(f"{'PASS' if ok else 'FAIL'}  {case:<{width}}  {detail}")
failed = [c for c, ok, _ in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed" + (f"; FAILED: {', '.join(failed)}" if failed else ""))
sys.exit(1 if failed else 0)
