"""Drive a real full recon against the false-positive lab, entirely over MCP.

Creates an IP-mode project on the lab's targets with exactly the modules under
test, checks its scope, starts the full pipeline, waits for it, then runs the
Priority Board and waits for that. Prints PROJECT_ID=<id> for validate_e2e.py.

    cd testing/guinea_pigs/fp_regression_target
    docker compose up -d --build
    # the orchestrator must forward the Shodan stub (see README.md)
    python3 e2e_fp.py                       # new project + full run
    python3 e2e_fp.py --rerun <projectId>   # a second run on the same project

Reads MCP_SERVER_TOKEN from the repo .env through ../fix_regression_target's
client, which never prints it.
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fix_regression_target"))
import mcp_client as mcp  # noqa: E402

NET = "192.88.94"
TARGETS = [f"{NET}.{n}" for n in (10, 11, 12, 13, 14, 15, 20)]
APEX = "fplab.test"
VHOST_NAMES = ["admin", "wiki", "dev", "staging", "jenkins", "portal-internal", "qa", "grafana", "vpn",
               "api-gateway", "kibana", "ci", "sso", "monitoring", "backoffice", "uat", "x1",
               "preprod-eu-west", "status", "mail", "intranet"]

AI_OFF = [
    "portScanAiPortCatalogEnabled", "masscanAiPortCatalogEnabled", "nmapAiVersionRegexEnabled",
    "httpProbeAiHeaderScanEnabled", "httpProbeAiFaviconHashEnabled", "httpProbeAiTitleDetectionEnabled",
    "httpProbeAiWappalyzerEnabled", "resourceEnumAiClassifierEnabled", "resourceEnumAiPathClassifierEnabled",
    "resourceEnumAiRagPathFlagEnabled", "resourceEnumAiParamInjectableFlagEnabled",
    "resourceEnumAiToolArgPathEnabled", "domainReconAiTxtHintEnabled", "domainReconAiNsHintEnabled",
    "ffufAiExtensions",
]

SETTINGS = {
    "scanModules": ["port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"],
    "naabuEnabled": True, "naabuCustomPorts": "80,443", "naabuTopPorts": "",
    "masscanEnabled": False, "nmapEnabled": False, "bannerGrabEnabled": False, "tlsxEnabled": False,
    "katanaEnabled": True, "katanaDepth": 2, "katanaJsCrawl": True,
    "hakrawlerEnabled": False, "gauEnabled": False, "ffufEnabled": False, "arjunEnabled": False,
    "jsluiceEnabled": False, "captureProxyEnabled": False,
    "nucleiEnabled": False, "securityCheckEnabled": False, "cveLookupEnabled": False, "mitreEnabled": False,
    "whoisEnabled": False, "urlscanEnabled": False, "otxEnabled": False, "subdomainDiscoveryEnabled": False,
    "aiSurfaceReconEnabled": False, "graphqlSecurityEnabled": False, "graphqlCopEnabled": False,
    "serializedScanEnabled": False, "supplyChainReconEnabled": False, "originDiscoveryEnabled": False,
    "subjackEnabled": False, "nucleiTakeoversEnabled": False, "baddnsEnabled": False,
    "scaIntelCorrelationEnabled": False,
    # Under test
    "vhostSniEnabled": True, "vhostSniTestL7": True, "vhostSniTestL4": True,
    "vhostSniUseDefaultWordlist": False, "vhostSniUseGraphCandidates": False,
    "vhostSniInjectDiscovered": False, "vhostSniBaselineSizeTolerance": 50, "vhostSniConcurrency": 8,
    "vhostSniCustomWordlist": "\n".join(f"{w}.{APEX}" for w in VHOST_NAMES),
    "jsReconEnabled": True, "jsReconSourceMaps": True, "jsReconDomSinks": True, "jsReconRegexPatterns": True,
    "jsReconValidateKeys": False, "jsReconValidateEndpoints": False, "jsReconMinConfidence": "low",
    "jsReconIncludeChunks": True, "jsReconIncludeArchivedJs": False,
    "shodanEnabled": True, "shodanHostLookup": True, "shodanPassiveCves": True,
    "shodanReverseDns": False, "shodanDomainDns": False,
    "webCachePoisonEnabled": True, "webCachePoisonScanProfile": "safe-confirm",
    # Rules-only ranking: the tiers under test come from the score model, and a
    # budget above 0 makes the UI ask for a review model first.
    "triageReviewBudget": 0,
    **{k: False for k in AI_OFF},
}


def call(tool, args):
    out, err = mcp.call(tool, args)
    if err:
        raise SystemExit(f"[!] {tool} failed: {json.dumps(out)[:800]}")
    return out


def reset_lab():
    """The rate-limit edge counts admin's requests and the cache holds pages:
    restart both so every run starts from the same state."""
    for name in ("redamon-fp-ratelimit", "redamon-fp-cache"):
        subprocess.run(["docker", "restart", name], check=False, capture_output=True)
    time.sleep(2)


def wait(tool, project_id, done, timeout, every=15):
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
        state = call(tool, {"projectId": project_id})
        view = json.dumps({k: state.get(k) for k in ("status", "phase", "currentPhase", "current_phase",
                                                     "state", "running") if k in state})
        if view != last:
            print(f"    {time.strftime('%H:%M:%S')} {tool}: {view}", flush=True)
            last = view
        if done(state):
            return state
        time.sleep(every)
    raise SystemExit(f"[!] {tool} timed out after {timeout}s")


def _recon_done(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "stopped", "idle") and not state.get("running")


def _triage_done(state):
    status = str(state.get("status") or state.get("state") or "").lower()
    return status in ("completed", "error", "failed", "idle", "done") and not state.get("running")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rerun", metavar="PROJECT_ID")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--no-triage", action="store_true")
    args = ap.parse_args()

    mcp.init()
    reset_lab()
    if args.rerun:
        project_id = args.rerun
    else:
        name = f"FP regression lab {time.strftime('%Y-%m-%d %H:%M:%S')}"
        out = call("create_project", {"name": name, "engagementKind": "internal",
                                      "description": "Guinea pig: testing/guinea_pigs/fp_regression_target",
                                      "targetIps": TARGETS, "settings": SETTINGS})
        project_id = (out.get("project") or {}).get("id") or out.get("id") or out.get("projectId")
        print(f"[+] project {project_id} ({name})", flush=True)
    print("[*] preflight:", json.dumps(call("preflight_scope_check", {"projectId": project_id}))[:600], flush=True)
    started = call("start_recon", {"projectId": project_id, "mode": "new"})
    print("[+] start_recon:", json.dumps(started)[:400], flush=True)
    time.sleep(20)
    final = wait("get_recon_status", project_id, _recon_done, args.timeout)
    print("[+] recon finished:", json.dumps(final)[:600], flush=True)
    if not args.no_triage:
        out, err = mcp.call("start_triage_run", {"projectId": project_id})
        if err and "triage:run" in json.dumps(out):
            # A token minted without this scope can still drive the recon; the
            # Priority Board is then started from the UI (or a token with the scope).
            print("[!] this MCP token lacks the triage:run scope: start the Priority Board "
                  "run from the UI, then run validate_e2e.py", flush=True)
        elif err:
            raise SystemExit(f"[!] start_triage_run failed: {json.dumps(out)[:800]}")
        else:
            print("[*] start_triage_run:", json.dumps(out)[:400], flush=True)
            time.sleep(10)
            tri = wait("get_triage_status", project_id, _triage_done, 1800)
            print("[+] triage finished:", json.dumps(tri)[:600], flush=True)
    print(f"PROJECT_ID={project_id}")


if __name__ == "__main__":
    main()
