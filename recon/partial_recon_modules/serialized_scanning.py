"""Partial recon entry point for the serialized-object scan.

Runs recon.serialized_scan.run_serialized_scan() against targets derived from
the existing Neo4j graph (BaseURLs + Endpoints, per
SECTION_INPUT_MAP[SerializedScan] = [BaseURL, Endpoint]) plus any user-supplied
URLs from the modal, and merges the candidates back. Mirrors
cache_scanning.run_webcachepoison; the scan itself is passive and in-memory.
"""
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import _build_graphql_data_from_graph
from recon.partial_recon_modules.helpers import (
    _should_include_root_domain,
    include_root_for,
    partial_settings,
    scope_roots,
)


def run_serialized_scan_partial(config: dict) -> None:
    """Run a partial serialized-object scan and merge candidates into the graph."""
    from recon.serialized_scan import run_serialized_scan
    from graph_db import Neo4jClient

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print("[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)
    # Force-enable so the DB toggle doesn't override an explicit partial-recon run.
    settings["SERIALIZED_SCAN_ENABLED"] = True
    for key, value in (config.get("settings_overrides") or {}).items():
        settings[key] = value

    include_root_domain = _should_include_root_domain(settings)

    user_targets = config.get("user_targets") or {}
    raw_user_urls = user_targets.get("urls") or []
    url_attach_to = user_targets.get("url_attach_to")
    user_urls = [u.strip() for u in raw_user_urls if u and u.strip()]

    print(f"\n{'=' * 50}")
    print("[*][Partial Recon] Serialized Object Scanning")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    if user_urls:
        print(f"[+][Partial Recon] {len(user_urls)} custom URL(s) provided"
              + (f" (attach to: {url_attach_to})" if url_attach_to else " (generic UserInput)"))
    print(f"{'=' * 50}\n")

    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print("[*][Partial Recon] Querying graph for targets (BaseURLs, Endpoints)...")
        recon_data = _build_graphql_data_from_graph(roots, user_id, project_id, settings=settings,
                                                    domain_groups=config.get("domain_groups"))
    else:
        print("[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": roots[0] if roots else "",
            "domains": roots,
            "http_probe": {"by_url": {}},
            "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
            "metadata": {
                "roe": {
                    "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                    "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
                }
            },
        }

    # Honor the Include Root Domain scope toggle (per root when groups are known).
    groups = config.get("domain_groups")
    if groups is None:
        excluded_apexes = set() if include_root_domain else {r.lower() for r in roots}
    else:
        excluded_apexes = {r.lower() for r in roots if not include_root_for(r, groups)}
    if excluded_apexes:
        recon_data["http_probe"]["by_url"] = {
            url: data for url, data in recon_data["http_probe"]["by_url"].items()
            if (urlparse(url).hostname or "").lower() not in excluded_apexes
        }

    # Reshape the graph builder's resource_enum["endpoints"] = {base: [{path,method}]}
    # into the by_base_url shape the serialized scanner reads. Without this every
    # graph Endpoint is silently dropped and only BaseURLs/cookies are scanned.
    by_base_url: dict = {}
    for base, eps in (recon_data.get("resource_enum", {}).get("endpoints", {}) or {}).items():
        if (urlparse(base).hostname or "").lower() in excluded_apexes:
            continue
        ep_map = {}
        for ep in (eps or []):
            path = ep.get("path")
            if path:
                ep_map[path] = {"method": ep.get("method", "GET"), "parameters": {}}
        if ep_map:
            by_base_url[base] = {"endpoints": ep_map}
    recon_data.setdefault("resource_enum", {})["by_base_url"] = by_base_url

    # Inject user-provided URLs as live targets (http_probe.by_url entries).
    for u in user_urls:
        recon_data["http_probe"]["by_url"].setdefault(u, {
            "url": u, "host": urlparse(u).hostname or "", "status_code": 200,
            "content_type": "", "headers": {},
        })

    if len(recon_data["http_probe"]["by_url"]) == 0 and not by_base_url:
        print("[!][SerializedScan] No targets available (graph empty, no custom URLs).")
        print("[!][SerializedScan] Enable 'Include graph targets' OR paste custom URLs in the modal.")
        return

    run_serialized_scan(recon_data, settings)

    with Neo4jClient() as graph_client:
        graph_client.update_graph_from_serialized_scan(recon_data, user_id, project_id)
        if user_urls:
            _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id)

    summary = recon_data.get("serialized_scan", {}).get("summary", {}) or {}
    print(f"\n[+][Partial Recon][SerializedScan] {summary.get('total_findings', 0)} candidate(s) flagged.")


def _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id):
    """Attach user-provided URLs to an existing BaseURL or a fresh UserInput node."""
    import uuid

    if url_attach_to:
        print(f"[*][Partial Recon][SerializedScan] Linking {len(user_urls)} URL(s) to BaseURL {url_attach_to}")
        return

    user_input_id = f"userinput-serialized-{uuid.uuid4().hex[:12]}"
    try:
        graph_client.create_user_input_node(
            domain=roots,
            user_input_data={
                "id": user_input_id,
                "input_type": "url",
                "values": user_urls,
                "tool_id": "SerializedScan",
            },
            user_id=user_id,
            project_id=project_id,
        )
        print(f"[*][Partial Recon][SerializedScan] Created UserInput node {user_input_id} for {len(user_urls)} URL(s)")
    except Exception as e:
        print(f"[!][Partial Recon][SerializedScan] Failed to create UserInput node: {e}")
