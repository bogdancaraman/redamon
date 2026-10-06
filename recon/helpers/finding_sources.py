"""The recon pipeline's own finding sources, shared by full and partial recon.

A prune only ever touches these, so a recon run can never remove a GVM,
GitHub-hunt or supply-chain finding; the node-filter sweep is scoped to them
for the same reason. graph_db/node_filters/build.py reads this tuple to check
that every source is claimed by a filter kind or listed as unfiltered.
"""

RECON_FINDING_SOURCES = (
    "nuclei", "security_check", "js_recon", "jsluice", "takeover_scan",
    "cache_poisoning", "graphql_scan", "graphql_cop", "ai_surface_recon",
    "vhost_sni_enum", "origin_discovery", "nmap_nse", "resource_enum",
    "http_probe", "vuln_scan", "wcvs", "serialized_scan",
)
