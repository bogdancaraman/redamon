"""
Cache Poisoning Scanner — Output normalisation.

Shapes confirmed findings into the `combined_result["cache_scan"]` structure,
mirroring the Nuclei output layout (scan_metadata / by_target / findings / summary)
so downstream consumers (graph mixin, reports) have a familiar shape.
"""


def build_finding(vector: dict, confirmation: dict, confidence: float,
                  tier: str, impact: str, severity: str, cvss: float,
                  cache_signals: list[str]) -> dict:
    """Assemble a single normalised finding from a confirmed vector."""
    ev = confirmation.get("evidence", {}) or {}
    return {
        "endpoint_url": vector["url"],
        "technique": vector.get("technique", "unknown"),
        "vector_type": vector.get("vector_type", "header"),
        "cache_header": vector["vector_name"] if vector.get("vector_type") == "header" else "",
        "cache_param": vector["vector_name"] if vector.get("vector_type") in ("param", "fat_get", "path_param") else "",
        "impact": impact,
        "confidence": round(confidence, 3),
        "confidence_tier": tier,
        "severity": severity,
        "cvss_score": cvss,
        "cache_signals": cache_signals,
        "cache_buster": ev.get("cache_buster", ""),
        "source_engine": vector.get("source", "hypothesis"),
        # How the poison was proven: "reflected" (canary echoed), "differential"
        # (non-reflective status/location/body change), or "both".
        "detection_mode": confirmation.get("detection_mode", "reflected"),
        "evidence": {
            "baseline_hash": ev.get("baseline_hash", ""),
            "poisoned_hash": ev.get("poisoned_hash", ""),
            "clean_validation_hash": ev.get("clean_validation_hash", ""),
            "poc_link": ev.get("poc_link", ""),
            "curl_verify": ev.get("curl_verify", ""),
            "canary": ev.get("canary", ""),
            "differential_change": ev.get("differential_change", ""),
            # What the confirmation itself observed. cache_signals above come from the
            # oracle's warm-up probes and say nothing about this vector's clean read.
            "clean_cache_state": ev.get("clean_cache_state", ""),
            "baseline_stable": ev.get("baseline_stable"),
            "control_check": ev.get("control_check", ""),
            "xss_context": ev.get("xss_context", ""),
        },
    }


def build_cache_scan_result(scan_metadata: dict, by_target: dict,
                            findings: list[dict]) -> dict:
    """Build the final combined_result['cache_scan'] payload."""
    tier_counts = {"Confirmed": 0, "Strong": 0, "Tentative": 0, "Rejected": 0}
    impact_counts: dict[str, int] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        tier_counts[f.get("confidence_tier", "Rejected")] = tier_counts.get(f.get("confidence_tier", "Rejected"), 0) + 1
        impact = f.get("impact", "unknown")
        impact_counts[impact] = impact_counts.get(impact, 0) + 1
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "scan_metadata": scan_metadata,
        "by_target": by_target,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "confirmed": tier_counts.get("Confirmed", 0),
            "strong": tier_counts.get("Strong", 0),
            "tentative": tier_counts.get("Tentative", 0),
            "rejected": tier_counts.get("Rejected", 0),
            "by_impact": impact_counts,
            "by_severity": severity_counts,
            "urls_scanned": scan_metadata.get("total_urls_scanned", 0),
            "cacheable_urls": scan_metadata.get("cacheable_urls", 0),
        },
    }
