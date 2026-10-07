"""
Cache Poisoning Scanner — Hypothesis generation (Phase 3 of the native engine).

WCVS gives breadth with generic wordlists. This module adds the framework-aware
payloads that generic scanners miss — the recent public breakthroughs from zhero's
research (Next.js / Nuxt / Remix). Packs are only fired when the technology
fingerprint makes them plausible, which cuts noise and reduces risky requests.

A hypothesis is a candidate vector to confirm:
  {url, technique, vector_type: "header"|"param"|"path", vector_name,
   payload_kind: "host"|"value"|"path", impact_hint, source: "hypothesis"}
The actual payload value (a benign canary) is injected at confirmation time.
"""

# Generic unkeyed-input candidates (always tried unless WCVS already covered them).
#
# (name, payload_kind, impact_hint). payload_kind drives how confirm.py builds the
# benign payload:
#   host     -> <token>.redamon-poc.invalid     (reflected host spoof / open redirect)
#   path     -> /<token>                         (path override, often reflected)
#   value    -> <token>                          (generic reflection marker)
#   scheme   -> "https"   (FIXED, benign)        (proto/scheme confusion, non-reflective)
#   port     -> "443"     (FIXED, benign)        (port confusion, non-reflective)
#   ip       -> "127.0.0.1" (FIXED, benign)      (client-IP spoof, non-reflective/ACL)
#   forwarded-> host=<canary>;proto=https        (RFC 7239 composite)
#
# scheme/port/ip carry a fixed benign value rather than a random canary because they
# poison via *behaviour change* (a different redirect / status / body), not by echoing
# a marker. The native differential detector (confirm.py) is what catches those.
#
# Curated from CacheX's payload list (ayuxdev/cachex, MIT) down to the high-value
# families; the long tail of exotic CGI-style vars (HTTP_*, REMOTE_ADDR, raw CF-* ray
# ids) is deliberately omitted to keep per-URL request load sane (see README §16).
_GENERIC_HEADERS = [
    # Host-spoofing family -> open redirect / cache-key host confusion
    ("X-Forwarded-Host", "host", "open_redirect"),
    ("X-Host", "host", "open_redirect"),
    ("X-Forwarded-Server", "host", "open_redirect"),
    ("X-Original-Host", "host", "open_redirect"),
    ("X-Host-Override", "host", "open_redirect"),
    ("X-Forwarded-Host-Override", "host", "open_redirect"),
    ("X-HTTP-Host-Override", "host", "open_redirect"),
    ("Forwarded", "forwarded", "open_redirect"),
    # Scheme / proto confusion (non-reflective) -> redirect-to-https loops, etc.
    ("X-Forwarded-Proto", "scheme", "open_redirect"),
    ("X-Forwarded-Scheme", "scheme", "open_redirect"),
    ("X-Original-Scheme", "scheme", "open_redirect"),
    ("X-Url-Scheme", "scheme", "open_redirect"),
    # Port confusion (non-reflective)
    ("X-Forwarded-Port", "port", "open_redirect"),
    # URL / path override (often reflected)
    ("X-Original-URL", "path", "reflected"),
    ("X-Rewrite-URL", "path", "reflected"),
    # Client-IP spoofing family (non-reflective / access-control, geo)
    ("X-Forwarded-For", "ip", "reflected"),
    ("X-Real-IP", "ip", "reflected"),
    ("True-Client-IP", "ip", "reflected"),
    ("X-Client-IP", "ip", "reflected"),
]

# Commonly cache-key-IGNORED query params. Caches routinely strip analytics/JSONP
# params from the cache key while the backend still reflects them -> parameter
# cloaking / unkeyed-param poisoning. Always tried (cheap) unless WCVS covered them.
_GENERIC_PARAMS = [
    ("utm_source", "reflected"),
    ("utm_medium", "reflected"),
    ("utm_campaign", "reflected"),
    ("utm_content", "reflected"),
    ("gclid", "reflected"),
    ("fbclid", "reflected"),
    ("callback", "reflected"),   # JSONP
]

# Fat GET: params carried in the GET request BODY (not the query). An origin that
# merges GET body params reflects them while a URL-keyed cache never sees them, so a
# poisoned body is stored under the bare URL and served to body-less victims. Kept
# short (this is an unusual request shape) and reflection-only.
_FAT_GET_PARAMS = [
    ("q", "reflected"),          # ubiquitous search param, commonly reflected
    ("utm_source", "reflected"),
]

# Cache-key normalization abuse: names tried as MATRIX / path parameters (…;name=value).
# A cache that strips ;params from its key (but whose origin reads them) is poisonable.
_PATH_PARAM_NAMES = [
    ("utm_source", "reflected"),
    ("v", "reflected"),
]

# Framework packs keyed by a technology-name substring (matched case-insensitively
# against the recon technology fingerprint).
_FRAMEWORK_PACKS = {
    "next": [
        ("x-invoke-status", "header", "value", "dos"),         # CPDoS render of /_error
        ("__nextDataReq", "param", "value", "reflected"),       # SSR data-request mode
        ("x-now-route-matches", "header", "value", "reflected"),
        ("Rsc", "header", "value", "reflected"),
    ],
    "nuxt": [
        ("_payload.json", "path", "path", "reflected"),         # full-URL vs path keying
    ],
    "remix": [
        ("_data", "param", "value", "reflected"),               # data-request mode
        ("Host", "header", "host", "open_redirect"),            # port-path confusion
    ],
    "react router": [
        ("_data", "param", "value", "reflected"),
        ("X-Forwarded-Host", "header", "host", "open_redirect"),
    ],
}


def framework_param_technique(name: str) -> str:
    """The framework_* technique of a framework pack's PARAM vector, "" for any other name.

    WCVS can surface one of these first, as a generic unkeyed param, and the pack's
    own copy is then skipped as already covered. Its re-test must still be judged as
    the framework data-request switch it is (it reshapes the body without echoing
    anything), not as a tracking parameter.
    """
    low = (name or "").lower()
    for tech_key, pack in _FRAMEWORK_PACKS.items():
        for vector_name, vector_type, _, _ in pack:
            if vector_type == "param" and vector_name.lower() == low:
                return f"framework_{tech_key.replace(' ', '_')}"
    return ""


def _fingerprint_technologies(combined_result: dict) -> set[str]:
    """Collect lowercase technology names from the recon fingerprint."""
    techs: set[str] = set()
    http_probe = combined_result.get("http_probe") or {}
    for name in (http_probe.get("technologies_found") or {}):
        techs.add(str(name).lower())
    for url_data in (http_probe.get("by_url") or {}).values():
        for t in (url_data.get("technologies") or []):
            techs.add(str(t).lower())
    return techs


def generate_hypotheses(url: str, combined_result: dict, settings: dict,
                        wcvs_vectors_seen: set[str]) -> list[dict]:
    """Build native hypotheses for one URL, skipping vectors WCVS already tested.

    `wcvs_vectors_seen` is the set of vector names WCVS already surfaced for this
    URL so we don't duplicate confirmation work.
    """
    from recon.cache_scan.safety import is_framework_packs_allowed

    hypotheses: list[dict] = []
    seen_lower = {v.lower() for v in wcvs_vectors_seen}

    # Framework packs FIRST (gated on fingerprint + setting). They are
    # fingerprint-targeted and higher-value than the broad generic sweep, so they
    # come ahead of the generic list to survive the per-URL vector cap when WCVS
    # already contributed many candidates.
    if is_framework_packs_allowed(settings):
        techs = _fingerprint_technologies(combined_result)
        for tech_key, pack in _FRAMEWORK_PACKS.items():
            if not any(tech_key in t for t in techs):
                continue
            for vector_name, vector_type, payload_kind, impact in pack:
                if vector_name.lower() in seen_lower:
                    continue
                hypotheses.append({
                    "url": url,
                    "technique": f"framework_{tech_key.replace(' ', '_')}",
                    "vector_type": vector_type,
                    "vector_name": vector_name,
                    "payload_kind": payload_kind,
                    "impact_hint": impact,
                    "source": "hypothesis",
                })

    # Generic header vectors (broad sweep)
    for name, kind, impact in _GENERIC_HEADERS:
        if name.lower() in seen_lower:
            continue
        hypotheses.append({
            "url": url,
            "technique": "unkeyed_header",
            "vector_type": "header",
            "vector_name": name,
            "payload_kind": kind,
            "impact_hint": impact,
            "source": "hypothesis",
        })

    # Generic unkeyed-param vectors (parameter cloaking)
    for name, impact in _GENERIC_PARAMS:
        if name.lower() in seen_lower:
            continue
        hypotheses.append({
            "url": url,
            "technique": "unkeyed_param",
            "vector_type": "param",
            "vector_name": name,
            "payload_kind": "value",
            "impact_hint": impact,
            "source": "hypothesis",
        })

    # Fat GET (body-borne parameter cloaking). A distinct TRANSPORT from the query
    # sweep above (param in the GET body, not the URL), so it is emitted even when
    # the same name rode the query -- the two exercise different code paths. A WCVS
    # fat_get candidate is instead re-tested via _wcvs_vector's fat_get branch.
    for name, impact in _FAT_GET_PARAMS:
        hypotheses.append({
            "url": url,
            "technique": "fat_get",
            "vector_type": "fat_get",
            "vector_name": name,
            "payload_kind": "value",
            "impact_hint": impact,
            "source": "hypothesis",
        })

    # Cache-key normalization abuse (matrix / path parameter). Distinct location from
    # the query and body sweeps, so always emitted.
    for name, impact in _PATH_PARAM_NAMES:
        hypotheses.append({
            "url": url,
            "technique": "normalization",
            "vector_type": "path_param",
            "vector_name": name,
            "payload_kind": "value",
            "impact_hint": impact,
            "source": "hypothesis",
        })

    return hypotheses
