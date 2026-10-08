"""
Cache Poisoning Scanner — Behavioural confirmation (Phase 4 of the native engine).

This is where RedAmon becomes more than a WCVS wrapper. A vector is only
"confirmed" after a POISON-FIRST behavioural sequence:

  1. baseline      : what the URL serves a clean client, sampled on SEPARATE fresh
                     cache-busters (once per URL via clean_profile(), or two slots per
                     vector when called standalone). Distinct slots on purpose —
                     re-reading ONE slot only returns the cache's frozen copy and can't
                     reveal a flapping page.
  2. poison        : fetch a fresh cache-buster WITH the payload. Because it is the
                     first request to that key it is a cache MISS that reaches the
                     origin, lands the poison, and the cache stores the poisoned
                     response.
  3. clean follow  : fetch that SAME poison slot again WITHOUT the payload (victim
                     view) -> a cache HIT that serves the poisoned copy.
  4. control       : the same-slot checks above hold for ANY cacheable page (a HIT
                     returns exactly what the MISS stored), so a candidate must also
                     survive a clean read of a NEVER-poisoned slot (the canary must be
                     absent; a behavioural change must not be there either) and, for a
                     behavioural change, a second poison on another fresh slot that
                     reproduces it.
  5. cache-hit     : was the clean follow-up served from cache?
  (optional) repeat the clean read to confirm stability.

Poison-first is essential against a REAL cache: baselining the poison slot first
would warm it with a clean response, and the later poison (unkeyed header -> same
key) would just HIT the clean copy and never reach the origin (a false negative).

Two detection modes run side by side:
  * REFLECTED   - the benign canary marker is echoed in the body/redirect. Strong,
                  unambiguous proof (we injected that exact token).
  * DIFFERENTIAL- the poison changes the response *behaviour* (status code, Location
                  redirect, or body) WITHOUT echoing a marker. This catches the
                  non-reflective class (ported from CacheX's detector: ayuxdev/cachex,
                  MIT). To keep the low-false-positive bar, differential signals are
                  only trusted on dimensions that were STABLE across the clean
                  baseline samples, and the cache-buster value is normalised out of
                  the comparison so distinct busters never look like a real change.

The canary is a non-resolving marker (.invalid), so a Confirmed finding never
points a victim at live attacker infrastructure.
"""

import hashlib
import re
from urllib.parse import urlencode, urlparse

import requests

from recon.cache_scan.buster import add_cache_buster, add_path_param, add_path_segment
from recon.cache_scan.oracle import response_cache_state
from recon.cache_scan.safety import (
    new_canary_token, canary_host, canary_value, new_cache_buster_value,
)

# Fixed, benign payloads for non-reflective vectors. These poison via behaviour
# change, not by echoing a marker, so they carry a meaningful (but safe) value
# rather than a random canary token.
_FIXED_PAYLOADS = {"scheme": "https", "port": "443", "ip": "127.0.0.1"}

# Clean samples taken once per URL for the differential detector. Two samples per
# vector let a page with a few random variants (an A/B bucket or a rotating banner
# picked per request) look stable half the time, and with ~30 vectors per URL some
# vector then reads that coincidence as a poisoning. One shared, larger sample makes
# "stable" a property of the URL (a 50/50 page passes 8 samples 1 time in 128), and
# costs a handful of requests instead of two per vector.
_PROFILE_SAMPLES = 8

# Fresh poisoned slots a behavioural change must reproduce on. A real poison is
# deterministic; a random variant the poison request happened to draw repeats twice
# in a row with probability p^2 (1 in 100 for a banner shown 10% of the time).
_REPRODUCTIONS = 2

# Vectors carried in the URL or the GET body. A tracking/search parameter that
# matters to the origin shows up in the response; a body that changes WITHOUT
# echoing it has no causal link to the payload (dynamic content, A/B buckets,
# time-varying tokens all do that), so for these a body-only difference proves
# nothing. Headers stay eligible: a Host-style header can legitimately route the
# origin to a different page without echoing anything.
_PARAM_BORNE_VECTORS = frozenset({"param", "fat_get", "path_param"})

# Script types a browser executes. Anything else (JSON-LD, a __NEXT_DATA__ JSON
# island, a handlebars/x-template block) is data, however it is named.
_EXECUTABLE_SCRIPT_TYPES = frozenset({
    "", "module", "text/javascript", "application/javascript", "application/x-javascript",
    "text/ecmascript", "application/ecmascript", "text/jscript",
})
_TYPE_ATTR = re.compile(r'(?:^|\s)type\s*=\s*["\']?([^"\'\s>]*)', re.I)
_SRC_ATTR = re.compile(r'(?:^|\s)src\s*=', re.I)


def _hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


def _payload_value(payload_kind: str, token: str) -> str:
    """Build the benign payload for a vector based on its kind."""
    if payload_kind == "host":
        return canary_host(token)
    if payload_kind == "path":
        return f"/{canary_value(token)}"
    if payload_kind == "forwarded":
        # RFC 7239 composite. Host carries the benign .invalid canary.
        return f"host={canary_host(token)};proto=https"
    if payload_kind in _FIXED_PAYLOADS:
        return _FIXED_PAYLOADS[payload_kind]
    return canary_value(token)


def _strip_buster(text: str, cb_param: str) -> str:
    """Remove the cache-buster query param from text so two responses fetched on
    different busters don't look different just because of the buster value."""
    if not text or not cb_param:
        return text or ""
    return re.sub(rf'[?&]{re.escape(cb_param)}=[^&\s"\'<>]+', '', text)


def _dim_value(resp, dim: str, cb_param: str = ""):
    """Extract one comparable response dimension (cache-buster normalised out)."""
    if dim == "status":
        return resp.status_code
    if dim == "location":
        return _strip_buster(resp.headers.get("location", "") or "", cb_param)
    return _strip_buster(resp.text or "", cb_param)  # body


def _changed_dims(a, b, cb_param: str = "") -> set:
    """Dimensions (status/location/body) that differ between two responses."""
    dims = set()
    for dim in ("status", "location", "body"):
        if _dim_value(a, dim, cb_param) != _dim_value(b, dim, cb_param):
            dims.add(dim)
    return dims


def _carries(resp, token: str) -> bool:
    """True if the canary token is echoed in the body or the Location header."""
    return token in (resp.text or "") or token in (resp.headers.get("location", "") or "")


def _host(url: str) -> str:
    # urlparse raises on a malformed bracketed host ("https://[cdn]/a.js"), which a
    # reflecting page can contain; one odd attribute must not abort the URL's scan.
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def _script_src_values(body: str) -> list[str]:
    # \s before src, so a lazy-loader's data-src is not read as the script's source.
    return re.findall(r'<script\b[^>]*?\ssrc\s*=\s*["\']?([^"\'\s>]+)', body or "", re.I)


def _script_src_canary(body: str, needle: str) -> bool:
    """True if the canary is the HOST of a <script src>: the victim's browser loads and
    runs script from an origin the attacker picked. Stored XSS with no escaping
    question, the only script context a benign canary can prove."""
    if not body or not needle:
        return False
    for src in _script_src_values(body):
        host = _host(src) if "//" in src else ""
        if needle.lower() in host:
            return True
    return False


def _xss_context(body: str, needle: str) -> bool:
    """True if `needle` is reflected inside an executable context: a <script src>, an
    executable inline <script>, an event-handler attribute value or a javascript: URI.

    Outside the script-src host case (see _script_src_canary) this proves where the
    input lands, not that it can break out: whether a quote or </script> would survive
    is unknown to an alphanumeric canary, so callers report it as unverified.
    """
    if not body or not needle:
        return False
    if any(needle in src for src in _script_src_values(body)):
        return True
    for attrs, code in re.findall(r'<script\b([^>]*)>(.*?)</script\s*>', body, re.I | re.S):
        type_match = _TYPE_ATTR.search(attrs)
        script_type = type_match.group(1).lower() if type_match else ""
        if (needle in code and script_type in _EXECUTABLE_SCRIPT_TYPES
                and not _SRC_ATTR.search(attrs)):
            return True
    n = re.escape(needle)
    # Both patterns are anchored inside a tag, so page text that merely mentions
    # "onload=" or "javascript:" does not count. The handler value stops at its own
    # closing quote: a canary in a LATER attribute of the same tag
    # (`<a onclick="f()" href="/?x=CANARY">`) is not in the handler.
    if re.search(rf'<[^>]*?\son\w+\s*=\s*(?:"[^"]*{n}|\'[^\']*{n}|[^\s>"\']*{n})', body, re.I):
        return True
    return bool(re.search(rf'<[^>]*?=\s*["\']?\s*javascript:[^"\'<>]*{n}', body, re.I))


def _redirects_to_canary(location: str, token: str) -> bool:
    """True if a Location sends the client to the canary's host (an attacker-chosen
    origin), as opposed to a redirect that merely changed or carries the token in its
    query string."""
    if not location or not token:
        return False
    return token.lower() in _host(location)


def _pick_diff(base, mod, trusted: set, cb_param: str = "") -> str:
    """First trusted dimension that the poison changed (priority loc > status > body).

    429s are treated as rate-limit noise, never a change (mirrors CacheX).
    """
    if base.status_code == 429 or mod.status_code == 429:
        return ""
    changed = _changed_dims(base, mod, cb_param)
    for dim in ("location", "status", "body"):
        if dim in trusted and dim in changed:
            return dim
    return ""


def _apply_vector(url: str, vector_type: str, vector_name: str, payload: str):
    """Return (request_url, extra_headers, body) with the payload applied.

    ``body`` is None for every vector except ``fat_get``.
    """
    if vector_type == "header":
        return url, {vector_name: payload}, None
    if vector_type == "param":
        return add_cache_buster(url, vector_name, payload), {}, None
    if vector_type == "path_param":
        # Cache-key normalization abuse: the payload rides as a matrix/path parameter
        # (…;name=value) on the path. A cache that strips ;params from its key serves
        # the poisoned response to a victim requesting the clean path; the confirm flow
        # then sees the canary persist on the clean (…;-free) follow-up.
        return add_path_param(url, vector_name, payload), {}, None
    if vector_type == "fat_get":
        # Fat GET: the param rides in the GET request BODY, never in the URL. A cache
        # keys on the URL and so never sees it; an origin that merges GET body params
        # still reads and reflects it -> body-borne parameter cloaking. The clean
        # victim request carries no body, so a HIT that still shows the value proves
        # the poisoned body was cached under the bare URL key.
        body = urlencode({vector_name: payload})
        return url, {"Content-Type": "application/x-www-form-urlencoded"}, body
    if vector_type == "path":
        # The segment is the vector NAME (a fixed confusion suffix like
        # "_payload.json"), inserted BEFORE the cache-buster query so it reaches the
        # route. The random `payload` canary is deliberately not used: a path vector
        # poisons via path-keying confusion (detected differentially), not by echoing
        # a marker, so the suffix must be the exact, fixed path the framework serves.
        return add_path_segment(url, vector_name), {}, None
    return url, {}, None


def _send(session, req_url, extra_headers=None, body=None, timeout=10, verify_ssl=True):
    # Only pass data= when there IS a body: the clean/baseline reads must stay plain
    # GETs, and it keeps fake sessions (no data kwarg) working unchanged.
    if body is not None:
        return session.get(req_url, headers=extra_headers or None, data=body,
                           timeout=timeout, verify=verify_ssl, allow_redirects=False)
    return session.get(req_url, headers=extra_headers or None,
                       timeout=timeout, verify=verify_ssl, allow_redirects=False)


def _untrust(baseline: dict, dim: str) -> None:
    """Stop trusting `dim` for the rest of the URL. The profile is shared by every
    vector of the URL, so a dimension seen moving on its own is evidence of nothing
    for the vectors still to run."""
    baseline["trusted"].discard(dim)
    baseline["stable"] = False


def clean_profile(url: str, cb_param: str, session, timeout: int = 10,
                  verify_ssl: bool = True, samples: int = _PROFILE_SAMPLES):
    """Sample the URL clean on `samples` fresh cache-busters (see _PROFILE_SAMPLES).

    Returns {"ref": first response, "trusted": dims equal across every sample,
    "stable": no dim flapped}, or None if the URL could not be sampled (the vectors
    then fall back to their own two-slot baseline).
    """
    try:
        resps = [_send(session, add_cache_buster(url, cb_param, new_cache_buster_value()),
                       timeout=timeout, verify_ssl=verify_ssl)
                 for _ in range(max(2, samples))]
    except requests.RequestException:
        return None
    ref = resps[0]
    unstable: set = set()
    for other in resps[1:]:
        unstable |= _changed_dims(ref, other, cb_param)
    return {"ref": ref, "trusted": {"status", "location", "body"} - unstable,
            "stable": not unstable}


def confirm_vector(vector: dict, buster: dict, session: requests.Session,
                   settings: dict, timeout: int = 10, verify_ssl: bool = True,
                   baseline: dict | None = None) -> dict:
    """Run the behavioural confirmation sequence for one vector.

    `vector` keys: url, vector_type, vector_name, payload_kind, impact_hint.
    `baseline`: the URL's clean_profile(); without one the vector samples its own two
    clean slots.
    Returns a confirmation record consumed by scoring.score_finding(), plus
    evidence fields for the graph.
    """
    url = vector["url"]
    vector_type = vector.get("vector_type", "header")
    vector_name = vector["vector_name"]
    payload_kind = vector.get("payload_kind", "value")

    cb_param = buster.get("param", "rdmncb")
    # The poison slot: a FRESH buster so the poison request below is the first request
    # to this cache key (a MISS that reaches the origin and lands the poison).
    cb_value = new_cache_buster_value()
    poison_url = add_cache_buster(url, cb_param, cb_value)

    token = new_canary_token()
    payload = _payload_value(payload_kind, token)
    differential_enabled = bool(settings.get("WEB_CACHE_POISON_DIFFERENTIAL", True))

    record = {
        "reflected_in_baseline": False,
        "persisted_on_clean": False,
        "persisted_reflected": False,
        "persisted_differential": False,
        "cache_hit_on_clean": False,
        "clean_cache_state": "unknown",
        "control_check": "",
        "repeated_ok": False,
        "stable": True,
        "baseline_stable": True,
        "differential_change": "",
        "detection_mode": "none",
        "xss_context": False,
        "script_src_canary": False,
        "redirect_to_canary": False,
        "evidence": {},
        "cross_vantage": False,
    }

    def _get(req_url, extra_headers=None, body=None):
        return _send(session, req_url, extra_headers, body, timeout, verify_ssl)

    def _fresh_slot():
        return add_cache_buster(url, cb_param, new_cache_buster_value())

    try:
        # 1. Clean baseline, for differential only (see clean_profile).
        base_ref = None
        trusted: set = set()
        if differential_enabled:
            if baseline is None:
                # The full profile, not two samples: a page alternating between two
                # variants agrees with itself on two samples half the time.
                baseline = clean_profile(url, cb_param, session, timeout, verify_ssl)
            if baseline is not None:
                base_ref = baseline["ref"]
                trusted = set(baseline["trusted"])
                record["baseline_stable"] = baseline["stable"]
            if vector_type in _PARAM_BORNE_VECTORS and not str(
                    vector.get("technique", "")).startswith("framework_"):
                trusted.discard("body")

        # 2. POISON FIRST on the fresh poison slot -> MISS -> origin -> poison cached.
        req_url, extra_headers, body = _apply_vector(poison_url, vector_type, vector_name, payload)
        poisoned = _get(req_url, extra_headers, body)
        poisoned_body = poisoned.text or ""
        poisoned_loc = poisoned.headers.get("location", "") or ""
        record["reflected_in_baseline"] = _carries(poisoned, token)
        diff_type = _pick_diff(base_ref, poisoned, trusted, cb_param) if base_ref is not None else ""
        record["differential_change"] = diff_type

        # 3. clean follow-up on the SAME poison slot (victim view) -> HIT -> poisoned.
        clean = _get(poison_url)
        clean_body = clean.text or ""
        clean_loc = clean.headers.get("location", "") or ""
        persisted_reflected = _carries(clean, token)
        # Differential persistence: the poisoned value still shows on the clean request
        # AND it differs from the clean baseline (the poison stuck, didn't revert).
        persisted_differential = bool(diff_type) and (
            _dim_value(clean, diff_type, cb_param) == _dim_value(poisoned, diff_type, cb_param)
            and _dim_value(clean, diff_type, cb_param) != _dim_value(base_ref, diff_type, cb_param)
        )

        # 4. Control. Both same-slot checks above hold for any cacheable page, so they
        #    prove nothing alone: the clean read is a HIT of whatever the poison MISS
        #    stored. A never-poisoned slot shows what a clean client gets RIGHT NOW,
        #    which separates poisoning from its impostors: state the origin keeps
        #    outside the cache (a cookie or session replaying the canary), a page that
        #    drifted between the baseline and the poison, an IP block that started
        #    mid-sequence. A behavioural change must also reproduce on a second poisoned
        #    slot, or a one-off error the poison request happened to catch gets cached
        #    and read as poisoning.
        if persisted_reflected or persisted_differential:
            control = _get(_fresh_slot())
            if control.status_code == 429:
                # A rate-limited control proves nothing either way; and a rate limit is
                # not the page moving, so the URL's profile keeps its trust.
                persisted_reflected = persisted_differential = False
                record["control_check"] = "rate_limited"
            if persisted_reflected and _carries(control, token):
                persisted_reflected = False
                record["control_check"] = "canary_on_fresh_slot"
            if persisted_differential and (
                    _dim_value(control, diff_type, cb_param) != _dim_value(base_ref, diff_type, cb_param)):
                persisted_differential = False
                record["control_check"] = "baseline_drift"
                _untrust(baseline, diff_type)
            for _ in range(_REPRODUCTIONS):
                if not persisted_differential:
                    break
                again = _get(*_apply_vector(_fresh_slot(), vector_type, vector_name, payload))
                if again.status_code == 429:
                    persisted_differential = False
                    record["control_check"] = "rate_limited"
                elif _dim_value(again, diff_type, cb_param) != _dim_value(poisoned, diff_type, cb_param):
                    persisted_differential = False
                    record["control_check"] = "not_reproduced"
                    if _dim_value(again, diff_type, cb_param) == _dim_value(base_ref, diff_type, cb_param):
                        # The same payload got the clean value: the earlier change was
                        # the page's own doing.
                        _untrust(baseline, diff_type)
            if persisted_reflected or persisted_differential:
                record["control_check"] = "passed"

        persisted = persisted_reflected or persisted_differential
        record["persisted_reflected"] = persisted_reflected
        record["persisted_differential"] = persisted_differential
        record["persisted_on_clean"] = persisted
        record["clean_cache_state"] = response_cache_state(clean)
        record["cache_hit_on_clean"] = record["clean_cache_state"] == "hit"
        record["detection_mode"] = (
            "both" if persisted_reflected and persisted_differential
            else "reflected" if persisted_reflected
            else "differential" if persisted_differential
            else "none"
        )
        if persisted_reflected:
            record["xss_context"] = _xss_context(clean_body, token)
            record["script_src_canary"] = _script_src_canary(clean_body, token)
            record["redirect_to_canary"] = _redirects_to_canary(clean_loc, token)

        # 5. repeat the clean read for stability (only if it persisted).
        if persisted:
            clean2 = _get(poison_url)
            clean2_body = clean2.text or ""
            if persisted_reflected:
                repeated = _carries(clean2, token)
            else:
                repeated = _dim_value(clean2, diff_type, cb_param) == _dim_value(poisoned, diff_type, cb_param)
            record["repeated_ok"] = repeated
            record["stable"] = abs(len(clean_body) - len(clean2_body)) < max(64, len(clean_body) * 0.05)

        record["evidence"] = {
            "baseline_hash": _hash(base_ref.text if base_ref is not None else ""),
            "poisoned_hash": _hash(poisoned_body),
            "clean_validation_hash": _hash(clean_body),
            "poc_link": poison_url if persisted else "",
            "curl_verify": _build_curl(req_url, extra_headers, body),
            "canary": payload,
            "cache_buster": f"{cb_param}={cb_value}",
            "redirect_baseline": (base_ref.headers.get("location", "") or "") if base_ref is not None else "",
            "redirect_poisoned": poisoned_loc,
            "differential_change": diff_type,
            "poisoned_status": poisoned.status_code,
            "baseline_status": base_ref.status_code if base_ref is not None else None,
            "clean_cache_state": record["clean_cache_state"],
            "baseline_stable": record["baseline_stable"],
            "control_check": record["control_check"],
            "xss_context": ("proven" if record["script_src_canary"]
                            else "unverified" if record["xss_context"] else ""),
        }
    except requests.RequestException as e:
        record["stable"] = False
        record["evidence"] = {"error": str(e)}

    return record


def classify_impact(vector: dict, record: dict) -> str:
    """Resolve the impact class from what the confirmation OBSERVED.

    The vector's impact_hint is what it *might* do; labelling from it is how a cached
    https-upgrade (X-Forwarded-Proto hints open_redirect) became a high-severity open
    redirect. It is only returned for a record that never persisted.
    """
    if not record.get("persisted_on_clean"):
        return vector.get("impact_hint") or "reflected"
    if record.get("script_src_canary"):
        return "stored_xss"
    if record.get("redirect_to_canary"):
        return "open_redirect"
    ev = record.get("evidence", {}) or {}
    diff = record.get("differential_change") or ev.get("differential_change")
    if record.get("persisted_differential") and diff == "status":
        # A persisted error/blank status served to clean users is a cache-poisoned DoS.
        status = ev.get("poisoned_status") or 0
        if isinstance(status, int) and (status >= 400 or status == 0):
            return "dos"
    if record.get("persisted_reflected"):
        return "reflected_script" if record.get("xss_context") else "reflected"
    return "response_change"


def _build_curl(url: str, headers: dict, body: str | None = None) -> str:
    parts = ["curl", "-sk"]
    if body is not None:
        # A fat GET: -X GET keeps the method, since curl turns --data into a POST.
        parts.extend(["-X", "GET"])
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    if body is not None:
        parts.append(f"--data '{body}'")
    parts.append(f"'{url}'")
    return " ".join(parts)
