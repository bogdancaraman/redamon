"""Serialized-object detection over the in-memory recon corpus (plan §5).

Passive, deterministic, no DB, no network, and it NEVER deserializes. It reads
only what the pipeline already holds in memory -- response headers + Set-Cookie
(http_probe ``by_url``) and enumerated endpoints/parameters (resource_enum
``by_base_url``) -- runs every value through the bomb-safe decode-and-recurse
normalizer, and matches the family signatures. Each hit becomes one
:Vulnerability candidate (needs_agent_confirmation=true, severity=info) that the
agent's deserialization skill confirms out of band.

Request-side blobs (POST bodies, request cookies) are not in the in-memory slice
(bodies are popped at http_probe.py:2051); that gap is the agent's half.
"""

from __future__ import annotations

import copy
import re
from urllib.parse import urlparse

from recon.serialized_scan import decoders, normalizers, signatures

# A serialized blob usually rides as a substring: a cookie VALUE after `=`, one
# query pair, or a long base64/hex run embedded in a larger string. Scanning the
# whole value catches inline text markers (O:4:, @class, <java version); these
# extracted tokens are what the decode-and-recurse normalizer peels.
_MAX_VALUE_LEN = 64 * 1024
_MAX_TOKENS = 24
_KV_SPLIT = re.compile(r"[;&,\s]+")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")


def _candidate_tokens(value: str) -> list:
    """The whole value plus embedded cookie/query values and base64/hex runs."""
    value = value[:_MAX_VALUE_LEN]
    tokens = [value]
    for part in _KV_SPLIT.split(value):
        if "=" in part:
            v = part.split("=", 1)[1]
            if v:
                tokens.append(v)
    tokens.extend(_B64_RUN.findall(value))
    tokens.extend(_HEX_RUN.findall(value))
    seen: set = set()
    out: list = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
        if len(out) >= _MAX_TOKENS:
            break
    return out

try:
    from recon.helpers.roe_scope import _is_roe_excluded
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.roe_scope import _is_roe_excluded


def _host_excluded(url: str, roe_excluded: list) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return False
    return bool(host) and _is_roe_excluded(host, roe_excluded)


def _scan_value(value, transport: str, location: str, ctx: dict, sink) -> None:
    """Decode-and-recurse one value, emitting a finding per signature hit.

    ``sink`` is called with a fully built finding dict for each unique hit.
    """
    if not isinstance(value, str) or not value:
        return
    seen_here: set = set()
    for token in _candidate_tokens(value):
        decoded = decoders.decode_layers(token)
        chain = list(decoded["encoding_chain"])
        if decoded["truncated"]:
            chain.append("truncated")
        for layer in decoded["layers"]:
            hits = signatures.scan_text(layer["text"]) + signatures.scan_bytes(layer["raw"])
            for hit in hits:
                key = (hit["format"], hit["magic"])
                if key in seen_here:
                    continue
                seen_here.add(key)
                sink(normalizers.build_finding(
                    endpoint_url=ctx["endpoint_url"],
                    http_method=ctx["http_method"],
                    baseurl=ctx["baseurl"],
                    path=ctx["path"],
                    transport=transport,
                    location=location,
                    hit=hit,
                    encoding_layers=chain,
                ))


def _scan_http_probe(combined_result: dict, roe_excluded: list, sink) -> None:
    """Response headers + Set-Cookie carry serialized blobs on the response side."""
    by_url = (combined_result.get("http_probe") or {}).get("by_url") or {}
    for url, entry in by_url.items():
        if not isinstance(entry, dict):
            continue
        if _host_excluded(url, roe_excluded):
            continue
        parsed = urlparse(url)
        ctx = {
            "endpoint_url": url,
            "http_method": "GET",
            "baseurl": f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else url,
            "path": parsed.path or "/",
        }

        content_type = entry.get("content_type")
        if isinstance(content_type, str):
            for hit in signatures.scan_header_value(content_type):
                sink(normalizers.build_finding(
                    endpoint_url=url, http_method="GET", baseurl=ctx["baseurl"],
                    path=ctx["path"], transport="header", location="Content-Type",
                    hit=hit, encoding_layers=[]))

        headers = entry.get("headers")
        if isinstance(headers, str):
            # httpx sometimes stores response headers as one CRLF-joined string
            # (http_probe normalises both forms). Parse it back into name/value
            # pairs so Set-Cookie and serialization content types are not missed.
            parsed: dict = {}
            for line in headers.split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    parsed.setdefault(k.strip(), v.strip())
            headers = parsed
        if isinstance(headers, dict):
            for name, raw_val in headers.items():
                # httpx stores response headers underscore-cased (set_cookie).
                values = raw_val if isinstance(raw_val, list) else [raw_val]
                for val in values:
                    if not isinstance(val, str):
                        continue
                    for hit in signatures.scan_header_value(val):
                        sink(normalizers.build_finding(
                            endpoint_url=url, http_method="GET",
                            baseurl=ctx["baseurl"], path=ctx["path"],
                            transport="header", location=str(name), hit=hit,
                            encoding_layers=[]))
                    transport = "cookie" if "cookie" in str(name).lower() else "header"
                    _scan_value(val, transport, str(name), ctx, sink)


def _scan_resource_enum(combined_result: dict, roe_excluded: list, sink) -> None:
    """Enumerated endpoints + parameters (names and example values)."""
    by_base = (combined_result.get("resource_enum") or {}).get("by_base_url") or {}
    for base_url, base_data in by_base.items():
        if not isinstance(base_data, dict):
            continue
        if _host_excluded(base_url, roe_excluded):
            continue
        endpoints = base_data.get("endpoints") or {}
        for path, endpoint in endpoints.items():
            if not isinstance(endpoint, dict):
                continue
            method = _endpoint_method(endpoint)
            endpoint_url = base_url.rstrip("/") + "/" + str(path).lstrip("/")
            ctx = {
                "endpoint_url": endpoint_url,
                "http_method": method,
                "baseurl": base_url,
                "path": path,
            }
            for pname, sample_values in _iter_params(endpoint.get("parameters")):
                # A parameter NAMED like a serialization sink (__VIEWSTATE) is a
                # signal even without a value; scan the name too.
                _scan_value(pname, "param", pname, ctx, sink)
                for val in sample_values:
                    _scan_value(val, "param", pname, ctx, sink)


def _endpoint_method(endpoint: dict) -> str:
    """The endpoint's primary HTTP method, uppercased.

    resource_enum stores `methods` (a list, the shape resource_mixin reads);
    partial recon and older/hand-built shapes carry a singular `method`. Both
    are tolerated; default GET.
    """
    methods = endpoint.get("methods") or endpoint.get("method") or "GET"
    if isinstance(methods, str):
        methods = [methods]
    first = methods[0] if methods else "GET"
    return str(first or "GET").upper()


def _iter_params(parameters):
    """Yield (name, [string sample values]) for every enumerated parameter.

    The real recon corpus keys parameters by POSITION, each a list of parameter
    dicts (the shape resource_mixin reads):
        {"query": [{"name": "...", "sample_values": [...], ...}], "body": [...]}
    A flat {name: value | {value/sample_values/...}} shape (partial recon, a
    hand-built fixture) is also tolerated so the scanner never silently reads the
    wrong shape again.
    """
    if not isinstance(parameters, dict):
        return
    for key, val in parameters.items():
        if isinstance(val, list):
            # positional bucket: a list of parameter dicts (or bare name strings)
            for param in val:
                if isinstance(param, dict):
                    name = param.get("name")
                    if not name:
                        continue
                    samples = [s for s in (param.get("sample_values") or []) if isinstance(s, str)]
                    yield str(name), samples
                elif isinstance(param, str) and param:
                    yield param, []
        elif isinstance(val, dict):
            # flat {name: {value/sample_values/...}} shape
            yield str(key), _param_values(val)
        elif isinstance(val, str):
            yield str(key), [val]


def _param_values(pdata: dict) -> list:
    """Pull candidate string values out of a flat-shape parameter record."""
    out: list = []
    for key in ("value", "example", "default", "sample"):
        v = pdata.get(key)
        if isinstance(v, str):
            out.append(v)
    vals = pdata.get("values") or pdata.get("examples") or pdata.get("sample_values")
    if isinstance(vals, list):
        out.extend(v for v in vals if isinstance(v, str))
    return out


def run_serialized_scan(combined_result: dict, settings: dict) -> dict:
    """Scan the in-memory corpus; mutate combined_result in place, return it.

    Guarded by SERIALIZED_SCAN_ENABLED. Never raises: on any error it writes an
    empty result and logs, so a malformed corpus can never fail the pipeline.
    """
    if not settings.get("SERIALIZED_SCAN_ENABLED", False):
        print("[-][SerializedScan] disabled")
        return combined_result

    print("[*][SerializedScan] scanning in-memory corpus for serialized-object signatures")
    findings: list = []
    try:
        roe_excluded = settings.get("ROE_EXCLUDED_HOSTS", []) or []
        if not settings.get("ROE_ENABLED", False):
            roe_excluded = []

        seen: set = set()

        def sink(finding: dict) -> None:
            key = normalizers.dedup_key(finding)
            if key in seen:
                return
            seen.add(key)
            findings.append(finding)

        _scan_http_probe(combined_result, roe_excluded, sink)
        _scan_resource_enum(combined_result, roe_excluded, sink)
    except Exception as e:  # noqa: BLE001 - never-raise contract (plan §5.2)
        print(f"[!][SerializedScan] Error: {e}")
        combined_result["serialized_scan"] = normalizers.build_result([])
        return combined_result

    combined_result["serialized_scan"] = normalizers.build_result(findings)
    if findings:
        print(f"[+][SerializedScan] {len(findings)} serialized-object candidate(s) flagged")
    else:
        print("[-][SerializedScan] no serialized-object signatures found")
    return combined_result


def run_serialized_scan_isolated(combined_result: dict, settings: dict) -> dict:
    """Thread-safe wrapper: deep-copies, runs, returns only this tool's payload.

    The fan-out and test call path (plan §5.2); required even for a sequential
    slot so the module can later join a parallel group without a shared-dict race.
    """
    snapshot = copy.deepcopy(combined_result)
    run_serialized_scan(snapshot, settings)
    return snapshot.get("serialized_scan", {})
