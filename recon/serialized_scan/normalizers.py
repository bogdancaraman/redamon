"""Shape serialized-scan hits into ``combined_result["serialized_scan"]``.

One finding per sink and format: (endpoint, transport, location, format). Each
maps to a :Vulnerability candidate downstream (serialized_mixin.py).
"""

from __future__ import annotations

VULNERABILITY_TYPE = "insecure_deserialization"
SOURCE = "serialized_scan"

# evidence_snippet is attacker-controlled text that lands in the NodeDrawer and
# can reach the HTML report; store printable-ASCII only, hex-escaped, bounded.
_SNIPPET_MAX = 120


def safe_snippet(raw, limit: int = _SNIPPET_MAX) -> str:
    """Printable-ASCII, hex-escaped, <= `limit` chars. Never raw decoded bytes."""
    if raw is None:
        return ""
    text = raw if isinstance(raw, str) else str(raw)
    out = []
    for ch in text:
        o = ord(ch)
        if 32 <= o < 127 and ch != "\\":
            out.append(ch)
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(f"\\x{o & 0xFF:02x}")
        if len(out) >= limit:
            break
    return "".join(out)[:limit]


def build_finding(
    *,
    endpoint_url: str,
    http_method: str,
    baseurl: str,
    path: str,
    transport: str,
    location: str,
    hit: dict,
    encoding_layers: list,
) -> dict:
    """Assemble one candidate finding from a signature hit (plan §5.3)."""
    return {
        "endpoint_url": endpoint_url,
        "http_method": http_method,
        "baseurl": baseurl,
        "path": path,
        "confidence": round(float(hit.get("confidence", 0.4)), 3),
        "source": SOURCE,
        "vulnerability_type": VULNERABILITY_TYPE,
        "needs_agent_confirmation": True,
        "severity": "info",
        "deser_language": hit.get("language", ""),
        "deser_format": hit.get("format", ""),
        "deser_transport": transport,
        "deser_location": location,
        "deser_encoding_layers": list(encoding_layers),
        "deser_magic": hit.get("magic", ""),
        "evidence_snippet": safe_snippet(hit.get("snippet", "")),
    }


def dedup_key(finding: dict) -> tuple:
    """Within-run uniqueness: one candidate per sink and format.

    The matched marker (deser_magic) is evidence, not identity: one sink seen as
    base64 in one sample and gzip in another, or as a PHP object one run and an
    array the next, is still one sink.
    """
    return (
        finding.get("endpoint_url", ""),
        finding.get("deser_transport", ""),
        finding.get("deser_location", ""),
        finding.get("deser_format", ""),
    )


def build_result(findings: list) -> dict:
    """The ``combined_result["serialized_scan"]`` payload."""
    by_format: dict = {}
    by_language: dict = {}
    by_transport: dict = {}
    truncated = 0
    for f in findings:
        by_format[f["deser_format"]] = by_format.get(f["deser_format"], 0) + 1
        by_language[f["deser_language"]] = by_language.get(f["deser_language"], 0) + 1
        by_transport[f["deser_transport"]] = by_transport.get(f["deser_transport"], 0) + 1
        if "truncated" in (f.get("deser_encoding_layers") or []):
            truncated += 1
    return {
        "summary": {
            "total_findings": len(findings),
            "by_format": by_format,
            "by_language": by_language,
            "by_transport": by_transport,
            "truncated_values": truncated,
        },
        "findings": findings,
    }
