"""Serialized-object family signatures (plan §3).

Defensive detection markers only: magic bytes, base64/hex prefixes, structural
JSON/XML/YAML keys, and the two serialization content types. Nothing here
deserializes anything; a signature is a regex over a decoded text layer, a byte
prefix at offset 0 of a decoded layer, or a substring of a response header.

Each match yields a hit dict:
    {format, language, magic, confidence, snippet}

``confidence`` is this detector's belief that *serialization is present* (not
that it is exploitable); it feeds the finding's displayed ``confidence`` only.
The Priority Board's per-source confidence is separate (score_model.py).
"""

from __future__ import annotations

import re

# --- Text signatures: (compiled regex, format, language, magic, confidence) --
# Matched against every decoded text layer. Markers are chosen to be specific
# enough that a hit means "a serialized blob or its wrapper is here".
_TEXT = [
    # Native Java: base64 (rO0AB...) and hex (aced0005) of the AC ED 00 05 header.
    (re.compile(r"rO0AB[A-Za-z0-9+/]"), "native_java", "java", "base64 rO0AB (AC ED 00 05)", 0.85),
    (re.compile(r"(?i)aced0005"), "native_java", "java", "hex aced0005", 0.85),
    # Jackson / json-io / Genson default typing.
    (re.compile(r'"@class"\s*:'), "jackson_json", "java", 'JSON "@class" key', 0.6),
    # FastJSON autotype.
    (re.compile(r'"@type"\s*:'), "fastjson", "java", 'JSON "@type" key', 0.6),
    # XMLDecoder.
    (re.compile(r"<java\s+version="), "xmldecoder", "java", "<java version=", 0.7),
    (re.compile(r"<object\s+class="), "xmldecoder", "java", "<object class=", 0.7),
    (re.compile(r"<void\s"), "xmldecoder", "java", "<void ", 0.55),
    # XStream serializes objects with the FQ class name as the element or a
    # class= attribute; both are distinctive enough to flag at low confidence.
    (re.compile(r"<(?:java|javax|com|org|net|sun)\.[\w.$]+[\s/>]"),
     "xstream", "java", "XStream FQCN element", 0.45),
    (re.compile(r'\bclass="(?:java|javax|com|org|net|sun)\.[\w.$]+"'),
     "xstream", "java", "XStream class= attribute", 0.45),
    # SnakeYAML global tag into a Java package.
    (re.compile(r"!!(?:java|javax|com|org|net|sun)\."),
     "snakeyaml", "java", "SnakeYAML !!<java-pkg> tag", 0.7),
    # PHP serialize() object/array markers and the phar:// stream wrapper.
    (re.compile(r'O:\d+:"'), "php_serialize", "php", 'PHP O:<n>:"', 0.7),
    (re.compile(r"a:\d+:\{"), "php_serialize", "php", "PHP a:<n>:{", 0.6),
    (re.compile(r"phar://"), "phar", "php", "phar:// stream wrapper", 0.75),
    # Python pickle base64 prefixes (proto 2 -> gAJ, proto 4/5 -> gASV), only at the
    # start of a base64 run: a 3-4 character prefix turns up by chance inside a
    # long random run such as a ViewState.
    (re.compile(r"(?<![A-Za-z0-9+/])gASV"), "python_pickle", "python",
     "base64 gASV (pickle proto 4/5)", 0.8),
    (re.compile(r"(?<![A-Za-z0-9+/])gAJ[A-Za-z0-9+/]"), "python_pickle", "python",
     "base64 gAJ (pickle proto 2)", 0.75),
    # .NET BinaryFormatter base64 and the ASP.NET __VIEWSTATE field, whose name is
    # anchored at its end: __VIEWSTATEGENERATOR and __VIEWSTATEENCRYPTED ride beside
    # every ViewState and are not serialized objects.
    (re.compile(r"AAEAAAD/////"), "dotnet_binaryformatter", "dotnet",
     "base64 AAEAAAD///// (BinaryFormatter)", 0.85),
    (re.compile(r"__VIEWSTATE(?![A-Za-z0-9_])"), "viewstate", "dotnet", "__VIEWSTATE field", 0.5),
]

# --- Byte signatures: (prefix, format, language, magic, confidence) ----------
# Matched at offset 0 of a decoded (non-raw) byte layer, or of the raw value's
# latin-1 bytes. The prefixes are the on-the-wire serialization headers.
_BYTES = [
    (b"\xac\xed\x00\x05", "native_java", "java", "AC ED 00 05 (Java stream)", 0.9),
    (b"\x00\x01\x00\x00\x00\xff\xff\xff\xff", "dotnet_binaryformatter", "dotnet",
     "00 01 00 00 00 FF FF FF FF (BinaryFormatter)", 0.9),
    (b"\x80\x05", "python_pickle", "python", "80 05 (pickle proto 5)", 0.75),
    (b"\x80\x04", "python_pickle", "python", "80 04 (pickle proto 4)", 0.75),
    (b"\x80\x03", "python_pickle", "python", "80 03 (pickle proto 3)", 0.7),
    (b"\x80\x02", "python_pickle", "python", "80 02 (pickle proto 2)", 0.7),
    (b"\x04\x08", "ruby_marshal", "ruby", "04 08 (Ruby Marshal)", 0.65),
]

# --- Header-value signatures: (substring, format, language, magic, confidence)
# Matched (case-insensitive) in response header values, chiefly Content-Type.
_HEADER_VALUES = [
    ("application/x-java-serialized-object", "native_java", "java",
     "Content-Type application/x-java-serialized-object", 0.95),
    ("application/x-hessian", "hessian", "java",
     "Content-Type application/x-hessian", 0.9),
]


def scan_text(text: str) -> list[dict]:
    """All family text-signature hits in a single decoded text layer."""
    hits = []
    for regex, fmt, lang, magic, conf in _TEXT:
        m = regex.search(text)
        if m:
            hits.append(_hit(fmt, lang, magic, conf, _around(text, m.start(), m.end())))
    return hits


def scan_bytes(raw: bytes) -> list[dict]:
    """All byte-prefix hits at offset 0 of a decoded byte layer."""
    hits = []
    for prefix, fmt, lang, magic, conf in _BYTES:
        if raw.startswith(prefix):
            hits.append(_hit(fmt, lang, magic, conf, raw[: len(prefix) + 8].hex()))
    return hits


def scan_header_value(value: str) -> list[dict]:
    """Content-type / header serialization hits."""
    low = value.lower()
    hits = []
    for needle, fmt, lang, magic, conf in _HEADER_VALUES:
        if needle in low:
            hits.append(_hit(fmt, lang, magic, conf, value[:120]))
    return hits


def _hit(fmt: str, lang: str, magic: str, conf: float, snippet: str) -> dict:
    return {
        "format": fmt,
        "language": lang,
        "magic": magic,
        "confidence": conf,
        "snippet": snippet,
    }


def _around(text: str, start: int, end: int, radius: int = 40) -> str:
    """A short window around the match for evidence (sanitised later)."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return text[lo:hi]
