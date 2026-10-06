"""Bomb-safe decode-and-recurse normalizer for the serialized-object scanner.

Every byte handed in here is attacker-controlled (a cookie, a query parameter,
a response header). The normalizer peels transport encodings so the family
signatures (signatures.py) can match the inner blob, but it must never become
the victim: it decodes with the stdlib only (``base64``/``binascii``/``zlib``/
``re``), never a real deserializer, and it refuses to expand a decompression
bomb.

Bounds (plan §3.1):
  * at most ``MAX_LAYERS`` peel steps per value;
  * at most ``MAX_CUMULATIVE_BYTES`` of decompressed output across all layers
    of one value; a gzip/zlib blob that would exceed that is aborted and the
    chain is flagged ``"truncated"`` rather than expanded.
"""

from __future__ import annotations

import binascii
import re
import zlib
from urllib.parse import unquote_to_bytes

try:  # the spawned-container path puts recon/ on sys.path directly
    from recon.helpers.js_recon.patterns import _shannon_entropy
except ImportError:  # pragma: no cover - import shim, exercised only in-container
    from helpers.js_recon.patterns import _shannon_entropy


MAX_LAYERS = 4
MAX_CUMULATIVE_BYTES = 1 * 1024 * 1024  # 1 MiB of decompressed output per value

# A base64 run worth decoding: the canonical serialized/compressed prefixes we
# care about are all >= 8 chars, and decoding short tokens just mints noise.
_MIN_BASE64_LEN = 16
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_HEX_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_URL_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")


class _DecompressionBomb(Exception):
    """A gzip/zlib value whose output would exceed the per-value size cap."""


def _bounded_decompress(raw: bytes, wbits: int) -> bytes:
    """Decompress with a hard output cap. Raises _DecompressionBomb on overflow.

    ``decompressobj(...).decompress(data, max_length)`` returns at most
    ``max_length`` bytes and parks the remaining *compressed* input in
    ``unconsumed_tail``; a non-empty tail (or hitting the cap exactly) means the
    real output is larger than we will ever read, i.e. a bomb.
    """
    obj = zlib.decompressobj(wbits)
    out = obj.decompress(raw, MAX_CUMULATIVE_BYTES)
    if obj.unconsumed_tail or len(out) >= MAX_CUMULATIVE_BYTES:
        raise _DecompressionBomb()
    return out


def _looks_base64(text: str) -> bool:
    """True when ``text`` is a base64 run long and dense enough to be a blob."""
    if len(text) < _MIN_BASE64_LEN or len(text) % 4 != 0:
        return False
    if not _BASE64_RE.match(text):
        return False
    # A serialized/compressed blob carries real entropy; a run of 'AAAA...' or a
    # single repeated word padded to a /4 length is not worth decoding.
    return _shannon_entropy(text) >= 3.5


def _peel_one(text: str, raw: bytes):
    """Return ``(encoding, decoded_bytes)`` for the next layer, or ``None``.

    Tries URL -> gzip -> zlib -> base64 -> hex, firing a decoder only when its
    precondition clearly holds and the output differs from the input. Raises
    _DecompressionBomb if a compressed layer would overflow the size cap.
    """
    # URL-encoding first: it is the only text->text transform and often wraps
    # the base64/hex payload of a cookie or query parameter.
    if _URL_ESCAPE_RE.search(text):
        decoded = unquote_to_bytes(text)
        if decoded and decoded != raw:
            return "url", decoded

    if raw[:2] == b"\x1f\x8b":  # gzip magic
        return "gzip", _bounded_decompress(raw, 16 + zlib.MAX_WBITS)

    if raw[:1] == b"\x78" and raw[1:2] in (b"\x01", b"\x9c", b"\xda"):  # zlib
        return "zlib", _bounded_decompress(raw, zlib.MAX_WBITS)

    stripped = text.strip()
    if _looks_base64(stripped):
        try:
            decoded = binascii.a2b_base64(stripped)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) >= 4 and decoded != raw:
            return "base64", decoded

    if len(stripped) >= 8 and _HEX_RE.match(stripped):
        try:
            decoded = binascii.unhexlify(stripped)
        except (binascii.Error, ValueError):
            decoded = b""
        if len(decoded) >= 4 and decoded != raw:
            return "hex", decoded

    return None


def decode_layers(value: str) -> dict:
    """Peel transport encodings off ``value`` under the §3.1 safety bounds.

    Returns ``{"layers": [{"text", "raw", "encoding"}...], "encoding_chain":
    [str...], "truncated": bool}``. Layer 0 is always the raw value; later
    layers are the bounded decodes. ``truncated`` is True when the depth or size
    cap stopped a peel that otherwise had more to give (including an aborted
    decompression bomb).
    """
    if not isinstance(value, str) or not value:
        return {"layers": [], "encoding_chain": [], "truncated": False}

    seed = value.encode("latin-1", "ignore")
    layers = [{"text": value, "raw": seed, "encoding": "raw"}]
    chain: list[str] = []
    truncated = False
    total = len(seed)
    cur_text, cur_raw = value, seed

    for _ in range(MAX_LAYERS):
        try:
            nxt = _peel_one(cur_text, cur_raw)
        except _DecompressionBomb:
            truncated = True
            break
        if nxt is None:
            break
        encoding, decoded = nxt
        if total + len(decoded) > MAX_CUMULATIVE_BYTES:
            truncated = True
            break
        total += len(decoded)
        cur_text = decoded.decode("latin-1", "ignore")
        cur_raw = decoded
        chain.append(encoding)
        layers.append({"text": cur_text, "raw": cur_raw, "encoding": encoding})
    else:
        # Loop exhausted MAX_LAYERS without breaking: if there is still a layer
        # to peel, we stopped short -> flag it.
        try:
            if _peel_one(cur_text, cur_raw) is not None:
                truncated = True
        except _DecompressionBomb:
            truncated = True

    return {"layers": layers, "encoding_chain": chain, "truncated": truncated}
