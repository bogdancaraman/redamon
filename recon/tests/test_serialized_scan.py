"""Unit tests for the serialized_scan recon module (plan §5, §14).

Hermetic: no network, no DB. Covers every family signature, the bomb-safe
decoder (depth/size caps), the scanner over a synthetic in-memory corpus, the
_isolated wrapper's no-mutate contract, the never-raise contract, and the
render-safe evidence snippet.
"""

import base64
import copy
import gzip
import unittest

from recon.serialized_scan import (
    decoders,
    normalizers,
    signatures,
    run_serialized_scan,
    run_serialized_scan_isolated,
)


def _latin1(b: bytes) -> str:
    """Carry raw bytes through a str field the way a cookie/param would."""
    return b.decode("latin-1")


class TestFamilySignatures(unittest.TestCase):
    """Each family's representative marker must yield its deser_format (§3)."""

    TEXT_CASES = [
        ("rO0ABXNy", "native_java"),
        ("aced0005cafebabe", "native_java"),
        ('{"@class":"java.util.HashMap"}', "jackson_json"),
        ('{"@type":"com.sun.rowset.JdbcRowSetImpl"}', "fastjson"),
        ('<java version="1.8"><object class="java.lang.Runtime">', "xmldecoder"),
        ("<org.apache.commons.collections.functors.ChainedTransformer>", "xstream"),
        ("!!javax.script.ScriptEngineManager [[!!java.net.URL []]]", "snakeyaml"),
        ('O:4:"User":1:{s:4:"name";s:3:"bob";}', "php_serialize"),
        ("phar:///tmp/evil.phar/x", "phar"),
        ("gASVlAAAAAAAAAB9", "python_pickle"),
        ("gAJ9cQ", "python_pickle"),
        ("AAEAAAD/////AQAAAAAAAAAM", "dotnet_binaryformatter"),
        ("__VIEWSTATE", "viewstate"),
    ]

    BYTE_CASES = [
        (b"\xac\xed\x00\x05sr\x00", "native_java"),
        (b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01", "dotnet_binaryformatter"),
        (b"\x80\x04\x95\x10", "python_pickle"),
        (b"\x80\x02}q\x00", "python_pickle"),
        (b"\x04\x08{\x06", "ruby_marshal"),
    ]

    HEADER_CASES = [
        ("application/x-java-serialized-object", "native_java"),
        ("application/x-hessian", "hessian"),
    ]

    def test_text_signatures(self):
        for value, fmt in self.TEXT_CASES:
            with self.subTest(fmt=fmt, value=value):
                hits = signatures.scan_text(value)
                self.assertIn(fmt, {h["format"] for h in hits})

    def test_byte_signatures(self):
        for raw, fmt in self.BYTE_CASES:
            with self.subTest(fmt=fmt):
                hits = signatures.scan_bytes(raw)
                self.assertIn(fmt, {h["format"] for h in hits})

    def test_header_signatures(self):
        for value, fmt in self.HEADER_CASES:
            with self.subTest(fmt=fmt):
                hits = signatures.scan_header_value(value)
                self.assertIn(fmt, {h["format"] for h in hits})

    def test_benign_text_has_no_hits(self):
        for benign in ("hello world", "id=42&page=3", "application/json",
                       "a normal sentence with class names"):
            with self.subTest(benign=benign):
                self.assertEqual(signatures.scan_text(benign), [])

    def test_benign_bytes_have_no_hits(self):
        self.assertEqual(signatures.scan_bytes(b"ordinary cookie value"), [])


class TestDecoders(unittest.TestCase):
    def test_base64_layer_is_peeled(self):
        inner = b"\xac\xed\x00\x05payload"
        value = base64.b64encode(inner).decode()
        out = decoders.decode_layers(value)
        self.assertIn("base64", out["encoding_chain"])
        # the inner Java stream is reachable on a decoded layer
        self.assertTrue(any(l["raw"].startswith(b"\xac\xed") for l in out["layers"]))

    def test_base64_gzip_double_layer(self):
        inner = b"\xac\xed\x00\x05" + b"X" * 50
        value = base64.b64encode(gzip.compress(inner)).decode()
        out = decoders.decode_layers(value)
        self.assertEqual(out["encoding_chain"][:2], ["base64", "gzip"])
        self.assertFalse(out["truncated"])
        self.assertTrue(any(l["raw"].startswith(b"\xac\xed") for l in out["layers"]))

    def test_decompression_bomb_is_aborted_and_flagged(self):
        """An oversized gzip value is flagged truncated, never expanded (§3.1)."""
        bomb = gzip.compress(b"A" * (3 * 1024 * 1024))  # 3 MiB > 1 MiB cap
        value = _latin1(bomb)
        out = decoders.decode_layers(value)
        self.assertTrue(out["truncated"])
        # only the raw layer survives; the bomb was never decompressed
        self.assertEqual(len(out["layers"]), 1)
        self.assertNotIn("gzip", out["encoding_chain"])
        for layer in out["layers"]:
            self.assertLessEqual(len(layer["raw"]), decoders.MAX_CUMULATIVE_BYTES)

    def test_depth_cap_flags_truncated(self):
        # base64 four times over a still-decodable blob hits the 4-layer cap
        payload = b"\xac\xed\x00\x05" + b"Y" * 40
        wrapped = payload
        for _ in range(6):
            wrapped = base64.b64encode(wrapped)
        out = decoders.decode_layers(wrapped.decode())
        self.assertLessEqual(len(out["encoding_chain"]), decoders.MAX_LAYERS)
        self.assertTrue(out["truncated"])

    def test_empty_and_nonstring(self):
        self.assertEqual(decoders.decode_layers("")["layers"], [])
        self.assertEqual(decoders.decode_layers(None)["layers"], [])


def _corpus():
    """A synthetic in-memory combined_result spanning transports/families."""
    return {
        "metadata": {"user_id": "u1", "project_id": "p1"},
        "http_probe": {
            "by_url": {
                "https://t.example.com/app": {
                    "url": "https://t.example.com/app",
                    "status_code": 200,
                    "content_type": "application/x-java-serialized-object",
                    "headers": {
                        "set_cookie": "sess=rO0ABXNyABByZW1lbWJlck1l; Path=/",
                        "x_powered_by": "ASP.NET",
                    },
                },
                "https://t.example.com/hessian": {
                    "url": "https://t.example.com/hessian",
                    "status_code": 200,
                    "content_type": "application/x-hessian",
                    "headers": {},
                },
            }
        },
        # The REAL recon-corpus shape (the shape resource_mixin reads):
        # endpoints carry `methods` (a list); parameters are keyed by POSITION
        # ("query"/"body"), each a list of param dicts with name + sample_values.
        "resource_enum": {
            "by_base_url": {
                "https://t.example.com": {
                    "endpoints": {
                        "/login": {
                            "methods": ["POST"],
                            "parameters": {
                                "query": [
                                    {"name": "__VIEWSTATE",
                                     "sample_values": ["AAEAAAD/////AQAAAA"]},
                                ],
                                "body": [
                                    {"name": "data",
                                     "sample_values": ['O:4:"User":1:{s:1:"a";i:1;}']},
                                ],
                            },
                        },
                    }
                }
            }
        },
    }


class TestScanner(unittest.TestCase):
    def test_disabled_returns_untouched(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": False})
        self.assertNotIn("serialized_scan", out)

    def test_finds_every_transport(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        findings = out["serialized_scan"]["findings"]
        formats = {f["deser_format"] for f in findings}
        self.assertIn("native_java", formats)       # cookie + header
        self.assertIn("hessian", formats)            # content-type header
        self.assertIn("viewstate", formats)          # param name
        self.assertIn("dotnet_binaryformatter", formats)  # param value
        self.assertIn("php_serialize", formats)      # param value
        transports = {f["deser_transport"] for f in findings}
        self.assertIn("cookie", transports)
        self.assertIn("header", transports)
        self.assertIn("param", transports)

    def test_param_method_comes_from_methods_list(self):
        # F2: endpoints carry `methods` (list); a param candidate must take the
        # real method so its Endpoint attach matches (not a hardcoded GET).
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        param_findings = [f for f in out["serialized_scan"]["findings"]
                          if f["deser_transport"] == "param"]
        self.assertTrue(param_findings)
        self.assertTrue(all(f["http_method"] == "POST" for f in param_findings))

    def test_positional_param_shape_scans_names_and_values(self):
        # F1 regression: the real {"query":[{name,sample_values}]} shape must
        # scan BOTH the parameter name and each sample value.
        cr = {"resource_enum": {"by_base_url": {"https://t": {"endpoints": {
            "/y": {"methods": ["GET"], "parameters": {
                "query": [{"name": "__VIEWSTATE",
                           "sample_values": ["gASVlAAAAAAAAAB9"]}]}}}}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("viewstate", fmts)        # from the param NAME
        self.assertIn("python_pickle", fmts)    # from the sample_value (gASV)

    def test_flat_param_shape_still_handled(self):
        # Partial recon / a hand-built flat {name: {value}} shape is tolerated.
        cr = {"resource_enum": {"by_base_url": {"https://t": {"endpoints": {
            "/x": {"method": "GET",
                   "parameters": {"q": {"value": "rO0ABXNy"}}}}}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)

    def test_string_form_response_headers_are_scanned(self):
        # F3: httpx sometimes stores headers as one CRLF-joined string; the
        # Set-Cookie blob must still be detected, not silently skipped.
        cr = {"http_probe": {"by_url": {"https://t/": {
            "url": "https://t/", "content_type": "text/html",
            "headers": "Set-Cookie: sess=rO0ABXNy; Path=/\nServer: nginx"}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)

    def test_candidate_shape(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        for f in out["serialized_scan"]["findings"]:
            self.assertEqual(f["source"], "serialized_scan")
            self.assertEqual(f["vulnerability_type"], "insecure_deserialization")
            self.assertIs(f["needs_agent_confirmation"], True)
            self.assertEqual(f["severity"], "info")
            self.assertTrue(f["endpoint_url"])
            self.assertIn("deser_language", f)
            self.assertIsInstance(f["deser_encoding_layers"], list)
            # evidence must be flat, printable, bounded
            self.assertLessEqual(len(f["evidence_snippet"]), 120)
            self.assertTrue(all(32 <= ord(c) < 127 for c in f["evidence_snippet"]))

    def test_dedup(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        keys = [normalizers.dedup_key(f) for f in out["serialized_scan"]["findings"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_roe_excludes_host(self):
        cr = _corpus()
        out = run_serialized_scan(cr, {
            "SERIALIZED_SCAN_ENABLED": True,
            "ROE_ENABLED": True,
            "ROE_EXCLUDED_HOSTS": ["t.example.com"],
        })
        self.assertEqual(out["serialized_scan"]["findings"], [])

    def test_no_findings_on_benign_corpus(self):
        cr = {
            "http_probe": {"by_url": {"https://x/": {
                "url": "https://x/", "content_type": "text/html",
                "headers": {"server": "nginx"}}}},
            "resource_enum": {"by_base_url": {"https://x": {"endpoints": {
                "/": {"method": "GET", "parameters": {"q": {"value": "search"}}}}}}},
        }
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        self.assertEqual(out["serialized_scan"]["findings"], [])
        self.assertEqual(out["serialized_scan"]["summary"]["total_findings"], 0)

    def test_never_raises_on_malformed_corpus(self):
        for bad in ({"http_probe": "nope"}, {"resource_enum": 5},
                    {"http_probe": {"by_url": {"u": "notadict"}}}, {}):
            with self.subTest(bad=bad):
                out = run_serialized_scan(dict(bad), {"SERIALIZED_SCAN_ENABLED": True})
                self.assertIn("serialized_scan", out)
                self.assertIn("findings", out["serialized_scan"])

    def test_isolated_wrapper_does_not_mutate(self):
        cr = _corpus()
        snapshot = copy.deepcopy(cr)
        payload = run_serialized_scan_isolated(cr, {"SERIALIZED_SCAN_ENABLED": True})
        self.assertEqual(cr, snapshot)              # input untouched
        self.assertIn("findings", payload)
        self.assertNotIn("serialized_scan", cr)     # not written back onto input

    def test_layered_cookie_is_decoded(self):
        inner = b"\xac\xed\x00\x05" + b"Z" * 30
        blob = base64.b64encode(gzip.compress(inner)).decode()
        cr = {"http_probe": {"by_url": {"https://t/": {
            "url": "https://t/", "content_type": "text/html",
            "headers": {"set_cookie": f"s={blob}"}}}}}
        out = run_serialized_scan(cr, {"SERIALIZED_SCAN_ENABLED": True})
        fmts = {f["deser_format"] for f in out["serialized_scan"]["findings"]}
        self.assertIn("native_java", fmts)
        f = next(f for f in out["serialized_scan"]["findings"]
                 if f["deser_format"] == "native_java")
        self.assertIn("gzip", f["deser_encoding_layers"])


class TestSnippetSafety(unittest.TestCase):
    def test_non_printable_is_hex_escaped(self):
        s = normalizers.safe_snippet(_latin1(b"\xac\xed\x00\x05\x80abc"))
        self.assertTrue(all(32 <= ord(c) < 127 for c in s))
        self.assertIn("\\xac", s)

    def test_length_bounded(self):
        s = normalizers.safe_snippet("A" * 500)
        self.assertLessEqual(len(s), 120)

    def test_backslash_escaped(self):
        self.assertEqual(normalizers.safe_snippet("a\\b"), "a\\\\b")


if __name__ == "__main__":
    unittest.main()
