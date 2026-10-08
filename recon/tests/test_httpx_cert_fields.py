"""httpx -tls-grab returns the SAME fingerprint and verdicts tlsx does.

httpx runs the tlsx library for -tls-grab, so its `tls` object already carries
the SHA-256 fingerprint and the expired/self_signed/mismatched/wildcard verdicts.
The parser used to copy seven descriptive fields and drop the rest, which left
`self_signed` permanently UNKNOWN on the five HTTPS ports (so a self-signed cert
on :443 produced no finding while the same cert on :993 did), and forced a
surrogate cert_key for a certificate whose real fingerprint was in the same
payload (so :443 and :993 never converged on one Certificate node).

The payloads below keep the exact field NAMES of a real httpx v1.11.0 record
captured against a TLS lab; that naming is the whole contract.
"""

import json
import os
import tempfile
import unittest

from recon.helpers import security_checks as sc
from recon.helpers.cert_access import _from_httpx
from recon.main_recon_modules.http_probe import parse_httpx_output


def _httpx_line(**tls_overrides):
    """One httpx -tls-grab JSON record, lab cert, synthetic tlslab.test names."""
    tls = {
        "host": "192.88.98.20", "port": "443", "probe_status": True,
        "tls_version": "tls13", "cipher": "TLS_AES_128_GCM_SHA256",
        "self_signed": True, "mismatched": True,
        "not_before": "2026-09-13T09:31:27Z", "not_after": "2027-09-13T09:31:27Z",
        "subject_dn": "O=RedAmon TLS Lab, CN=web.tlslab.test",
        "subject_cn": "web.tlslab.test",
        "subject_org": ["RedAmon TLS Lab"],
        "subject_an": ["web.tlslab.test", "alt.tlslab.test"],
        "serial": "53:F1:91:03:D5:AB:05:39:A4:01:03:3D:74:FB:43:97:8E:E3:1B:0E",
        "issuer_dn": "O=RedAmon TLS Lab, CN=web.tlslab.test",
        "issuer_cn": "web.tlslab.test",
        "issuer_org": ["RedAmon TLS Lab"],
        "fingerprint_hash": {
            "md5": "4a76fed83c22e177c98dd131be15d4bb",
            "sha1": "4b9afb458729e3acb7bc009429ad57a65c7e2e6d",
            "sha256": "69c0426eb1a16a530cab42374a92bd4d671b55ca0f38dc116a15386711bdfba7",
        },
        "tls_connection": "ctls",
    }
    tls.update(tls_overrides)
    return {
        "url": "https://192.88.98.20", "input": "https://192.88.98.20",
        "host": "192.88.98.20", "port": "443", "scheme": "https",
        "status_code": 200, "failed": False, "tls": tls,
    }


def _parse(record):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(record) + "\n")
        return parse_httpx_output(path)
    finally:
        os.unlink(path)


class TestParserKeepsWhatHttpxReturns(unittest.TestCase):

    def setUp(self):
        parsed = _parse(_httpx_line())
        self.entry = parsed["by_url"]["https://192.88.98.20"]
        self.cert = self.entry["tls"]["certificate"]

    def test_sha256_fingerprint_is_kept(self):
        """Without it the graph falls back to a surrogate cert_key and the same
        certificate seen by tlsx on another port becomes a SECOND node."""
        self.assertEqual(
            self.cert["fingerprint_sha256"],
            "69c0426eb1a16a530cab42374a92bd4d671b55ca0f38dc116a15386711bdfba7")

    def test_verdicts_are_kept(self):
        self.assertIs(self.cert["self_signed"], True)
        self.assertIs(self.cert["mismatched"], True)

    def test_tls_version_is_read_from_inside_the_tls_object(self):
        """httpx names it `tls_version` INSIDE `tls`. The parser read `version`
        there and `tls_version` at the TOP level, and neither exists, so the
        version was None on every probe and tls_weak_version could never fire."""
        self.assertEqual(self.entry["tls"]["version"], "tls13")

    def test_issuer_matches_the_tlsx_writers_precedence(self):
        """tlsx_mixin stores `issuer = issuer_dn or issuer_cn`. Both sources now
        converge on ONE node, so a different value here would make the property
        flip depending on which scanner wrote last."""
        self.assertEqual(self.cert["issuer"], "O=RedAmon TLS Lab, CN=web.tlslab.test")

    def test_identifying_detail_is_kept(self):
        self.assertEqual(self.cert["subject_dn"], "O=RedAmon TLS Lab, CN=web.tlslab.test")
        self.assertEqual(self.cert["issuer_cn"], "web.tlslab.test")
        self.assertTrue(self.cert["serial"].startswith("53:F1:91"))


class TestConsumersSurfaceTheVerdicts(unittest.TestCase):

    def test_cert_access_reports_self_signed_instead_of_unknown(self):
        cert = _parse(_httpx_line())["by_url"]["https://192.88.98.20"]["tls"]["certificate"]
        self.assertIs(_from_httpx(cert)["self_signed"], True)

    def test_self_signed_finding_fires_on_an_https_port(self):
        """The regression this whole change exists for: before it, a self-signed
        certificate on :443 produced NO finding."""
        recon = {"http_probe": {"by_url": {
            "https://192.88.98.20": _parse(_httpx_line())["by_url"]["https://192.88.98.20"]}}}
        types = [f["type"] for f in sc.run_tls_data_checks(recon, {"tls_self_signed": True})]
        self.assertIn("tls_self_signed", types)

    def test_wildcard_flag_comes_from_httpx_not_only_from_the_san_shape(self):
        record = _httpx_line(wildcard_certificate=True, subject_cn="*.wild.tlslab.test")
        cert = _parse(record)["by_url"]["https://192.88.98.20"]["tls"]["certificate"]
        self.assertIs(cert["wildcard"], True)


class TestOlderScanDataStillWorks(unittest.TestCase):
    """Results captured before the parser kept the verdicts have no such keys.
    Unknown must stay unknown: collapsing it to False would read as "healthy"
    and silently suppress a real finding."""

    _LEGACY = {
        "subject_cn": "mail.tlslab.test",
        "issuer": "RedAmon TLS Lab",
        "not_after": "2024-02-01T00:00:00Z",
        "san": ["mail.tlslab.test"],
    }

    def test_self_signed_stays_unknown_rather_than_false(self):
        self.assertIsNone(_from_httpx(dict(self._LEGACY))["self_signed"])

    def test_expiry_is_still_derived_from_not_after(self):
        self.assertIs(_from_httpx(dict(self._LEGACY))["expired"], True)

    def test_iter_cert_targets_still_derives_mismatch_and_wildcard(self):
        recon = {"http_probe": {"by_url": {"https://other.tlslab.test": {
            "host": "other.tlslab.test",
            "tls": {"version": "tls12", "certificate": dict(self._LEGACY)},
        }}}}
        _host, _ip, _port, cert = next(iter(sc._iter_cert_targets(recon)))
        self.assertIsNone(cert["self_signed"])
        self.assertIs(cert["mismatched"], True)   # cert names mail., host is other.
        self.assertIs(cert["wildcard"], False)


if __name__ == "__main__":
    unittest.main()
