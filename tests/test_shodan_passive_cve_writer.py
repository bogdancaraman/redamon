"""The Shodan passive-CVE graph write.

Rows were written ON CREATE only, with nothing but the CVE id: no severity,
no port, no product, no version and no way to tell a banner match from an
IP-catalog correlation, and a rescan never refreshed them. Each row now
carries its evidence grade, a CVSS-derived severity when Shodan gave a score,
and hangs off its Service when the banner named one.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin, _cvss_severity, _shodan_cve_props  # noqa: E402


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _write(cves):
    w = _Writer()
    w.update_graph_from_shodan({"domain": "example.com", "domains": ["example.com"],
                                "shodan": {"hosts": [], "cves": cves}}, "u1", "p1")
    return w.session.calls


BANNER = {"cve_id": "CVE-2021-23017", "ip": "203.0.113.9", "source": "shodan_api", "port": 443,
          "product": "nginx", "version": "1.18.0", "cvss": 7.7, "verified": False,
          "detection_method": "passive_version_match"}
CATALOG = {"cve_id": "CVE-2019-11043", "ip": "203.0.113.9", "source": "internetdb",
           "detection_method": "passive_catalog"}


class TestCvssSeverity(unittest.TestCase):
    def test_bands(self):
        self.assertEqual([_cvss_severity(s) for s in (9.8, 9.0, 7.7, 4.0, 3.9, 0.1)],
                         ["critical", "critical", "high", "medium", "low", "low"])

    def test_no_score_no_severity(self):
        for s in (None, "", "n/a", 0, 0.0):
            self.assertIsNone(_cvss_severity(s), s)


class TestProps(unittest.TestCase):
    def test_banner_match_carries_its_evidence(self):
        p = _shodan_cve_props(BANNER)
        self.assertEqual(p["detection_method"], "passive_version_match")
        self.assertEqual((p["target_ip"], p["target_port"], p["product"], p["version"]),
                         ("203.0.113.9", 443, "nginx", "1.18.0"))
        self.assertEqual((p["cvss_score"], p["severity"], p["verified"]), (7.7, "high", False))
        self.assertEqual((p["name"], p["cves"]), ("CVE-2021-23017", ["CVE-2021-23017"]))

    def test_catalog_match_has_no_invented_severity(self):
        p = _shodan_cve_props(CATALOG)
        self.assertEqual(p["detection_method"], "passive_catalog")
        self.assertIsNone(p["severity"])
        self.assertIsNone(p["target_port"])
        self.assertIsNone(p["product"])

    def test_entry_from_an_older_payload_is_a_catalog_match(self):
        self.assertEqual(_shodan_cve_props({"cve_id": "CVE-1", "ip": "203.0.113.1"})["detection_method"],
                         "passive_catalog")

    def test_props_are_flat(self):
        for p in (_shodan_cve_props(BANNER), _shodan_cve_props(CATALOG)):
            for k, v in p.items():
                self.assertNotIsInstance(v, dict, k)


class TestWrite(unittest.TestCase):
    def test_vulnerability_is_refreshed_not_create_only(self):
        calls = _write([BANNER])
        [(q, params)] = [(q, p) for q, p in calls if "MERGE (v:Vulnerability" in q]
        self.assertIn("SET v += $props", q)
        self.assertIn("ON CREATE SET v.source = $source", q)
        self.assertIn("user_id: $user_id", q)
        self.assertIn("project_id: $project_id", q)
        self.assertEqual(params["props"]["detection_method"], "passive_version_match")
        self.assertEqual(params["vuln_id"], "shodan-CVE-2021-23017-203.0.113.9")

    def test_banner_cve_hangs_off_its_service(self):
        calls = _write([BANNER])
        links = [p for q, p in calls if "MATCH (svc:Service" in q and "HAS_VULNERABILITY" in q]
        self.assertEqual(len(links), 1)
        self.assertEqual((links[0]["product"], links[0]["port"], links[0]["ip"]), ("nginx", 443, "203.0.113.9"))

    def test_catalog_cve_has_no_service_link(self):
        calls = _write([CATALOG])
        self.assertFalse(any("MATCH (svc:Service" in q for q, _ in calls))
        self.assertTrue(any("MERGE (i)-[:HAS_VULNERABILITY]->(v)" in q for q, _ in calls))


if __name__ == "__main__":
    unittest.main()
