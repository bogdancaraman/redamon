"""False-positive regressions for Shodan / InternetDB passive CVEs.

A field report muted 174 Shodan CVE rows: IP-keyed catalog correlations with
no service or version, and CVEs on shared Vercel/Cloudflare IPs that belong
to whichever tenant answered there. Each CVE now says what it rests on (a
Shodan-verified banner, a banner's product+version, or the IP's catalog
alone), and a shared CDN/edge IP yields no CVEs, by Shodan's own tags and
attribution as well as our CDN ranges.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

_recon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main_recon_modules")
sys.path.insert(0, _recon_dir)

import shodan_enrich as se  # noqa: E402
from shodan_enrich import (  # noqa: E402
    _extract_passive_cves, _is_shared_edge_host, _run_host_lookup, _service_vulns, drop_cdn_ips,
)

API_HOST = {
    "ip_str": "203.0.113.9",
    "org": "Example Hosting Ltd", "isp": "Example Hosting Ltd", "os": None,
    "country_name": "Ireland", "city": "Dublin",
    "ports": [22, 443],
    "tags": [],
    "vulns": ["CVE-2021-23017", "CVE-2019-11043", "CVE-2014-0160"],
    "data": [
        {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0", "data": "HTTP/1.1 200 OK",
         "_shodan": {"module": "https"},
         "vulns": {
             "CVE-2021-23017": {"cvss": 7.7, "verified": False, "summary": "resolver off-by-one"},
             "CVE-2014-0160": {"cvss": 7.5, "verified": True, "summary": "heartbleed"},
         }},
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "", "data": "SSH-2.0-OpenSSH",
         "_shodan": {"module": "ssh"}},
    ],
}


def _by_cve(cves):
    return {c["cve_id"]: c for c in cves}


class TestServiceVulns(unittest.TestCase):
    def test_parses_shodan_banner_vulns(self):
        vulns = _service_vulns({"CVE-1": {"cvss": "9.8", "verified": True}, "CVE-2": {"cvss": None}, "CVE-3": "x"})
        self.assertEqual(vulns, [
            {"cve_id": "CVE-1", "cvss": 9.8, "verified": True},
            {"cve_id": "CVE-2", "cvss": None, "verified": False},
            {"cve_id": "CVE-3", "cvss": None, "verified": False},
        ])

    def test_missing_or_odd_shapes_are_empty(self):
        for raw in (None, [], "CVE-1", 3):
            self.assertEqual(_service_vulns(raw), [])


class TestHostLookupKeepsEvidence(unittest.TestCase):
    @patch("shodan_enrich._shodan_get")
    @patch("shodan_enrich.time.sleep")
    def test_banner_vulns_and_tags_survive_the_lookup(self, _sleep, mock_get):
        mock_get.return_value = dict(API_HOST, tags=["cloud"])
        [host] = _run_host_lookup(["203.0.113.9"], "k")
        self.assertEqual(host["tags"], ["cloud"])
        https = [s for s in host["services"] if s["port"] == 443][0]
        self.assertEqual({v["cve_id"] for v in https["vulns"]}, {"CVE-2021-23017", "CVE-2014-0160"})


class TestGrading(unittest.TestCase):
    def _cves(self):
        with patch("shodan_enrich._shodan_get", return_value=API_HOST), patch("shodan_enrich.time.sleep"):
            hosts = _run_host_lookup(["203.0.113.9"], "k")
        return _by_cve(_extract_passive_cves(hosts, ["203.0.113.9"], "k"))

    def test_banner_match_carries_port_product_version_and_score(self):
        c = self._cves()["CVE-2021-23017"]
        self.assertEqual((c["port"], c["product"], c["version"], c["cvss"]), (443, "nginx", "1.18.0", 7.7))
        self.assertEqual(c["detection_method"], "passive_version_match")
        self.assertFalse(c["verified"])

    def test_shodan_verified_banner(self):
        c = self._cves()["CVE-2014-0160"]
        self.assertEqual((c["detection_method"], c["verified"]), ("passive_verified", True))

    def test_ip_level_only_cve_is_a_catalog_match(self):
        c = self._cves()["CVE-2019-11043"]
        self.assertEqual(c["detection_method"], "passive_catalog")
        self.assertIsNone(c["port"])
        self.assertIsNone(c["product"])
        self.assertIsNone(c["cvss"])

    def test_each_cve_once_per_ip(self):
        self.assertEqual(len(self._cves()), 3)

    def test_the_best_evidenced_banner_wins_for_a_cve(self):
        hosts = [{"ip": "203.0.113.5", "vulns": ["CVE-Y"], "services": [
            {"port": 8080, "product": "", "version": "", "vulns": [{"cve_id": "CVE-Y", "cvss": None, "verified": False}]},
            {"port": 80, "product": "OpenSSH", "version": "7.4", "vulns": [{"cve_id": "CVE-Y", "cvss": 5.3, "verified": False}]},
            {"port": 443, "product": "OpenSSH", "version": "7.4", "vulns": [{"cve_id": "CVE-Y", "cvss": 5.3, "verified": True}]},
        ]}]
        [c] = _extract_passive_cves(hosts, [], "k")
        self.assertEqual((c["port"], c["detection_method"]), (443, "passive_verified"))

    def test_product_without_version_is_not_a_version_match(self):
        hosts = [{"ip": "203.0.113.5", "vulns": [], "services": [
            {"port": 22, "product": "OpenSSH", "version": "", "vulns": [{"cve_id": "CVE-X", "cvss": 5.0, "verified": False}]},
        ]}]
        [c] = _extract_passive_cves(hosts, [], "k")
        self.assertEqual(c["detection_method"], "passive_catalog")
        self.assertEqual(c["port"], 22)


class TestSharedEdge(unittest.TestCase):
    def test_shodan_cdn_tag(self):
        self.assertTrue(_is_shared_edge_host({"tags": ["cdn"]}))
        self.assertTrue(_is_shared_edge_host({"tags": ["CDN", "cloud"]}))

    def test_edge_provider_attribution(self):
        for org in ("Vercel, Inc", "Cloudflare, Inc.", "Fastly, Inc.", "Netlify", "Amazon CloudFront"):
            self.assertTrue(_is_shared_edge_host({"org": org}), org)

    def test_cloud_hosting_is_not_a_shared_edge(self):
        # A bare EC2/Azure/GCP origin, or a Linode VM now attributed to Akamai,
        # serves the target itself.
        for host in ({"org": "Amazon.com, Inc.", "tags": ["cloud"]}, {"isp": "Microsoft Corporation"},
                     {"org": "Google LLC"}, {"org": "Example Hosting Ltd"}, {},
                     {"org": "Akamai Connected Cloud", "isp": "Akamai Technologies, Inc."},
                     {"org": "G-Core Labs S.A."}, {"org": "StackPath, LLC"}):
            self.assertFalse(_is_shared_edge_host(host), host)

    def test_edge_names_match_as_whole_words(self):
        self.assertFalse(_is_shared_edge_host({"org": "Bunnyhop Networks"}))
        self.assertFalse(_is_shared_edge_host({"org": "Fastlyne Hosting"}))
        self.assertTrue(_is_shared_edge_host({"org": "BunnyWay d.o.o."}))

    def test_akamai_edge_is_recognised_by_shodans_cdn_tag(self):
        self.assertTrue(_is_shared_edge_host({"org": "Akamai Technologies, Inc.", "tags": ["cdn"]}))

    def test_edge_host_yields_no_cves(self):
        hosts = [
            {"ip": "203.0.113.20", "org": "Vercel, Inc", "vulns": ["CVE-2020-11022", "CVE-2020-11023"], "services": []},
            {"ip": "203.0.113.21", "tags": ["cdn"], "vulns": ["CVE-2019-11358"], "services": []},
            {"ip": "203.0.113.22", "org": "Example Hosting Ltd", "vulns": ["CVE-2021-23017"], "services": []},
        ]
        cves = _extract_passive_cves(hosts, [], "k")
        self.assertEqual([(c["cve_id"], c["ip"]) for c in cves], [("CVE-2021-23017", "203.0.113.22")])

    @patch("shodan_enrich._internetdb_get")
    @patch("shodan_enrich.time.sleep")
    def test_internetdb_cdn_tag_yields_no_cves(self, _sleep, mock_idb):
        mock_idb.side_effect = lambda ip: {
            "203.0.113.30": {"vulns": ["CVE-2020-11022"], "tags": ["cdn"], "ports": [443]},
            "203.0.113.31": {"vulns": ["CVE-2021-23017"], "tags": [], "ports": [443]},
        }[ip]
        cves = _extract_passive_cves([], ["203.0.113.30", "203.0.113.31"], "k")
        self.assertEqual([c["ip"] for c in cves], ["203.0.113.31"])
        self.assertEqual(cves[0]["detection_method"], "passive_catalog")

    def test_drop_cdn_ips_uses_shodans_own_attribution(self):
        data = {
            "hosts": [{"ip": "203.0.113.20", "org": "Vercel, Inc"}, {"ip": "203.0.113.22", "org": "Example Hosting Ltd"}],
            "cves": [{"cve_id": "CVE-1", "ip": "203.0.113.20"}, {"cve_id": "CVE-2", "ip": "203.0.113.22"}],
            "reverse_dns": {"203.0.113.20": ["edge.vendor.test"]},
        }
        dropped = drop_cdn_ips(data, {"port_scan": {"by_ip": {}}})
        self.assertEqual(dropped, 1)
        self.assertEqual([h["ip"] for h in data["hosts"]], ["203.0.113.22"])
        self.assertEqual([c["ip"] for c in data["cves"]], ["203.0.113.22"])
        self.assertEqual(data["reverse_dns"], {})


if __name__ == "__main__":
    unittest.main()
