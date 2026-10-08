"""False-positive regressions for origin discovery (CDN bypass).

A field report muted origin findings where the host was not behind a CDN at
all (its public A records were plain cloud hosting, which httpx also flags
as is_cdn), and where the public host and the "origin" answered with the
same deny wall: identical 403 pages scored as a near-perfect HTML match. A
real bypass, the origin serving the application the edge refuses or serves,
must still be reported.

Candidate IPs are public resolver addresses: documentation ranges
(203.0.113.0/24, ...) are dropped by the SSRF filter before any other rule.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from recon.main_recon_modules import origin_discovery as od


def _settings(**over):
    s = {
        "ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_KEYLESS": True,
        "ORIGIN_DISCOVERY_SCANNERS": False, "ORIGIN_DISCOVERY_PASSIVE_DNS": False,
        "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25, "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
        "ORIGIN_DISCOVERY_THRESHOLD": 60, "ORIGIN_DISCOVERY_TIMEOUT": 3,
        "ORIGIN_DISCOVERY_WORKERS": 2, "ORIGIN_DISCOVERY_RATE": 0,
        "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [],
    }
    s.update(over)
    return s


def _probe(host="www.example.com", ip="198.51.100.10", cdn="cloudflare", is_cdn=True):
    return {"http_probe": {"by_url": {f"https://{host}": {
        "host": host, "ip": ip, "is_cdn": is_cdn, "cdn": cdn, "status_code": 200}}}}


DENY = {"text": "Access Denied You don't have permission to access this server", "status": 403,
        "headers": {"server": "nginx"}, "cookies": ""}
APP = {"text": "Example Portal Sign in to your account Forgot password", "status": 200,
       "headers": {"server": "nginx"}, "cookies": "session=1"}


class TestFrontedHosts(unittest.TestCase):
    def test_plain_cloud_hosting_is_not_cdn_fronted(self):
        ctx = od._RunCtx(_settings())
        for cdn in ("azure", "aws", "amazon", "gcp", "digitalocean"):
            with self.subTest(cdn=cdn), patch.object(od, "_resolve_ips", return_value=set()):
                self.assertEqual(od._select_fronted_hosts(_probe(cdn=cdn), ctx), {})

    def test_named_edge_cdns_are_fronted(self):
        ctx = od._RunCtx(_settings())
        # "google" is a CDN label in httpx's cdncheck (Google's LB / Cloud CDN edge).
        for cdn in ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "bunnycdn", "keycdn", "google"):
            with self.subTest(cdn=cdn), patch.object(od, "_resolve_ips", return_value=set()):
                self.assertIn("www.example.com", od._select_fronted_hosts(_probe(cdn=cdn), ctx))

    def test_an_ip_in_a_known_waf_range_is_fronted_whatever_the_label(self):
        ctx = od._RunCtx(_settings())
        with patch.object(od, "_resolve_ips", return_value=set()):
            fronted = od._select_fronted_hosts(_probe(ip="104.16.1.1", cdn=None, is_cdn=False), ctx)
        self.assertIn("www.example.com", fronted)

    def test_a_subdomain_a_person_entered_as_fronted_is_fronted(self):
        ctx = od._RunCtx(_settings())
        combined = _probe(cdn=None)
        combined["http_probe"]["by_url"]["https://www.example.com"]["user_fronted"] = True
        with patch.object(od, "_resolve_ips", return_value=set()):
            self.assertIn("www.example.com", od._select_fronted_hosts(combined, ctx))

    def test_only_live_resolution_counts_not_recorded_dns(self):
        # A partial run's recorded DNS comes from the graph, which keeps the
        # pre-CDN addresses: exactly the origins this tool looks for.
        ctx = od._RunCtx(_settings())
        combined = _probe()
        combined["dns"] = {"subdomains": {"www.example.com": {"ips": {"ipv4": ["149.112.112.112"], "ipv6": []}}}}
        with patch.object(od, "_resolve_ips", return_value={"9.9.9.9"}):
            entry = od._select_fronted_hosts(combined, ctx)["www.example.com"]
        self.assertEqual(entry["resolved_ips"], {"198.51.100.10", "9.9.9.9"})
        meta = {}
        kept = od._dedup_and_filter({"9.9.9.9": "dns", "149.112.112.112": "otx"}, entry, ctx, meta)
        self.assertEqual(kept, [("149.112.112.112", "otx")])
        self.assertEqual(meta["dropped"]["current_resolution"], 1)

    def test_direct_cloud_host_produces_no_finding_end_to_end(self):
        with patch.object(od, "_resolve_ips", return_value=set()), \
             patch.object(od, "_discover_via_subdomains", return_value=["8.8.8.8"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_fetch") as fetch:
            out = od.run_origin_discovery_enrichment_isolated(_probe(cdn="azure"), _settings())
        self.assertEqual(out["confirmed"], [])
        fetch.assert_not_called()


class TestPartialCdnLabel(unittest.TestCase):
    def test_an_edge_label_wins_over_a_cloud_label_for_the_same_host(self):
        import sys
        from unittest.mock import MagicMock
        from recon.partial_recon_modules import origin_enrichment as oe

        rows = [{"root": "example.com", "host": "www.example.com", "favicon": None,
                 "cdns": ["aws", "cloudflare"], "ip": "104.16.1.1"}]
        session = MagicMock()
        session.__enter__.return_value = session
        session.run.return_value = rows
        client = MagicMock()
        client.__enter__.return_value = client
        client.verify_connection.return_value = True
        client.driver.session.return_value = session
        fake_graph_db = MagicMock(Neo4jClient=MagicMock(return_value=client))
        by_url = {}
        with patch.dict(sys.modules, {"graph_db": fake_graph_db}), \
             patch.object(oe, "_root_scope", return_value=(["example.com"], None)), \
             patch.object(oe, "_host_allowed", return_value=True):
            oe._inject_graph_fronted_hosts(by_url, ["example.com"], "u1", "p1")
        self.assertEqual(by_url["https://www.example.com"]["cdn"], "cloudflare")


class TestDenyWalls(unittest.TestCase):
    def _score(self, reference, candidate, cert=0.0):
        ctx = od._RunCtx(_settings())
        with patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
             patch.object(od, "_compare_certs", return_value=cert), \
             patch.object(od, "_fetch", return_value=candidate):
            return od._score_candidate("www.example.com", reference, "8.8.8.8", ctx)

    def test_identical_deny_walls_are_not_a_bypass(self):
        self.assertIsNone(self._score(DENY, DENY))

    def test_identical_deny_walls_with_a_shared_certificate_are_not_a_bypass(self):
        self.assertIsNone(self._score(DENY, DENY, cert=1.0))

    def test_candidate_deny_wall_against_a_live_site_is_not_a_bypass(self):
        self.assertIsNone(self._score(APP, DENY, cert=1.0))

    def test_empty_reference_and_empty_candidate_need_a_certificate(self):
        empty = {"text": "", "status": 200, "headers": {}, "cookies": ""}
        self.assertIsNone(self._score(empty, empty, cert=0.0))
        self.assertIsNotNone(self._score(empty, APP, cert=1.0))

    def test_origin_serving_the_same_application_is_a_bypass(self):
        match = self._score(APP, APP, cert=1.0)
        self.assertIsNotNone(match)
        self.assertEqual(match["status_code"], 200)
        self.assertGreaterEqual(match["confidence_score"], 80)

    def test_a_server_sharing_a_wildcard_certificate_is_not_the_origin(self):
        # The org's mail server presents the same wildcard certificate and 404s
        # at /, while the site serves its app: a certificate alone cannot pick
        # the origin out of the org's servers.
        not_found = {"text": "404 Not Found nginx", "status": 404, "headers": {}, "cookies": ""}
        self.assertIsNone(self._score(APP, not_found, cert=0.5))
        self.assertIsNone(self._score(APP, not_found, cert=1.0))

    def test_a_blocked_edge_and_a_cert_sharing_server_serving_content_is_not_confirmed(self):
        self.assertIsNone(self._score(DENY, APP, cert=1.0))

    def test_api_origin_answering_401_or_404_confirms_on_body_and_certificate_together(self):
        for status in (401, 404):
            api = {"text": '{"error":"not found"}', "status": status, "headers": {}, "cookies": ""}
            ref = {"text": '{"error":"not found"}', "status": status, "headers": {}, "cookies": ""}
            self.assertIsNotNone(self._score(ref, api, cert=0.5), status)
            self.assertIsNone(self._score(ref, api, cert=0.0), status)

    def test_edge_denies_and_the_origin_has_no_matching_certificate(self):
        self.assertIsNone(self._score(DENY, APP, cert=0.0))


class TestSeverityFollowsConfidence(unittest.TestCase):
    def _confirmed(self, score):
        ctx = od._RunCtx(_settings())
        entry = {"favicon_hash": None, "cdn_name": "cloudflare", "edge_ip": "104.16.1.1", "resolved_ips": set()}
        match = {"matched_ip": "8.8.8.8", "port": 443, "method": "host-header", "confidence_score": score,
                 "html_similarity": 90.0, "cert_match": 50.0, "header_match": 100.0, "status_code": 200,
                 "url": "https://8.8.8.8:443"}
        with patch.object(od, "_gather_candidates", return_value={"8.8.8.8": "dns"}), \
             patch.object(od, "_fetch", return_value=APP), \
             patch.object(od, "_score_candidate", return_value=match):
            confirmed, _ = od._process_host("www.example.com", entry, ctx)
        return confirmed[0]

    def test_strong_match_is_high(self):
        self.assertEqual(self._confirmed(92.5)["severity"], "high")

    def test_threshold_match_is_medium(self):
        self.assertEqual(self._confirmed(64.0)["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
