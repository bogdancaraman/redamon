"""False-positive regressions for subdomain takeover.

A field report muted takeover findings on hosts that were live first-party,
Akamai and Azure services, and one where a generic body fingerprint named an
uptime-monitor SaaS on a host whose CNAME pointed at a mail provider. The
provider check knows those providers' CNAME suffixes, and a host that served
a normal 2xx page is demoted, or dropped as an active resource.
A dangling CNAME (NXDOMAIN) keeps its score.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import takeover_helpers as th
from recon.main_recon_modules import subdomain_takeover as runner

SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "SUBJACK_ENABLED": True,
    "NUCLEI_TAKEOVERS_ENABLED": True,
    "BADDNS_ENABLED": False,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": True,
    "TAKEOVER_CERT_VALIDATION_ENABLED": False,
    "TAKEOVER_CONFIDENCE_THRESHOLD": 60,
}


def _cert(host, *, names_host=True):
    """An http_probe certificate: the customer's own, or a SaaS default one."""
    return {"subject_cn": host if names_host else "*.saas-default.test",
            "san": [host] if names_host else ["*.saas-default.test"],
            "issuer": ["Example CA"], "expired": False, "self_signed": False, "mismatched": False}


def _run(monkeypatch, host, cname, *, subjack_service=None, nuclei_template=None,
         status=None, resolves=True, nxdomain=False, cert=None, **settings):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: (
        [{"subdomain": host, "vulnerable": True, "service": subjack_service}] if subjack_service else []))
    monkeypatch.setattr(runner, "_run_nuclei_takeover", lambda urls, work_dir, settings: (
        [{"template-id": nuclei_template, "matched-at": f"https://{host}/",
          "info": {"name": nuclei_template, "severity": "high", "tags": ["takeover"]}}]
        if nuclei_template else []))
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target",
                        lambda c, timeout=3.0: {"resolves": resolves, "ips": ("203.0.113.5",) if resolves else (),
                                                "nxdomain": nxdomain})
    probe = {"status_code": status, "host": host}
    if cert:
        probe["tls"] = {"certificate": cert}
    recon = {
        "domain": "example.com",
        "dns": {"subdomains": {host: {"records": {"CNAME": f"{cname}."}}}},
        "http_probe": {"by_url": {f"https://{host}": probe}} if status else {},
    }
    out = runner.run_subdomain_takeover(recon, settings={
        **SETTINGS, "TAKEOVER_CERT_VALIDATION_ENABLED": bool(cert), **settings})
    return out["subdomain_takeover"]


class TestProviderHelpers:
    def test_provider_families(self):
        assert th.same_provider_family("azure", "azure-app-service")
        assert th.same_provider_family("azure-app-service", "azure")
        assert th.same_provider_family("heroku", "heroku")
        assert not th.same_provider_family("aws-s3", "aws-cloudfront")
        assert not th.same_provider_family("uptimerobot", "mailgun")
        assert not th.same_provider_family("", "heroku")

    def test_new_cname_providers(self):
        assert th.provider_from_cname("mailgun.org") == "mailgun"
        assert th.provider_from_cname("stats.uptimerobot.com") == "uptimerobot"
        assert th.provider_from_cname("www.example.com.edgekey.net") == "akamai"
        assert th.provider_from_cname("app-x.azurefd.net") == "azure-front-door"

    def test_score_live_host_penalty(self):
        base = {"sources": ["subjack", "nuclei_takeover"], "takeover_provider": "heroku", "takeover_method": "cname"}
        plain = th.score_finding(dict(base))["confidence"]
        live = th.score_finding(dict(base, host_answers_2xx=True))["confidence"]
        dangling = th.score_finding(dict(base, host_answers_2xx=True, cname_nxdomain=True))["confidence"]
        assert live == plain - 30
        assert dangling == plain


class TestFieldReportCases:
    def test_generic_fingerprint_on_a_mail_provider_cname(self, monkeypatch):
        [f] = _run(monkeypatch, "email.example.com", "mailgun.org",
                   subjack_service="uptimerobot", status=None)["findings"]
        assert f["provider_mismatch"] is True
        assert f["cname_provider"] == "mailgun"
        assert f["verdict"] == "manual_review"
        assert f["severity"] == "info"

    def test_a_cname_the_table_does_not_know_is_not_a_mismatch(self, monkeypatch):
        # The suffix table is incomplete (a regional S3 endpoint here), so an
        # unknown CNAME must not demote a real dangling bucket.
        [f] = _run(monkeypatch, "assets.example.com", "example-assets.s3.eu-west-1.amazonaws.com",
                   nuclei_template="aws-bucket-takeover", status=404, resolves=False, nxdomain=True)["findings"]
        assert not f.get("provider_mismatch")

    def test_live_akamai_service_is_an_active_resource_not_a_finding(self, monkeypatch):
        out = _run(monkeypatch, "www.example.com", "www.example.com.edgekey.net",
                   subjack_service="akamai", nuclei_template="akamai-takeover", status=200,
                   cert=_cert("www.example.com"))
        assert out["findings"] == []
        assert [a["hostname"] for a in out["active_resources"]] == ["www.example.com"]
        assert out["summary"]["active_resources"] == 1

    def test_live_azure_app_service_is_an_active_resource(self, monkeypatch):
        out = _run(monkeypatch, "portal.example.com", "example-portal.azurewebsites.net",
                   subjack_service="azure", status=200, cert=_cert("portal.example.com"))
        assert out["findings"] == []
        assert [a["hostname"] for a in out["active_resources"]] == ["portal.example.com"]

    def test_a_live_page_without_a_certificate_for_the_host_stays_reported(self, monkeypatch):
        # Some SaaS answer an unclaimed name with a 200 page, never with a
        # valid certificate for the customer's name.
        out = _run(monkeypatch, "book.example.com", "example.saas-default.test",
                   nuclei_template="saas-takeover", status=200,
                   cert=_cert("book.example.com", names_host=False))
        assert [f["hostname"] for f in out["findings"]] == ["book.example.com"]
        assert out["active_resources"] == []

    def test_without_certificate_data_nothing_is_dropped(self, monkeypatch):
        # Partial runs carry no certificate data and may carry a stale status.
        out = _run(monkeypatch, "www.example.com", "www.example.com.edgekey.net",
                   subjack_service="akamai", status=200)
        assert len(out["findings"]) == 1
        assert out["active_resources"] == []

    def test_auto_publish_keeps_every_candidate(self, monkeypatch):
        out = _run(monkeypatch, "www.example.com", "www.example.com.edgekey.net",
                   subjack_service="akamai", status=200, cert=_cert("www.example.com"),
                   TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH=True)
        assert len(out["findings"]) == 1
        assert out["findings"][0]["severity"] == "medium"

    def test_dns_level_takeovers_are_never_active_resources(self):
        # A dangling MX/SPF/TXT/NS record is about DNS, not the web page.
        for method in ("mx", "spf", "txt", "ns", "dns"):
            finding = {"verdict": "manual_review", "takeover_method": method, "cname_target": "x.test",
                       "cname_alive": True, "host_answers_2xx": True, "cert_name_match": True}
            assert runner._is_active_resource(finding) is False, method

    def test_live_auto_exploitable_provider_is_demoted_but_kept_when_tools_agree(self, monkeypatch):
        # Two tools on an auto-exploitable provider outweigh one 2xx: demoted,
        # still reported for a person to check.
        out = _run(monkeypatch, "docs.example.com", "example.github.io",
                   subjack_service="github", nuclei_template="github-takeover", status=200)
        [f] = out["findings"]
        assert f["host_answers_2xx"] is True
        assert f["confidence"] == 100 - 30
        assert out["active_resources"] == []

    def test_mismatch_without_a_live_page_stays_reported(self, monkeypatch):
        # Not proven active: a candidate is never dropped on a mismatch alone.
        out = _run(monkeypatch, "email.example.com", "mailgun.org", subjack_service="uptimerobot")
        assert len(out["findings"]) == 1
        assert out["active_resources"] == []


class TestRealTakeoversStillReport:
    def test_dangling_heroku_cname(self, monkeypatch):
        [f] = _run(monkeypatch, "shop.example.com", "example-shop.herokuapp.com",
                   subjack_service="heroku", nuclei_template="heroku-takeover",
                   status=404, resolves=False, nxdomain=True)["findings"]
        assert not f.get("provider_mismatch")
        assert not f.get("host_answers_2xx")
        assert f["verdict"] == "confirmed"

    def test_nxdomain_outweighs_a_stale_2xx(self, monkeypatch):
        [f] = _run(monkeypatch, "shop.example.com", "example-shop.herokuapp.com",
                   subjack_service="heroku", nuclei_template="heroku-takeover",
                   status=200, resolves=False, nxdomain=True)["findings"]
        assert f["verdict"] == "confirmed"

    def test_unclaimed_azure_app_service_answers_404(self, monkeypatch):
        [f] = _run(monkeypatch, "old.example.com", "example-old.azurewebsites.net",
                   subjack_service="azure", nuclei_template="azure-takeover-detection",
                   status=404, resolves=False, nxdomain=True)["findings"]
        assert not f.get("provider_mismatch")
        assert f["verdict"] in ("confirmed", "likely")
