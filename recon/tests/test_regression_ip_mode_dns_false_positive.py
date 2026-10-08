"""An IP-mode scan must not run SPF/DMARC/DNSSEC checks on its synthetic root.

Found by the fix-regression end-to-end run (testing/guinea_pigs/
recon fix-regression lab): an IP-mode project produced a `dmarc_missing` finding
with no domain, IP or host. IP mode names its scan "ip-targets.<project_id>",
a name in no DNS zone, so the DMARC lookup returned nothing and the check
reported the record "missing" for a domain that does not exist.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks as sc  # noqa: E402

PID = "cmur0s0xm000bo501c98xlfn9"


def test_regression_ip_mode_dns_false_positive_full_pipeline():
    # The full pipeline's IP-mode recon_data (main.py run_ip_recon).
    recon = {"domain": f"ip-targets.{PID}",
             "metadata": {"ip_mode": True, "root_domain": f"ip-targets.{PID}"}}
    assert sc._dns_check_domains(recon) == []


def test_regression_ip_mode_dns_false_positive_partial_root():
    # Partial recon carries the synthetic root without the ip_mode flag.
    recon = {"domain": f"ip-targets.{PID}", "domains": [f"ip-targets.{PID}"]}
    assert sc._dns_check_domains(recon) == []


def test_a_real_domain_named_ip_targets_is_still_checked():
    # The shape is the cuid suffix, not the prefix: a real domain keeps its checks.
    for real in ("ip-targets.com", "ip-targets.io", "ip-targets.example.org"):
        assert sc._dns_check_domains({"domain": real}) == [real]


def test_domain_mode_roots_are_unchanged():
    recon = {"domain": "alpha.test", "domains": ["alpha.test", "beta.test"],
             "metadata": {"ip_mode": False}}
    assert sc._dns_check_domains(recon) == ["alpha.test", "beta.test"]


def test_the_ip_mode_run_emits_no_dns_finding(monkeypatch):
    # End to end through the DNS block: nothing is looked up for the placeholder.
    looked_up = []
    monkeypatch.setattr(sc, "run_dns_checks",
                        lambda domain, **kw: looked_up.append(domain) or
                        [{"type": "dmarc_missing", "severity": "medium"}])
    recon = {"domain": f"ip-targets.{PID}", "metadata": {"ip_mode": True},
             "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}}, "subdomains": {}}}
    out = sc.run_security_checks(recon, {"spf_missing": True, "dmarc_missing": True,
                                         "dnssec_missing": True, "zone_transfer": True},
                                 timeout=1)
    assert looked_up == []
    types = [f["type"] for f in out.get("security_checks", {}).get("findings", [])]
    assert "dmarc_missing" not in types
