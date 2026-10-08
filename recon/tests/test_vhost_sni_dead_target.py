"""Mid-run target death on the vhost/SNI enumerator (vhost_sni_enum.py).

The fan-in loop used to `continue` silently on every None, so a target that
died after the baseline made the pipeline probe its whole wordlist against a
dead port. Now a run of Nones re-asks the per-port baseline; only a dead
baseline stops the port and lists the IP:port so the prune keeps its findings.

A quiet-but-live port (a small vhost set that legitimately 404s) must NOT be
mistaken for a dead one: the baseline re-probe is what tells them apart.
"""
from __future__ import annotations

from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import vhost_sni_enum as v

LIVE = {"status": 200, "size": 100, "body_hash": "live"}


class _Probe:
    """A stand-in for _curl_probe. A baseline call (host_header and
    sni_hostname both None) is alive the first time; afterwards it is alive
    only when `revive` is set. Every candidate/control probe is dead (None)."""

    def __init__(self, revive: bool):
        self.revive = revive
        self.baseline_calls = 0
        self.candidate_calls = 0
        self.control_calls = 0

    def __call__(self, *args, **kwargs):
        if kwargs:
            host_header = kwargs.get("host_header")
            sni = kwargs.get("sni_hostname")
        else:  # _curl_probe(scheme, host_header, sni_hostname, target, port, timeout)
            host_header, sni = args[1], args[2]
        if host_header is None and sni is None:
            self.baseline_calls += 1
            if self.baseline_calls == 1:
                return dict(LIVE)
            return dict(LIVE) if self.revive else None
        # Calibration probes use bogus "vhostsni-ctrl-*" hostnames (under the
        # apex and under .invalid); keep them apart from the real wordlist
        # candidates the streak logic counts.
        if str(host_header or sni or "").startswith(v._CONTROL_LABEL_PREFIX):
            self.control_calls += 1
        else:
            self.candidate_calls += 1
        return None


def _probe_one(ip="1.2.3.4", ports=None, probe=None, concurrency=1):
    # concurrency=1 makes the completion order match submission order, so the
    # streak crosses _DEAD_STREAK deterministically.
    with mock.patch.object(v, "_curl_probe", probe):
        return v._probe_single_ip(
            ip=ip,
            ports=ports or [{"port": 80, "protocol": "tcp", "scheme": "http"}],
            apex_domain="example.test",
            default_prefixes=[],
            custom_lines=[f"c{i}" for i in range(20)],
            graph_candidates=[],
            test_l7=True,
            test_l4=False,
            timeout=1,
            concurrency=concurrency,
            size_tolerance=50,
            max_candidates=2000,
        )


def test_a_port_that_dies_mid_run_is_stopped_and_listed():
    probe = _Probe(revive=False)
    out = _probe_one(probe=probe)
    assert out.get("unreachable_ports") == ["1.2.3.4:80"]
    # Initial baseline + exactly one re-probe (dead -> the loop breaks). A
    # second re-probe would mean the break never fired. (Cancelling the
    # in-flight futures is best-effort and saves real time only against slow
    # network probes, not instant mocks, so candidate_calls is not asserted.)
    assert probe.baseline_calls == 2


def test_a_quiet_but_live_port_is_not_marked_dead():
    probe = _Probe(revive=True)
    out = _probe_one(probe=probe)
    assert "unreachable_ports" not in out
    # Every candidate was probed; the streak reset on each live re-probe.
    assert probe.candidate_calls == 20
    assert probe.baseline_calls >= 2


def test_the_off_switch_never_re_probes_or_stops(monkeypatch):
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    probe = _Probe(revive=False)
    out = _probe_one(probe=probe)
    assert "unreachable_ports" not in out
    assert probe.baseline_calls == 1  # only the initial baseline, no re-probe
    assert probe.candidate_calls == 20


def test_a_port_another_module_found_down_is_skipped_before_any_probe():
    for _ in range(3):
        cb.host_health.record_failure("http://1.2.3.4:80", requests.ConnectionError("x"))
    probe = _Probe(revive=True)
    out = _probe_one(probe=probe)
    assert out.get("unreachable_ports") == ["1.2.3.4:80"]
    assert probe.baseline_calls == 0
    assert probe.candidate_calls == 0


def test_an_ipv6_dead_port_key_is_bracketed():
    for _ in range(3):
        cb.host_health.record_failure("http://[dead::1]:80", requests.ConnectionError("x"))
    probe = _Probe(revive=True)
    out = _probe_one(ip="dead::1", probe=probe)
    assert out.get("unreachable_ports") == ["[dead::1]:80"]


class TestRunLevelReporting:
    def _combined(self):
        return {
            "domain": "example.test",
            "port_scan": {"by_host": {"1.2.3.4": {
                "ip": "1.2.3.4",
                "ports": [{"port": 80, "scheme": "http"}],
            }}},
        }

    def _settings(self):
        return {
            "VHOST_SNI_ENABLED": True,
            "VHOST_SNI_USE_DEFAULT_WORDLIST": False,
            "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
            "VHOST_SNI_INJECT_DISCOVERED": False,
        }

    def test_dead_ports_reach_the_payload_and_the_coverage_report(self):
        dead_ip_result = {
            "unreachable_ports": ["1.2.3.4:80"],
            "anomalies": [],
            "candidates_tested": 10,
        }
        with mock.patch.object(v, "_is_curl_available", return_value=True), \
             mock.patch.object(v, "_probe_single_ip", return_value=dead_ip_result):
            out = v.run_vhost_sni_enrichment(self._combined(), self._settings())
        payload = out["vhost_sni"]
        assert "1.2.3.4:80" in payload.get("unreachable_hosts", [])
        report = cb.coverage_report()
        assert "1.2.3.4" in report.skipped_hosts or "1.2.3.4:80" in report.skipped_hosts

    def test_a_clean_run_has_no_unreachable_hosts_key(self):
        clean = {"unreachable_ports": [], "anomalies": [], "candidates_tested": 10}
        with mock.patch.object(v, "_is_curl_available", return_value=True), \
             mock.patch.object(v, "_probe_single_ip", return_value=clean):
            out = v.run_vhost_sni_enrichment(self._combined(), self._settings())
        assert "unreachable_hosts" not in out["vhost_sni"]
        assert "degraded" not in out["vhost_sni"]
