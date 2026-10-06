"""serialized_scan pipeline/lifecycle registration (plan §5.4, §5.6, §14).

Guards the silent-failure layers: a source absent from RECON_FINDING_SOURCES is
never pruned (stale candidates pile up), and a phase absent from
_PHASE_FINDING_SOURCES makes a degraded run report zero sources so the prune
deletes prior-run candidates it should have spared.
"""

import unittest


class TestFindingSourceRegistration(unittest.TestCase):
    def test_source_in_recon_finding_sources(self):
        from recon.helpers.finding_sources import RECON_FINDING_SOURCES
        self.assertIn("serialized_scan", RECON_FINDING_SOURCES)

    def test_phase_finding_sources_entry(self):
        import recon.main as rm
        self.assertEqual(
            rm._PHASE_FINDING_SOURCES.get("serialized_scan"),
            ("serialized_scan",))

    def test_phase_sources_subset_invariant(self):
        import recon.main as rm
        from recon.helpers.finding_sources import RECON_FINDING_SOURCES
        for phase, sources in rm._PHASE_FINDING_SOURCES.items():
            with self.subTest(phase=phase):
                self.assertTrue(set(sources) <= set(RECON_FINDING_SOURCES))


if __name__ == "__main__":
    unittest.main()
