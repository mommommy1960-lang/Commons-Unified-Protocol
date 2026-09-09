import unittest
from governance_sim import Scenario, evaluate, monte_carlo

class GovernanceSimTests(unittest.TestCase):
    def test_boring_failure_when_interruption_beats_harm(self):
        o=evaluate(Scenario(name='x', detect_time=1, authorize_time=1, interrupt_time=1, irreversible_harm_time=5))
        self.assertTrue(o.boring_failure)
        self.assertLess(o.maximum_malicious_reach, 100)

    def test_catastrophic_path_when_interruption_too_slow(self):
        o=evaluate(Scenario(name='x', detect_time=2, authorize_time=2, interrupt_time=2, irreversible_harm_time=5))
        self.assertFalse(o.boring_failure)
        self.assertEqual(o.maximum_malicious_reach, 100)

    def test_faster_detection_reduces_mmr(self):
        slow=evaluate(Scenario(name='s', detect_time=3, authorize_time=1, interrupt_time=1, irreversible_harm_time=10, containment_fraction=.9))
        fast=evaluate(Scenario(name='f', detect_time=1, authorize_time=1, interrupt_time=1, irreversible_harm_time=10, containment_fraction=.9))
        self.assertLess(fast.maximum_malicious_reach, slow.maximum_malicious_reach)

    def test_mdb_and_dib_are_separate(self):
        o=evaluate(Scenario(name='x', ordinary_person_burden=7, interruptions_per_year=3, burden_per_interruption=4))
        self.assertEqual(o.minimum_defensive_burden, 7)
        self.assertEqual(o.defensive_interruption_burden, 12)

    def test_essentials_continuity_preserved(self):
        o=evaluate(Scenario(name='x', essentials_continuity=.98))
        self.assertEqual(o.essentials_continuity, .98)

    def test_monte_carlo_is_deterministic_for_seed(self):
        s=Scenario(name='x')
        a=monte_carlo(s, 100, seed=42)
        b=monte_carlo(s, 100, seed=42)
        self.assertEqual(a,b)

    def test_invalid_containment_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(Scenario(name='x', containment_fraction=1.5))

if __name__ == '__main__':
    unittest.main()
