"""Skew gate: shipped kerberos_should_skip."""

import unittest

from wayfind.utils.clock import kerberos_should_skip, SKEW_WARN_SECONDS


class ClockGateTests(unittest.TestCase):
    def test_over_five_minutes_skips_and_names_ntpdate(self):
        skip, msg = kerberos_should_skip(13 * 3600, "10.0.0.10")
        self.assertTrue(skip)
        self.assertIn("ntpdate 10.0.0.10", msg)
        self.assertIn("Kerberos", msg)

    def test_under_five_minutes_does_not_skip(self):
        skip, msg = kerberos_should_skip(60.0, "10.0.0.10")
        self.assertFalse(skip)
        self.assertEqual(msg, "")

    def test_exactly_boundary(self):
        skip, _ = kerberos_should_skip(float(SKEW_WARN_SECONDS), "dc")
        self.assertFalse(skip)
        skip, _ = kerberos_should_skip(float(SKEW_WARN_SECONDS) + 1, "dc")
        self.assertTrue(skip)

    def test_unknown_offset_does_not_skip(self):
        skip, msg = kerberos_should_skip(None, "10.0.0.10")
        self.assertFalse(skip)
        self.assertEqual(msg, "")


if __name__ == "__main__":
    unittest.main()
