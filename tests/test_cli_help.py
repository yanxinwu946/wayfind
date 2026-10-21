"""CLI help: -h is compact, -hh shows advanced options."""

import unittest

from typer.testing import CliRunner

from wayfind.cli import app


class CliHelpTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_short_help_hides_advanced(self):
        result = self.runner.invoke(app, ["-h"])
        self.assertEqual(result.exit_code, 0)
        out = result.output
        self.assertIn("Active Directory domain scan", out)
        self.assertIn("--domain", out)
        self.assertIn("--dc-ip", out)
        self.assertIn("--profile", out)
        self.assertIn("-hh", out)
        self.assertNotIn("COMMAND [ARGS]", out)
        self.assertNotIn("--socks", out)
        self.assertNotIn("--bloodhound-options", out)
        self.assertNotIn("--include-ip", out)

    def test_advanced_help_shows_hidden_options(self):
        result = self.runner.invoke(app, ["-hh"])
        self.assertEqual(result.exit_code, 0)
        out = result.output
        self.assertIn("--socks", out)
        self.assertIn("--bloodhound-options", out)
        self.assertIn("--include-ip", out)
        self.assertIn("--as", out)
        self.assertIn("--loot", out)
        self.assertNotIn("COMMAND [ARGS]", out)
