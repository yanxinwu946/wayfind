"""Profile membership, categories, and opsec class — shipped functions only."""

import unittest

from wayfind.core.profiles import (
    DEFAULT_PROFILE,
    CATEGORIES,
    checks_for_profile,
    checks_for_category,
    expand_selector,
    included_in,
    opsec_for,
    format_profile_help,
    normalize_profile,
    category_of,
    OPSEC_LDAP,
    OPSEC_HIT_DC,
)


class ProfileTests(unittest.TestCase):
    def test_default_is_audit(self):
        self.assertEqual(DEFAULT_PROFILE, "audit")
        self.assertEqual(checks_for_profile(None), checks_for_profile("audit"))

    def test_anonymous_alias_is_recon(self):
        self.assertEqual(normalize_profile("anonymous"), "recon")
        self.assertEqual(checks_for_profile("anonymous"), checks_for_profile("recon"))

    def test_audit_excludes_offensive(self):
        audit = checks_for_profile("audit")
        self.assertNotIn("dc-vulns", audit)
        self.assertIn("roasting", audit)
        self.assertNotIn("timeroast", audit)
        self.assertFalse(included_in("audit", "dc-vulns"))
        self.assertTrue(included_in("audit", "roasting"))

    def test_recon_is_anonymous_category(self):
        recon = checks_for_profile("recon")
        self.assertEqual(recon, CATEGORIES["anonymous"])
        self.assertIn("timeroast", recon)
        self.assertIn("smb", recon)
        self.assertIn("ldap-anonymous-bind", recon)
        self.assertNotIn("roasting", recon)
        self.assertNotIn("dc-vulns", recon)

    def test_offensive_adds_host_and_probe(self):
        self.assertTrue(included_in("offensive", "roasting"))
        self.assertTrue(included_in("offensive", "dc-vulns"))
        self.assertTrue(included_in("offensive", "timeroast"))
        self.assertIn("roasting", checks_for_profile("offensive"))
        self.assertIn("dc-vulns", checks_for_profile("offensive"))
        self.assertFalse(included_in("recon", "roasting"))
        self.assertTrue(included_in("audit", "roasting"))
        self.assertFalse(included_in("audit", "dc-vulns"))

    def test_outdated_covers_legacy_slices(self):
        audit = checks_for_profile("audit")
        self.assertIn("outdated", audit)
        self.assertNotIn("privileged-accounts", audit)
        self.assertNotIn("legacy", audit)

    def test_opsec_classes(self):
        self.assertEqual(opsec_for("gmsa"), OPSEC_LDAP)
        self.assertEqual(opsec_for("bloodhound"), OPSEC_LDAP)
        self.assertEqual(opsec_for("roasting"), OPSEC_LDAP)
        self.assertEqual(opsec_for("dc-vulns"), OPSEC_HIT_DC)
        self.assertEqual(opsec_for("gpp"), OPSEC_HIT_DC)
        self.assertEqual(opsec_for("timeroast"), OPSEC_HIT_DC)

    def test_help_groups_categories(self):
        text = format_profile_help()
        self.assertIn("audit", text)
        self.assertIn("anonymous", text)
        self.assertIn("Zerologon", text)
        self.assertIn("timeroast", text)
        self.assertLess(text.index("anonymous"), text.index("directory"))
        self.assertLess(text.index("directory"), text.index("host"))
        self.assertLess(text.index("host"), text.index("probe"))


class CategoryTests(unittest.TestCase):
    def test_timeroast_is_anonymous(self):
        self.assertEqual(category_of("timeroast"), "anonymous")
        self.assertIn("timeroast", checks_for_category("anonymous"))

    def test_gpp_is_directory(self):
        self.assertEqual(category_of("gpp"), "directory")
        self.assertIn("gpp", checks_for_category("directory"))

    def test_expand_category(self):
        names = expand_selector("anonymous")
        self.assertEqual(names, CATEGORIES["anonymous"])
        self.assertIn("timeroast", names)

    def test_expand_comma_and_profile(self):
        names = expand_selector("anonymous,dc-vulns")
        self.assertIn("timeroast", names)
        self.assertIn("dc-vulns", names)
        self.assertEqual(expand_selector("recon"), CATEGORIES["anonymous"])

    def test_expand_unknown_with_known(self):
        with self.assertRaises(ValueError):
            expand_selector("not-a-check", known_checks=["gpp"])


if __name__ == "__main__":
    unittest.main()
