#!/usr/bin/env python3
"""Unit tests for TattleTale"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path to import tattletale
sys.path.insert(0, str(Path(__file__).parent.parent))

from tattletale import (
    Credential,
    parse_dit_file,
    parse_pot_file,
    parse_target_file,
    NULL_LM,
    NULL_NT,
)


class TestCredential(unittest.TestCase):
    """Test Credential dataclass"""

    def test_hash_property_prefers_nt(self):
        cred = Credential(
            down_level_logon_name="DOMAIN\\user",
            lm_hash="e52cac67419a9a224a3b108f3fa6cb6d",
            nt_hash="8846f7eaee8fb117ad06bdd830b7586c",
        )
        self.assertEqual(cred.hash, "8846f7eaee8fb117ad06bdd830b7586c")

    def test_hash_property_falls_back_to_lm(self):
        cred = Credential(
            down_level_logon_name="DOMAIN\\user",
            lm_hash="e52cac67419a9a224a3b108f3fa6cb6d",
            nt_hash=NULL_NT,
        )
        self.assertEqual(cred.hash, "e52cac67419a9a224a3b108f3fa6cb6d")

    def test_hash_property_empty_when_null(self):
        cred = Credential(
            down_level_logon_name="DOMAIN\\user",
            lm_hash=NULL_LM,
            nt_hash=NULL_NT,
        )
        self.assertEqual(cred.hash, "")

    def test_is_machine_detection(self):
        machine = Credential(down_level_logon_name="DOMAIN\\SERVER$")
        machine.is_machine = machine.down_level_logon_name.endswith("$")
        self.assertTrue(machine.is_machine)

        user = Credential(down_level_logon_name="DOMAIN\\user")
        user.is_machine = user.down_level_logon_name.endswith("$")
        self.assertFalse(user.is_machine)


class TestParseDitFile(unittest.TestCase):
    """Test DIT file parsing"""

    def setUp(self):
        self.sample_dit = Path(__file__).parent.parent / "examples" / "sample.dit"

    def test_parse_dit_file(self):
        creds = parse_dit_file(self.sample_dit)
        self.assertGreater(len(creds), 0)

    def test_parses_domain_and_username(self):
        creds = parse_dit_file(self.sample_dit)
        admin = next(c for c in creds if "Administrator" in c.down_level_logon_name)
        self.assertEqual(admin.domain, "CONTOSO")
        self.assertEqual(admin.sam_account_name, "Administrator")

    def test_detects_machine_accounts(self):
        creds = parse_dit_file(self.sample_dit)
        machines = [c for c in creds if c.is_machine]
        self.assertGreater(len(machines), 0)
        for m in machines:
            self.assertTrue(m.down_level_logon_name.endswith("$"))

    def test_detects_null_passwords(self):
        creds = parse_dit_file(self.sample_dit)
        null_creds = [c for c in creds if c.is_null]
        self.assertGreater(len(null_creds), 0)

    def test_skips_comments_and_empty_lines(self):
        creds = parse_dit_file(self.sample_dit)
        for cred in creds:
            self.assertFalse(cred.down_level_logon_name.startswith("#"))


class TestParsePotFile(unittest.TestCase):
    """Test potfile parsing"""

    def setUp(self):
        self.sample_pot = Path(__file__).parent.parent / "examples" / "sample.pot"

    def test_parse_pot_file(self):
        hashes = parse_pot_file(self.sample_pot)
        self.assertGreater(len(hashes), 0)

    def test_hash_to_cleartext_mapping(self):
        hashes = parse_pot_file(self.sample_pot)
        # Real NT hash for "Password1"
        self.assertIn("64f12cddaa88057e06a81b54e73b949b", hashes)
        self.assertEqual(hashes["64f12cddaa88057e06a81b54e73b949b"], "Password1")

    def test_hashes_are_lowercase(self):
        hashes = parse_pot_file(self.sample_pot)
        for h in hashes.keys():
            self.assertEqual(h, h.lower())


class TestParseTargetFile(unittest.TestCase):
    """Test target file parsing"""

    def setUp(self):
        self.sample_targets = Path(__file__).parent.parent / "examples" / "targets.txt"

    def test_parse_target_file(self):
        targets = parse_target_file(self.sample_targets)
        self.assertGreater(len(targets), 0)

    def test_targets_are_lowercase(self):
        targets = parse_target_file(self.sample_targets)
        for t in targets:
            self.assertEqual(t, t.lower())

    def test_contains_expected_targets(self):
        targets = parse_target_file(self.sample_targets)
        self.assertIn("administrator", targets)
        self.assertIn("da_smith", targets)


class TestIntegration(unittest.TestCase):
    """Integration tests combining all components"""

    def setUp(self):
        self.sample_dit = Path(__file__).parent.parent / "examples" / "sample.dit"
        self.sample_pot = Path(__file__).parent.parent / "examples" / "sample.pot"
        self.sample_targets = Path(__file__).parent.parent / "examples" / "targets.txt"

    def test_correlate_cracked_hashes(self):
        creds = parse_dit_file(self.sample_dit)
        pot_hashes = parse_pot_file(self.sample_pot)

        cracked_count = 0
        for cred in creds:
            if cred.hash in pot_hashes:
                cred.cleartext = pot_hashes[cred.hash]
                cred.is_cracked = True
                cracked_count += 1

        self.assertGreater(cracked_count, 0)

    def test_identify_shared_hashes(self):
        creds = parse_dit_file(self.sample_dit)

        hash_to_creds = {}
        for cred in creds:
            if cred.hash and not cred.is_null:
                if cred.hash not in hash_to_creds:
                    hash_to_creds[cred.hash] = []
                hash_to_creds[cred.hash].append(cred)

        shared = {h: c for h, c in hash_to_creds.items() if len(c) > 1}
        self.assertGreater(len(shared), 0, "Should find shared password hashes")

    def test_mark_targets(self):
        creds = parse_dit_file(self.sample_dit)
        targets = parse_target_file(self.sample_targets)

        for cred in creds:
            if cred.sam_account_name.lower() in targets:
                cred.is_target = True

        target_creds = [c for c in creds if c.is_target]
        self.assertGreater(len(target_creds), 0)


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
