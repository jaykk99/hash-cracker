#!/usr/bin/env python3
"""Audit tests added 2026-11-25 (hourly repo audit run).

Each test fails on the pre-fix code and passes on the fix. Run:
    python3 -m unittest discover tests
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crack
import md4

HERE = os.path.join(os.path.dirname(__file__), "..")
MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"  # "password"
NTLM_ALPHA = md4.ntlm_hex("alpha")
SMALL_WORDS = ["alpha", "bravo", "charlie", "delta", "echo"]


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, os.path.join(HERE, "crack.py"), *argv],
        capture_output=True, text=True, timeout=300)


class TestAudit20261125(unittest.TestCase):
    def test_whitespace_padded_argv_hash_cracks(self):
        # A hash pasted with surrounding spaces never matched any
        # candidate: identify() stripped for the type check, but the
        # lookup key kept the spaces.
        proc = run_cli(" " + MD5_PASSWORD + " ")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("CRACKED: password", proc.stdout)

    def test_no_duplicate_candidates(self):
        # "69" was in both _COMMON_SUFFIXES and the %02d range, and
        # 2023-2026 were in both _COMMON_SUFFIXES and the year range:
        # 418 generated per word, only 408 unique.
        cands = [c for c, _ in crack.candidates(["password"])]
        self.assertEqual(len(cands), len(set(cands)))
        self.assertEqual(len(cands), 408)

    def test_candidates_tried_counts_all_passes(self):
        # NTLM("alpha") used to report candidates_tried=1, seconds=0.001
        # while the run had already spent a full MD5 pass (5 words x 408
        # candidates) before the NTLM pass found it on its 1st candidate.
        r = crack.crack_fast({NTLM_ALPHA: ["md5", "ntlm"]}, SMALL_WORDS)
        self.assertTrue(r[NTLM_ALPHA]["cracked"])
        self.assertEqual(r[NTLM_ALPHA]["plaintext"], "alpha")
        self.assertEqual(r[NTLM_ALPHA]["algo"], "ntlm")
        # Full MD5 pass over all candidates first, then the 1st NTLM
        # candidate cracks it.
        expected = sum(1 for _ in crack.candidates(SMALL_WORDS)) + 1
        self.assertEqual(r[NTLM_ALPHA]["candidates_tried"], expected)

    def test_missing_wordlist_clean_error(self):
        proc = run_cli(MD5_PASSWORD, "--wordlist", "/nonexistent.txt")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("wordlist", proc.stderr)

    def test_missing_hash_file_clean_error(self):
        proc = run_cli("--file", "/nonexistent.txt")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIn("hash file", proc.stderr)

    def test_comment_with_leading_space_skipped(self):
        # "  # comment" was checked with startswith("#") on the raw line,
        # so it slipped through as an "unknown" hash instead of a comment.
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("  # comment\n%s\n" % MD5_PASSWORD)
            path = fh.name
        try:
            proc = run_cli("--file", path, "--json")
        finally:
            os.unlink(path)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(len(data["results"]), 1)
        self.assertTrue(data["results"][0]["cracked"])
        self.assertEqual(data["results"][0]["plaintext"], "password")

    def test_ntlm_digest_strict_decode(self):
        # Guard: digest_for must hash exactly the candidate it reports,
        # never a lossy errors="ignore" decode of it.
        self.assertEqual(
            crack.digest_for("ntlm", "password".encode()),
            "8846f7eaee8fb117ad06bdd830b7586c")

    def test_uppercase_hex_cracks(self):
        # Guard: uppercase hex input still cracks (key lowercasing).
        proc = run_cli(MD5_PASSWORD.upper())
        self.assertEqual(proc.returncode, 0)
        self.assertIn("CRACKED: password", proc.stdout)


if __name__ == "__main__":
    unittest.main()
