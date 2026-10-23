#!/usr/bin/env python3
"""Tests for crack.py and md4.py. Run: python3 -m unittest discover tests"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crack
import md4

WORDS = crack.load_words(crack.DEFAULT_WORDLIST)
SMALL_WORDS = ["alpha", "bravo", "charlie", "delta", "echo"]

# Known vectors
MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"          # "password"
SHA1_PASSWORD = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"  # "password"
SHA256_PASSWORD1 = ("19513fdc9da4fb72a4a05eb66917548d3c90ff94d5419e1f2"
                    "363eea89dfee1dd")                       # "Password1"
MD5_LETMEIN123 = "4ca7c5c27c2314eecc71f67501abb724"         # "letmein123"
MD5_DRAGON7 = "aacbb97948b2cadb1e92cba4bb84c567"            # "dragon7"
NTLM_PASSWORD = "8846f7eaee8fb117ad06bdd830b7586c"          # "password"
MD5_STRONG = "a74dfc7cafb12827ab6d65dda95a2688"  # "Xq9!vR2#mZp7$kLw"
BCRYPT_PASSWORD = ("$2b$04$K867sHJk4lI491gqhxwejeFmddyLRuxR6Y88hwfUG"
                   "mTMAVZRQNgLC")  # "password", cost 4


class TestMD4(unittest.TestCase):
    def test_rfc_vectors_and_ntlm(self):
        self.assertTrue(md4.self_test())

    def test_ntlm_known(self):
        self.assertEqual(md4.ntlm_hex("password"), NTLM_PASSWORD)


class TestIdentify(unittest.TestCase):
    def test_types(self):
        self.assertEqual(crack.identify(MD5_PASSWORD)[1], ["md5", "ntlm"])
        self.assertEqual(crack.identify(SHA1_PASSWORD)[1], ["sha1"])
        self.assertEqual(crack.identify(SHA256_PASSWORD1)[1],
                         ["sha256", "sha3_256"])
        self.assertEqual(crack.identify(BCRYPT_PASSWORD)[0], "bcrypt")
        self.assertEqual(crack.identify("zzzz")[0], "unknown")


class TestCrackFast(unittest.TestCase):
    def _run(self, hashes, words=WORDS):
        targets = {}
        for h in hashes:
            kind, algos = crack.identify(h)
            assert kind == "fast"
            targets[h.lower()] = algos
        return crack.crack_fast(targets, words)

    def test_md5_password(self):
        r = self._run([MD5_PASSWORD])[MD5_PASSWORD]
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "password")
        self.assertEqual(r["algo"], "md5")

    def test_sha1_password(self):
        r = self._run([SHA1_PASSWORD])[SHA1_PASSWORD]
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "password")

    def test_sha256_capitalized_plus_digit(self):
        r = self._run([SHA256_PASSWORD1])[SHA256_PASSWORD1]
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "Password1")
        self.assertIn("capitalized", r["rule"])

    def test_md5_append_123(self):
        r = self._run([MD5_LETMEIN123])[MD5_LETMEIN123]
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "letmein123")

    def test_md5_midlist_digit_suffix(self):
        r = self._run([MD5_DRAGON7])[MD5_DRAGON7]
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "dragon7")

    def test_ntlm_password(self):
        r = self._run([NTLM_PASSWORD])[NTLM_PASSWORD]
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "password")
        self.assertEqual(r["algo"], "ntlm")

    def test_strong_password_not_cracked(self):
        r = self._run([MD5_STRONG], words=SMALL_WORDS)[MD5_STRONG]
        self.assertFalse(r["cracked"])
        self.assertIsNone(r["plaintext"])


class TestBcrypt(unittest.TestCase):
    def test_bcrypt_password(self):
        try:
            import bcrypt  # noqa: F401
        except ImportError:
            self.skipTest("bcrypt package not installed")
        r = crack.crack_bcrypt(BCRYPT_PASSWORD, WORDS, 300)
        self.assertTrue(r["cracked"])
        self.assertEqual(r["plaintext"], "password")


class TestCLI(unittest.TestCase):
    def test_cli_json(self):
        here = os.path.join(os.path.dirname(__file__), "..")
        proc = subprocess.run(
            [sys.executable, os.path.join(here, "crack.py"),
             MD5_PASSWORD, "--json"],
            capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["results"][0]["plaintext"], "password")
        self.assertTrue(data["results"][0]["cracked"])


if __name__ == "__main__":
    unittest.main()
