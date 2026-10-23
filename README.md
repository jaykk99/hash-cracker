# hash-cracker

A standalone, **offline** dictionary + rules hash cracker.

> **Scope:** for hashes you own or are authorized to audit — your own
> hashes, CTF challenges, authorized password audits. It runs entirely
> locally: no targets, no network lookups, no integration with any scanner
> or other app. You supply the hashes; it tries to recover the plaintexts.

## What it does

Give it one or more hashes and it auto-identifies the type and runs a
dictionary attack with rule mutations against them:

- **Algorithms:** MD5, NTLM, SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512,
  bcrypt (see notes below)
- **Wordlist:** bundled 10,000 most-common passwords (see Attribution).
  Point `--wordlist` at a bigger list (e.g. rockyou.txt) for deeper runs.
- **Rules applied to every word:** as-is, Capitalized, UPPER, leetspeak
  (a→4, e→3, i→1, o→0, s→5), capitalized+leet, append `!`, append 1–2 digits,
  append common suffixes (`123`, `1234`, `007`, ...), append a year
  1970–2030. Roughly 400 candidates per word, ~4M per full pass over the
  bundled list.
- **Multi-hash:** all hashes of the same algorithm are attacked in a single
  candidate pass. Ambiguous lengths are tried as every matching algorithm
  (a 32-hex hash is tried as both MD5 and NTLM, a 64-hex as SHA-256 and
  SHA3-256).
- **NTLM** uses a bundled pure-Python MD4 (`md4.py`, RFC 1320, self-tested)
  because OpenSSL 3 builds usually disable MD4 in `hashlib`.

## Usage

```bash
# One hash
python3 crack.py 5f4dcc3b5aa765d61d8327deb882cf99

# Several hashes
python3 crack.py <hash1> <hash2> ...

# A file of hashes (one per line)
python3 crack.py --file hashes.txt

# Bigger wordlist (e.g. rockyou) + JSON output
python3 crack.py --file hashes.txt --wordlist /path/to/rockyou.txt --json

# bcrypt: cap how many top candidates to try (default 300)
python3 crack.py '$2b$12$...' --bcrypt-limit 1000
```

Output per hash: type, `CRACKED: <plaintext>` (plus the rule that found it,
candidate count and time) or `NOT CRACKED` with an honest explanation.

### bcrypt setup

bcrypt verification needs the `bcrypt` pip package:

```bash
python3 -m venv .venv && .venv/bin/pip install bcrypt
.venv/bin/python crack.py '$2b$12$...'
```

Without it, bcrypt hashes are skipped with a clear message; all other
algorithms work with the standard library alone.

## Tests

```bash
python3 -m unittest discover tests      # stdlib only (bcrypt test skips)
.venv/bin/python -m unittest discover tests   # includes the bcrypt test
```

Known vectors: MD5/SHA-1/SHA-256 of common passwords, a rule-mutated
mid-list word (`dragon7`), NTLM of `password`, the RFC 1320 MD4 suite, and
a strong random password that must come back NOT CRACKED.

## Honest limits

- **Dictionary + rules only.** If the plaintext is not a wordlist word with
  a common mutation, it will not be found. There is no brute-force mode —
  pure-Python brute force is pointless anyway.
- **Salted and slow hashes resist.** bcrypt/Argon2 are designed to be slow;
  only the first few hundred top candidates are practical to check. Per-hash
  salts also defeat multi-hash passes and precomputation.
- **For serious work use hashcat** with a GPU, big wordlists (rockyou) and
  rule files (OneRuleToRuleThemAll, best64). This tool is for quick local
  audits, CTFs and checking your own passwords — it answers "is this hash
  something trivially guessable?" fast.

## Attribution

`10k-most-common.txt` is the 10,000 most common passwords list from
[SecLists](https://github.com/danielmiessler/SecLists)
(Passwords/Common-Credentials/10k-most-common.txt) by Daniel Miessler
and contributors, used under its MIT license.
