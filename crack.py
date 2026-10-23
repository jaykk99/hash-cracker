#!/usr/bin/env python3
"""crack.py - standalone offline hash cracker (dictionary + rules).

For hashes you own or are authorized to audit: your own hashes, CTFs,
authorized password audits. Local and offline only: no targets, no network.

Usage:
    python3 crack.py <hash> [more hashes...]
    python3 crack.py --file hashes.txt
    python3 crack.py --file hashes.txt --wordlist rockyou.txt --json

Algorithms: MD5, NTLM, SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512,
bcrypt (needs the `bcrypt` pip package; only top candidates are practical).
"""

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from md4 import ntlm_hex  # pure-Python MD4 (hashlib usually lacks it)

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_WORDLIST = os.path.join(HERE, "10k-most-common.txt")

# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------

_HEX_LEN_TO_ALGOS = {
    32: ["md5", "ntlm"],            # ambiguous: try both
    40: ["sha1"],
    56: ["sha224", "sha3_224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512"],
}

_ALGO_LABEL = {
    "md5": "MD5", "ntlm": "NTLM", "sha1": "SHA-1",
    "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384", "sha3_512": "SHA3-512", "bcrypt": "bcrypt",
}


def identify(hash_str):
    """Return (kind, algos) where kind is 'fast', 'bcrypt', or 'unknown'."""
    h = hash_str.strip()
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt", ["bcrypt"]
    low = h.lower()
    if all(c in "0123456789abcdef" for c in low) and len(low) in _HEX_LEN_TO_ALGOS:
        return "fast", _HEX_LEN_TO_ALGOS[len(low)]
    return "unknown", []


def digest_for(algo, candidate_bytes):
    if algo == "ntlm":
        return ntlm_hex(candidate_bytes.decode("utf-8", "ignore"))
    return hashlib.new(algo, candidate_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Candidate generation: wordlist x rules
# ---------------------------------------------------------------------------

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
                       "A": "4", "E": "3", "I": "1", "O": "0", "S": "5"})

_COMMON_SUFFIXES = ["123", "1234", "12345", "123456", "12345678",
                    "007", "69", "420", "666", "777", "888", "999",
                    "111", "000", "2023", "2024", "2025", "2026"]
_FULL_SUFFIXES = (["", "!"] + [str(d) for d in range(10)]
                  + ["%02d" % d for d in range(100)]
                  + _COMMON_SUFFIXES
                  + [str(y) for y in range(1970, 2031)])
_LIGHT_SUFFIXES = ["", "!"] + [str(d) for d in range(10)]


def _base_forms(word):
    """Yield (form, rule_name) case/leet transforms of a word."""
    yield word, "as-is"
    cap = word.capitalize()
    if cap != word:
        yield cap, "capitalized"
    up = word.upper()
    if up != word and up != cap:
        yield up, "upper"
    leet = word.translate(_LEET)
    if leet != word:
        yield leet, "leet"
    cap_leet = cap.translate(_LEET)
    if cap_leet not in (word, cap, leet):
        yield cap_leet, "capitalized+leet"


def candidates(words):
    """Yield (plaintext, rule_description) for every word x rule combo."""
    for word in words:
        for form, rule in _base_forms(word):
            suffixes = _FULL_SUFFIXES if rule in ("as-is", "capitalized") \
                else _LIGHT_SUFFIXES
            for suf in suffixes:
                if suf:
                    yield form + suf, "%s + append '%s'" % (rule, suf)
                else:
                    yield form, rule


def slow_candidates(words, limit):
    """First `limit` candidates for slow hashes (bcrypt): base forms only."""
    count = 0
    for word in words:
        for form, rule in _base_forms(word):
            if rule in ("as-is", "capitalized", "upper"):
                yield form, rule
                count += 1
                if count >= limit:
                    return


# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------

def crack_fast(targets, words, progress=False):
    """targets: dict hash->algos. One candidate pass per algorithm group.

    Returns dict hash -> result dict.
    """
    results = {}
    # Group hashes by algorithm; a hash may belong to several algos
    # (e.g. 32-hex could be MD5 or NTLM) - it stays in `remaining` until hit.
    algo_targets = {}
    for h, algos in targets.items():
        for a in algos:
            algo_targets.setdefault(a, set()).add(h)
    remaining = set(targets)

    for algo, hashes in algo_targets.items():
        if not remaining:
            break
        live = hashes & remaining
        if not live:
            continue
        start = time.time()
        tried = 0
        for cand, rule in candidates(words):
            tried += 1
            d = digest_for(algo, cand.encode())
            if d in live:
                results[d] = {
                    "hash": d, "type": _ALGO_LABEL[algo], "algo": algo,
                    "cracked": True, "plaintext": cand, "rule": rule,
                    "candidates_tried": tried,
                    "seconds": round(time.time() - start, 3),
                }
                remaining.discard(d)
                live.discard(d)
                if not live:
                    break
            if progress and tried % 500000 == 0:
                print("  [%s] %d candidates, %d/%d cracked..."
                      % (algo, tried, len(results), len(targets)),
                      file=sys.stderr)
        for h in list(live):
            pass  # still uncracked under this algo; other algos may match
    for h in remaining:
        algos = targets[h]
        results[h] = {
            "hash": h,
            "type": "/".join(_ALGO_LABEL[a] for a in algos),
            "algo": None, "cracked": False, "plaintext": None, "rule": None,
            "candidates_tried": None, "seconds": None,
        }
    return results


def crack_bcrypt(hash_str, words, limit):
    """Try the first `limit` base-form candidates against a bcrypt hash."""
    try:
        import bcrypt as _bcrypt
    except ImportError:
        return {"hash": hash_str, "type": "bcrypt", "algo": "bcrypt",
                "cracked": False, "plaintext": None, "rule": None,
                "candidates_tried": 0, "seconds": 0,
                "error": "bcrypt package not installed - "
                         "run: pip install bcrypt"}
    start = time.time()
    tried = 0
    target = hash_str.encode()
    for cand, rule in slow_candidates(words, limit):
        tried += 1
        try:
            if _bcrypt.checkpw(cand.encode(), target):
                return {"hash": hash_str, "type": "bcrypt", "algo": "bcrypt",
                        "cracked": True, "plaintext": cand, "rule": rule,
                        "candidates_tried": tried,
                        "seconds": round(time.time() - start, 3)}
        except ValueError:
            return {"hash": hash_str, "type": "bcrypt", "algo": "bcrypt",
                    "cracked": False, "plaintext": None, "rule": None,
                    "candidates_tried": tried,
                    "seconds": round(time.time() - start, 3),
                    "error": "invalid bcrypt hash"}
    return {"hash": hash_str, "type": "bcrypt", "algo": "bcrypt",
            "cracked": False, "plaintext": None, "rule": None,
            "candidates_tried": tried,
            "seconds": round(time.time() - start, 3),
            "note": "only the first %d base-form candidates were tried "
                    "(bcrypt is slow by design)" % limit}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def load_words(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Offline dictionary+rules hash cracker. "
                    "For hashes you own or are authorized to audit.")
    ap.add_argument("hashes", nargs="*", help="one or more hashes")
    ap.add_argument("--file", help="file with one hash per line")
    ap.add_argument("--wordlist", default=DEFAULT_WORDLIST,
                    help="wordlist path (default: bundled 10k-most-common)")
    ap.add_argument("--bcrypt-limit", type=int, default=300,
                    help="max candidates to try per bcrypt hash (default 300)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--progress", action="store_true",
                    help="progress to stderr during long passes")
    args = ap.parse_args(argv)

    raw = list(args.hashes)
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
            raw += [ln.strip() for ln in fh if ln.strip()
                    and not ln.startswith("#")]
    if not raw:
        ap.error("give at least one hash or --file")

    words = load_words(args.wordlist)
    fast_targets, bcrypt_targets, unknown = {}, [], []
    order = []
    for h in raw:
        kind, algos = identify(h)
        key = h.lower() if kind == "fast" else h
        order.append((h, key))
        if kind == "fast":
            fast_targets[key] = algos
        elif kind == "bcrypt":
            bcrypt_targets.append(h)
        else:
            unknown.append(h)

    t0 = time.time()
    results = {}
    if fast_targets:
        results.update(crack_fast(fast_targets, words,
                                  progress=args.progress))
    for h in bcrypt_targets:
        results[h] = crack_bcrypt(h, words, args.bcrypt_limit)
    elapsed = round(time.time() - t0, 3)

    out = []
    for original, key in order:
        if key in results:
            out.append(results[key])
        else:
            out.append({"hash": original, "type": "unknown", "algo": None,
                        "cracked": False, "plaintext": None, "rule": None,
                        "candidates_tried": 0, "seconds": 0,
                        "error": "unrecognized hash format"})

    if args.json:
        print(json.dumps({"results": out, "elapsed_seconds": elapsed,
                          "wordlist": args.wordlist,
                          "wordlist_size": len(words)}, indent=2))
    else:
        for r in out:
            label = r["type"]
            if r["cracked"]:
                print("%s [%s] CRACKED: %s  (rule: %s, %d candidates, %ss)"
                      % (r["hash"], label, r["plaintext"], r["rule"],
                         r["candidates_tried"], r["seconds"]))
            else:
                line = "%s [%s] NOT CRACKED" % (r["hash"], label)
                if r.get("error"):
                    line += " - " + r["error"]
                elif r.get("note"):
                    line += " - " + r["note"]
                else:
                    line += (" - not in wordlist+rules. Salted/slow hashes "
                             "and strong passwords resist dictionary "
                             "attacks; use hashcat with a GPU for serious "
                             "work.")
                print(line)
        print("Done: %d/%d cracked in %ss (wordlist: %d words)"
              % (sum(1 for r in out if r["cracked"]), len(out), elapsed,
                 len(words)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
