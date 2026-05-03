#!/usr/bin/env python3
"""Regenerate fixtures/encrypted.json from fixtures/full.json.

Encrypts the plaintext fixture under the self-test passphrase / salt /
iteration count documented in CLAUDE.md ("Fixtures and ?selftest=1") so the
encrypted-fixture invariant in runSelfTest can decrypt it.

By default applies Tier-1 only (today's app behavior). Pass --tier2 once
sub-plan 03 has landed to regenerate with the full Tier-1+Tier-2 path set;
the committed fixture must match whichever tiers the running app understands,
otherwise self-test fails.

Output bytes are NOT deterministic across runs — AES-GCM IVs come from
crypto.getRandomValues, so two regenerations of the same input produce
different ciphertext. The invariant the self-test checks is round-trip
decryptability, not byte identity.

Run from repo root:
  python bin/regen-encrypted-fixture.py
  python bin/regen-encrypted-fixture.py --tier2
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from encrypt_hosts import (  # noqa: E402
    TEST_ITERATIONS,
    TEST_PASSPHRASE,
    TEST_SALT_B64,
    TIER1_PATHS,
    TIER2_PATHS,
    build_envelope,
)

FIXTURE_FULL = REPO_ROOT / "fixtures" / "full.json"
FIXTURE_ENC = REPO_ROOT / "fixtures" / "encrypted.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--tier2",
        action="store_true",
        help="Apply Tier-1 + Tier-2 paths (use after sub-plan 03 lands).",
    )
    args = ap.parse_args()

    plaintext = json.loads(FIXTURE_FULL.read_text(encoding="utf-8"))
    paths = list(TIER1_PATHS)
    if args.tier2:
        paths += list(TIER2_PATHS)

    envelope = build_envelope(
        copy.deepcopy(plaintext),
        TEST_PASSPHRASE,
        paths,
        salt=base64.b64decode(TEST_SALT_B64),
        iterations=TEST_ITERATIONS,
    )

    FIXTURE_ENC.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE_ENC.relative_to(REPO_ROOT)}")
    print(f"  paths encrypted: {len(paths)}")
    print("  reminder: also update the inline <script id=\"fixture-encrypted\"> block in network-inventory.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
