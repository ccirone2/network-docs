#!/usr/bin/env python3
"""Pre-commit / pre-push leak guard for network-docs and homelab-data.

Two modes:
  --mode=public-app    Path allowlist. Reject any staged path not listed.
  --mode=private-data  Allowlist + structural validation of
                       network-import-encrypted.json. Reject if any path
                       declared in encrypted_fields holds plaintext.

Run from the repo root. Reads `git diff --cached --name-only` for the
list of staged paths.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

PUBLIC_APP_ALLOWLIST = [
    "network-inventory.html",
    "network-import.schema.json",
    "encrypt_hosts.py",
    "README.md",
    "CLAUDE.md",
    ".gitignore",
    "bin/*",
    "fixtures/empty.json",
    "fixtures/full.json",
    "fixtures/encrypted.json",
    ".githooks/*",
    ".github/*",
    ".github/workflows/*",
]

PRIVATE_DATA_ALLOWLIST = [
    "network-import-encrypted.json",
    "README.md",
    ".gitignore",
    "bin/*",
    ".githooks/*",
]

ENCRYPTED_FILE = "network-import-encrypted.json"


def staged_files() -> list[str]:
    out = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        text=True,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def reject(reason: str, items: list[str]) -> int:
    print(f"verify-no-leaks: {reason}", file=sys.stderr)
    for item in items:
        print(f"  - {item}", file=sys.stderr)
    print(
        "\nIf this is intentional, update the allowlist in bin/verify-no-leaks.py.",
        file=sys.stderr,
    )
    return 1


def check_allowlist(allow: list[str]) -> tuple[int, list[str]]:
    files = staged_files()
    bad = [f for f in files if not matches_any(f, allow)]
    if bad:
        return reject("staged paths not in allowlist:", bad), files
    return 0, files


def walk_path(node, parts: list[str]):
    """Yield every value in `node` reached by the dotted path `parts`.
    `*` matches any dict key or list index.
    """
    if not parts:
        yield node
        return
    head, *rest = parts
    if head == "*":
        if isinstance(node, dict):
            for v in node.values():
                yield from walk_path(v, rest)
        elif isinstance(node, list):
            for v in node:
                yield from walk_path(v, rest)
        return
    if isinstance(node, dict) and head in node:
        yield from walk_path(node[head], rest)


def is_encrypted_blob(v) -> bool:
    return (
        isinstance(v, dict)
        and isinstance(v.get("iv"), str)
        and isinstance(v.get("ct"), str)
    )


def network_iter(data: dict):
    """Yield (network_label, network_dict) for either multi- or single-network shape."""
    if isinstance(data.get("networks"), dict):
        for nid, net in data["networks"].items():
            yield nid, net
    elif "network" in data and "vlans" in data:
        yield "(single)", data
    else:
        yield "(unknown)", data


def check_encrypted_file() -> int:
    target = Path(ENCRYPTED_FILE)
    if not target.exists():
        print(f"verify-no-leaks: {target} staged but missing", file=sys.stderr)
        return 1
    try:
        env = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"verify-no-leaks: {target} is not valid JSON: {e}", file=sys.stderr)
        return 1

    missing = {"kdf", "cipher", "encrypted_fields", "data"} - set(env.keys())
    if missing:
        return reject(
            "envelope missing required keys:", [str(k) for k in sorted(missing)]
        )

    if env["kdf"].get("name") != "PBKDF2":
        print(
            f"verify-no-leaks: kdf.name must be 'PBKDF2', got "
            f"{env['kdf'].get('name')!r}",
            file=sys.stderr,
        )
        return 1

    leaks: list[str] = []
    for path in env["encrypted_fields"]:
        parts = path.split(".")
        for nid, net in network_iter(env["data"]):
            for value in walk_path(net, parts):
                if value == "" or value is None:
                    continue
                if not is_encrypted_blob(value):
                    sample = (value[:32] + "…") if isinstance(value, str) else repr(value)[:32]
                    leaks.append(f"networks.{nid}.{path}: {sample!r}")
    if leaks:
        return reject(
            "expected-encrypted paths contain plaintext or invalid values:", leaks
        )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["public-app", "private-data"], required=True)
    args = ap.parse_args()

    if args.mode == "public-app":
        rc, _ = check_allowlist(PUBLIC_APP_ALLOWLIST)
        return rc

    rc, files = check_allowlist(PRIVATE_DATA_ALLOWLIST)
    if rc != 0:
        return rc
    if ENCRYPTED_FILE in files:
        return check_encrypted_file()
    return 0


if __name__ == "__main__":
    sys.exit(main())
