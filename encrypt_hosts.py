#!/usr/bin/env python3
"""
encrypt_hosts.py — Encrypt sensitive fields in a hosts JSON file.

Reads a plaintext hosts JSON, prompts for a master passphrase, and writes an
encrypted JSON envelope where every value at a configured dotted path is
replaced with an {iv, ct} blob. Output shape matches the envelope produced
and consumed by network-inventory.html (network-import.schema.json /
EncryptedEnvelope).

Crypto layout (matches the HTML app):
  - KDF:      PBKDF2-HMAC-SHA256(passphrase, salt, iterations) -> 32 bytes
  - Cipher:   AES-256-GCM
  - Per-value IV: 12 random bytes, fresh for every value
  - Output:   base64(standard) for salt, iv, ct

Usage:
  python encrypt_hosts.py input.json output.json                # Tier-1
  python encrypt_hosts.py input.json output.json --tier2        # Tier-1+Tier-2
  python encrypt_hosts.py input.json output.json --paths a.b,c.* # explicit
  python encrypt_hosts.py input.json output.json --iterations 600000

Path syntax: dotted paths, applied per-network. `*` matches any dict key or
list index. Examples:
  credentials.*.password
  hosts.*.interfaces.*.ip_addresses.*.address
  hosts.*.aliases.*

Requires: cryptography  (pip install cryptography)
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from typing import Any, Callable, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


DEFAULT_ITERATIONS = 250_000

# Mirrors restructuring/03-tier2-encryption.md "Stays plaintext (structural)".
TIER1_PATHS: tuple[str, ...] = (
    "credentials.*.password",
)

TIER2_PATHS: tuple[str, ...] = (
    "network.name",
    "network.description",
    "vlans.*.name",
    "vlans.*.gateway_ip",
    "vlans.*.dhcp_range_start",
    "vlans.*.dhcp_range_end",
    "hosts.*.display_name",
    "hosts.*.hostname",
    "hosts.*.aliases.*",
    "hosts.*.notes",
    "hosts.*.management_ip",
    "hosts.*.vm_id",
    "hosts.*.software.name",
    "hosts.*.software.version",
    "hosts.*.software.notes",
    "hosts.*.manufacturer",
    "hosts.*.model",
    "hosts.*.hardware_revision",
    "hosts.*.identifiers.*.value",
    "hosts.*.identifiers.*.label",
    "hosts.*.interfaces.*.mac",
    "hosts.*.interfaces.*.ip_addresses.*.address",
    "hosts.*.services.*.name",
    "hosts.*.services.*.display_name",
    "hosts.*.services.*.listen_ip",
    "hosts.*.services.*.url",
    "hosts.*.services.*.notes",
    "hosts.*.links.*.label",
    "hosts.*.links.*.url",
    "hosts.*.peripherals.*.usb_vid_pid",
    "hosts.*.peripherals.*.description",
    "credentials.*.username",
    "credentials.*.notes",
    "credentials.*.external_ref.id",
)

# Self-test fixture parameters — see CLAUDE.md "Fixtures and ?selftest=1".
TEST_PASSPHRASE = "selftest"
TEST_SALT_B64 = "c2VsZnRlc3Qtc2FsdCEhIQ=="
TEST_ITERATIONS = 1000


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_value(aesgcm: AESGCM, plaintext: str) -> dict[str, str]:
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return {"iv": b64(iv), "ct": b64(ct)}


def _is_blob(v: Any) -> bool:
    return isinstance(v, dict) and isinstance(v.get("iv"), str) and isinstance(v.get("ct"), str)


def _walk_and_apply(node: Any, parts: list[str], fn: Callable[[Any, Any], Any]) -> None:
    """Walk `node` along path `parts`. At each leaf, replace the value in
    place with `fn(parent, value)`'s return. `*` matches all dict keys or
    list indices. Missing intermediate keys are silently skipped."""
    if not parts:
        return
    head, *rest = parts
    if not rest:
        if head == "*":
            if isinstance(node, dict):
                for k in list(node.keys()):
                    node[k] = fn(node, node[k])
            elif isinstance(node, list):
                for i in range(len(node)):
                    node[i] = fn(node, node[i])
            return
        if isinstance(node, dict) and head in node:
            node[head] = fn(node, node[head])
        return
    if head == "*":
        if isinstance(node, dict):
            for v in node.values():
                _walk_and_apply(v, rest, fn)
        elif isinstance(node, list):
            for v in node:
                _walk_and_apply(v, rest, fn)
        return
    if isinstance(node, dict) and head in node:
        _walk_and_apply(node[head], rest, fn)


def _network_records(data: dict) -> Iterable[dict]:
    """Yield each network record from either multi- or single-network shape."""
    if isinstance(data.get("networks"), dict):
        for net in data["networks"].values():
            if isinstance(net, dict):
                yield net
        return
    if "network" in data and "vlans" in data:
        yield data


def encrypt_paths(data: dict, paths: Iterable[str], aesgcm: AESGCM) -> None:
    """Mutate `data` in place: for each network record, encrypt the value at
    every leaf reached by each dotted path. Empty strings are left as-is
    (the empty string is not a secret); existing {iv, ct} blobs are passed
    through. Non-string values at a leaf are left unchanged."""
    def encrypt_leaf(_parent: Any, value: Any) -> Any:
        if _is_blob(value):
            return value
        if isinstance(value, str) and value != "":
            return encrypt_value(aesgcm, value)
        return value

    for net in _network_records(data):
        for path in paths:
            _walk_and_apply(net, path.split("."), encrypt_leaf)


def build_envelope(
    data: dict,
    passphrase: str,
    paths: list[str],
    *,
    salt: bytes | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> dict:
    """Encrypt `data` in place under `passphrase`, return the envelope dict.
    Caller owns `data`; pass a deep copy if mutation is undesirable."""
    if salt is None:
        salt = os.urandom(16)
    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    encrypt_paths(data, paths, aesgcm)
    return {
        "kdf": {
            "name": "PBKDF2",
            "salt": b64(salt),
            "iterations": iterations,
            "hash": "SHA-256",
        },
        "cipher": {"name": "AES-GCM", "length": 256},
        "encrypted_fields": list(paths),
        "data": data,
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Encrypt sensitive fields in a hosts JSON file.")
    p.add_argument("input", help="Path to plaintext input JSON")
    p.add_argument("output", help="Path to write encrypted JSON")
    tier = p.add_mutually_exclusive_group()
    tier.add_argument(
        "--tier1",
        action="store_true",
        help="Encrypt Tier-1 paths only (default): credentials.*.password",
    )
    tier.add_argument(
        "--tier2",
        action="store_true",
        help="Encrypt Tier-1 + Tier-2 paths (identifying values across hosts/services/credentials).",
    )
    tier.add_argument(
        "--paths",
        help="Comma-separated dotted paths, overrides --tier1/--tier2.",
    )
    p.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iteration count (default: {DEFAULT_ITERATIONS})",
    )
    return p.parse_args()


def resolve_paths(args: argparse.Namespace) -> list[str]:
    if args.paths:
        paths = [p.strip() for p in args.paths.split(",") if p.strip()]
        if not paths:
            print("error: --paths is empty", file=sys.stderr)
            sys.exit(2)
        return paths
    if args.tier2:
        return list(TIER1_PATHS) + list(TIER2_PATHS)
    return list(TIER1_PATHS)


def main() -> int:
    args = parse_args()
    paths = resolve_paths(args)

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error reading {args.input}: {e}", file=sys.stderr)
        return 1

    passphrase = getpass.getpass("Master passphrase: ")
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        print("error: passphrases do not match", file=sys.stderr)
        return 1
    if not passphrase:
        print("error: empty passphrase", file=sys.stderr)
        return 1

    envelope = build_envelope(data, passphrase, paths, iterations=args.iterations)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
            f.write("\n")
    except OSError as e:
        print(f"error writing {args.output}: {e}", file=sys.stderr)
        return 1

    print(f"wrote {args.output}")
    print(f"  paths encrypted: {len(paths)}")
    print(f"  iterations: {args.iterations}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
