#!/usr/bin/env python3
"""
reid-plaintext.py — Rewrite all entity IDs in a plaintext network-import JSON.

Generates a fresh opaque ID (<typetag>_<6 hex>) for every network, vlan, host,
credential, and service, and rewrites both dict keys and every ref-shaped
field in lockstep. Migration tool for sub-plan 06: closes the dict-key leak
channel that Tier-2 encryption can't touch.

Usage:
  python bin/reid-plaintext.py input.json output.json
  python bin/reid-plaintext.py input.json output.json --seed deadbeef

Refuses to operate if the input has dangling refs (fix in the app first).
Refuses to write the output if any ref fails to resolve post-rewrite. ID
allocator retries on duplicates within the same run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from typing import Any, Callable

ID_PREFIXES = {
    "network":    "n",
    "vlan":       "v",
    "host":       "h",
    "credential": "c",
    "service":    "s",
}
ID_HEX_LEN = 6


HexFn = Callable[[int], str]


def make_hex_source(seed: str | None) -> HexFn:
    """Return a callable that yields fresh hex strings of length n. With a
    seed, deterministic via SHA-256 chain; otherwise cryptographically random."""
    if seed is None:
        return lambda n: secrets.token_hex((n + 1) // 2)[:n]
    state = [hashlib.sha256(seed.encode("utf-8")).digest()]
    def next_hex(n: int) -> str:
        chunks: list[bytes] = []
        while sum(len(c) for c in chunks) * 2 < n:
            state[0] = hashlib.sha256(state[0]).digest()
            chunks.append(state[0])
        return b"".join(chunks).hex()[:n]
    return next_hex


def alloc_id(prefix: str, used: set[str], hex_source: HexFn) -> str:
    for _ in range(10_000):
        nid = f"{prefix}_{hex_source(ID_HEX_LEN)}"
        if nid not in used:
            used.add(nid)
            return nid
    raise RuntimeError(f"could not allocate fresh {prefix}_ id in 10000 attempts")


def validate_refs(net: dict) -> list[dict]:
    """Port of validateRefs() from network-inventory.html. Returns one row per
    dangling reference found in `net`."""
    if not isinstance(net, dict):
        return []
    rows: list[dict] = []
    vlan_ids = set((net.get("vlans") or {}).keys())
    host_ids = set((net.get("hosts") or {}).keys())
    cred_ids = set((net.get("credentials") or {}).keys())

    for hid, host in (net.get("hosts") or {}).items():
        if host.get("management_vlan") and host["management_vlan"] not in vlan_ids:
            rows.append({"from": f"host:{hid}", "field": "management_vlan",
                         "expected_id": host["management_vlan"], "kind": "vlan"})
        if host.get("hosted_on") and host["hosted_on"] not in host_ids:
            rows.append({"from": f"host:{hid}", "field": "hosted_on",
                         "expected_id": host["hosted_on"], "kind": "host"})
        if host.get("credential_ref") and host["credential_ref"] not in cred_ids:
            rows.append({"from": f"host:{hid}", "field": "credential_ref",
                         "expected_id": host["credential_ref"], "kind": "credential"})
        for iface in (host.get("interfaces") or []):
            tag = f'host:{hid}/iface:{iface.get("name", "?")}'
            ct = iface.get("connected_to") or {}
            if ct.get("host_id"):
                if ct["host_id"] not in host_ids:
                    rows.append({"from": tag, "field": "connected_to.host_id",
                                 "expected_id": ct["host_id"], "kind": "host"})
                elif ct.get("interface"):
                    target = (net.get("hosts") or {}).get(ct["host_id"]) or {}
                    found = any(i.get("name") == ct["interface"]
                                for i in (target.get("interfaces") or []))
                    if not found:
                        rows.append({"from": tag, "field": "connected_to.iface_name",
                                     "expected_id": f'{ct["host_id"]}:{ct["interface"]}',
                                     "kind": "interface"})
            if iface.get("access_vlan") and iface["access_vlan"] not in vlan_ids:
                rows.append({"from": tag, "field": "access_vlan",
                             "expected_id": iface["access_vlan"], "kind": "vlan"})
            if iface.get("native_vlan") and iface["native_vlan"] not in vlan_ids:
                rows.append({"from": tag, "field": "native_vlan",
                             "expected_id": iface["native_vlan"], "kind": "vlan"})
            for v in (iface.get("allowed_vlans") or []):
                if v and v not in vlan_ids:
                    rows.append({"from": tag, "field": "allowed_vlans[]",
                                 "expected_id": v, "kind": "vlan"})
        for svc in (host.get("services") or []):
            if svc.get("credential_ref") and svc["credential_ref"] not in cred_ids:
                stag = f'host:{hid}/svc:{svc.get("id") or svc.get("name", "?")}'
                rows.append({"from": stag, "field": "credential_ref",
                             "expected_id": svc["credential_ref"], "kind": "credential"})
    return rows


def validate_data(data: dict) -> list[dict]:
    rows: list[dict] = []
    if isinstance(data.get("networks"), dict):
        for nid, net in data["networks"].items():
            for r in validate_refs(net):
                rows.append({"network": nid, **r})
    elif "vlans" in data or "hosts" in data:
        rows.extend(validate_refs(data))
    return rows


def reid_network_inplace(net: dict, used: set[str], hex_source: HexFn) -> None:
    """Allocate fresh IDs for every vlan/host/credential/service in `net`,
    rewrite dict keys and every ref-shaped field in lockstep."""
    vlan_map = {old: alloc_id("v", used, hex_source)
                for old in (net.get("vlans") or {}).keys()}
    host_map = {old: alloc_id("h", used, hex_source)
                for old in (net.get("hosts") or {}).keys()}
    cred_map = {old: alloc_id("c", used, hex_source)
                for old in (net.get("credentials") or {}).keys()}

    if isinstance(net.get("vlans"), dict):
        net["vlans"] = {vlan_map[k]: v for k, v in net["vlans"].items()}
    if isinstance(net.get("credentials"), dict):
        net["credentials"] = {cred_map[k]: v for k, v in net["credentials"].items()}

    if isinstance(net.get("hosts"), dict):
        new_hosts: dict[str, Any] = {}
        for old_hid, host in net["hosts"].items():
            _rewrite_host_refs(host, vlan_map, host_map, cred_map, used, hex_source)
            new_hosts[host_map[old_hid]] = host
        net["hosts"] = new_hosts


def _rewrite_host_refs(
    host: dict,
    vlan_map: dict[str, str],
    host_map: dict[str, str],
    cred_map: dict[str, str],
    used: set[str],
    hex_source: HexFn,
) -> None:
    for field, m in (("management_vlan", vlan_map),
                     ("hosted_on", host_map),
                     ("credential_ref", cred_map)):
        v = host.get(field)
        if v:
            host[field] = m.get(v, v)
    for iface in (host.get("interfaces") or []):
        for field in ("access_vlan", "native_vlan"):
            v = iface.get(field)
            if v:
                iface[field] = vlan_map.get(v, v)
        if iface.get("allowed_vlans"):
            iface["allowed_vlans"] = [vlan_map.get(v, v) for v in iface["allowed_vlans"]]
        ct = iface.get("connected_to") or {}
        if ct.get("host_id"):
            ct["host_id"] = host_map.get(ct["host_id"], ct["host_id"])
    for svc in (host.get("services") or []):
        if svc.get("credential_ref"):
            svc["credential_ref"] = cred_map.get(svc["credential_ref"], svc["credential_ref"])
        if svc.get("id"):
            svc["id"] = alloc_id("s", used, hex_source)


def reid_data_inplace(data: dict, hex_source: HexFn) -> None:
    used: set[str] = set()
    if isinstance(data.get("networks"), dict):
        net_map = {old: alloc_id("n", used, hex_source)
                   for old in data["networks"].keys()}
        for net in data["networks"].values():
            reid_network_inplace(net, used, hex_source)
        data["networks"] = {net_map[k]: v for k, v in data["networks"].items()}
        if data.get("activeNetworkId"):
            data["activeNetworkId"] = net_map.get(data["activeNetworkId"],
                                                  data["activeNetworkId"])
    elif "vlans" in data or "hosts" in data:
        reid_network_inplace(data, used, hex_source)
    else:
        print("error: input does not look like a network-import JSON "
              "(missing 'networks' and 'vlans'/'hosts')", file=sys.stderr)
        sys.exit(1)


def print_rows(label: str, rows: list[dict]) -> None:
    print(f"{label}: {len(rows)} dangling ref(s)", file=sys.stderr)
    for r in rows:
        print(f"  - {r}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    p.add_argument("input", help="Plaintext network-import JSON to rewrite")
    p.add_argument("output", help="Path for the rewritten JSON")
    p.add_argument("--seed", help="Hex seed for deterministic ID generation "
                                  "(testing/fixture-regen). Omit for "
                                  "cryptographically random IDs.")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error reading {args.input}: {e}", file=sys.stderr)
        return 1

    pre = validate_data(data)
    if pre:
        print_rows("input has dangling refs — refusing to reid. "
                   "Fix in the app, then re-run.", pre)
        return 2

    reid_data_inplace(data, make_hex_source(args.seed))

    post = validate_data(data)
    if post:
        print_rows("post-reid validation failed (this is a bug in the script)",
                   post)
        return 3

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    except OSError as e:
        print(f"error writing {args.output}: {e}", file=sys.stderr)
        return 1

    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
