#!/usr/bin/env python3
"""Tests for the recovered player-information packet constructor.

Verifies:
  * mandatory prefix byte 0x1f
  * every key the original server reads is emitted
  * optional keys are omitted when None (server skips missing keys, so the
    constructor must never invent them)
  * XML plist round-trip preserves values
  * packet is a strict 0x1f + plist split (prefix never corrupts the plist)
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plistlib
from player_info_packet import (
    PREFIX, SERVER_KEYS, CORE_KEYS, OPTIONAL_KEYS,
    build_packet, build_player_info_dict, parse_packet,
)

FAIL = []


def check(name, cond, extra=""):
    if not cond:
        FAIL.append(name)
        print(f"FAIL {name} {extra}")
    else:
        print(f"ok   {name}")


# 1. prefix byte
pkt = build_packet()
check("prefix==0x1f", pkt[0] == PREFIX, hex(pkt[0]))

# 2. core keys always present in default packet
d = build_player_info_dict()
missing_core = [k for k in CORE_KEYS if k not in d]
check("core-keys-present", not missing_core, str(missing_core))

# 2b. optional keys omitted by default
missing_opt = [k for k in OPTIONAL_KEYS if k in d]
check("optional-keys-omitted", not missing_opt, str(missing_opt))

# 3. optional keys omitted when None
check("cloudKey-omitted", "cloudKey" not in d)
check("clientPassword-omitted", "clientPassword" not in d)

# 4. optional keys present when set
d2 = build_player_info_dict(client_password="sekret", cloud_key="ck")
check("clientPassword-set", d2["clientPassword"] == "sekret")
check("cloudKey-set", d2["cloudKey"] == "ck")

# 5. XML plist round-trip, exact values
pkt2 = build_packet(d2)
parsed = parse_packet(pkt2)
check("roundtrip-alias", parsed["alias"] == "probe")
check("roundtrip-password", parsed["clientPassword"] == "sekret")
check("roundtrip-minorVersion", parsed["minorVersion"] == 176)
check("roundtrip-local-bool", parsed["local"] is True)

# 6. packet split is clean: 0x1f then a complete single plist document
body = pkt2[1:]
check("body-xml-open", body.lstrip()[:5] == b"<?xml")
doc = plistlib.loads(body)
check("body-parses", isinstance(doc, dict))

# 7. photo bytes preserved (binary data in plist becomes <data>)
d3 = build_player_info_dict(photo=b"\x00\x01\x02\xff")
p3 = parse_packet(build_packet(d3))
check("photo-bytes", p3["photo"] == b"\x00\x01\x02\xff")

# 8. strict: no trailing bytes after plist end
p4 = build_packet()
trailing = p4[1:].find(b"</plist>")
check("plist-terminates", trailing != -1 and
      p4[1:][trailing + len(b"</plist>"):].strip() == b"")

print()
if FAIL:
    print(f"FAILED: {FAIL}")
    sys.exit(1)
print("ALL PASS")