#!/usr/bin/env python3
"""Recovered client-side player-information packet constructor.

Original client  1.7.6  (BHNetClientMatch -sendPlayerInformationToServer:password:,
disassembled at libApplication.so 0x833a60, ARM32):
  * NSMutableData starts with prefix byte 0x1f
  * copies myPlayerInfo dict (keys below, recovered from the ORIGINAL SERVER
    BHNetServerMatch -clientPlayerInformationRecieved:fromPeer: 0x4f8d70,
    GNUstep string table at server .data 0xbc2208..0xbc23d0)
  * optional clientPassword value under key 'clientPassword'
  * serializes with NSPropertyListSerialization XML (format 100; the constant
    0x64 is passed where the XML format enum is expected), appends to the
    prefix byte and transmits.

The server performs NO minorVersion gate: it reads the key and stores it
(0x4fa288 cmp/je skip, 0x4fa348 setValue:forKey:). Any value is accepted.

This module builds the exact byte stream (0x1f + XML plist) so the local
probe can perform the real first join step against the original server.
"""

import plistlib

PREFIX = 0x1F

# Keys observed in the original server receive path (server .data table).
SERVER_KEYS = [
    "alias", "local", "micOrSpeakerOn", "voiceConnected", "playerID",
    "udidNew", "photo", "connected", "cloudKey", "ip", "iCloudID",
    "gameCenterID", "minorVersion", "clientPassword",
]

# Keys the real client always carries (read multiple times by the server;
# udidNew drives reconnect identification at 0x4f9280/0x4f92dc/0x4f9336).
CORE_KEYS = ["alias", "playerID", "udidNew", "local", "micOrSpeakerOn",
             "voiceConnected", "photo", "connected", "ip", "minorVersion"]
# Keys present only when the player actually has them (server skips missing).
OPTIONAL_KEYS = ["cloudKey", "iCloudID", "gameCenterID", "clientPassword"]


def build_player_info_dict(alias="probe", player_id="probe-player-0001",
                           minor_version=176, local=True,
                           mic_or_speaker_on=False, voice_connected=False,
                           photo=b"", connected=True, cloud_key=None,
                           ip="127.0.0.1", icloud_id=None,
                           game_center_id=None, udid_new="probe-udid-0001",
                           client_password=None):
    """Build the myPlayerInfo-style dict using only keys the original server
    actually reads. None-valued optional keys are omitted (server treats a
    missing key as nil and skips it; the client's own dict also omits
    nils)."""
    d = {
        "alias": alias,
        "playerID": player_id,
        "udidNew": udid_new,
        "local": local,
        "micOrSpeakerOn": mic_or_speaker_on,
        "voiceConnected": voice_connected,
        "photo": photo,
        "connected": connected,
        "ip": ip,
        "minorVersion": minor_version,
    }
    if cloud_key is not None:
        d["cloudKey"] = cloud_key
    if icloud_id is not None:
        d["iCloudID"] = icloud_id
    if game_center_id is not None:
        d["gameCenterID"] = game_center_id
    if udid_new is not None:
        d["udidNew"] = udid_new
    if client_password is not None:
        d["clientPassword"] = client_password
    return d


def serialize_xml_plist(d):
    """GNUstep-compatible XML plist bytes. plistlib emits Apple DTD; GNUstep
    parses both. Keep format==100 semantics (NSPropertyListXMLFormat_v1_0)."""
    return plistlib.dumps(d, fmt=plistlib.FMT_XML, sort_keys=False)


def build_packet(d=None, **kwargs):
    """Full wire packet: single 0x1f byte + XML plist of the dict."""
    if d is None:
        d = build_player_info_dict(**kwargs)
    body = serialize_xml_plist(d)
    return bytes([PREFIX]) + body


def parse_packet(packet):
    """Inverse: verify prefix, parse the remaining bytes as plist."""
    assert packet[0] == PREFIX, f"bad prefix {packet[0]:#x}"
    return plistlib.loads(packet[1:])


if __name__ == "__main__":
    import sys
    pkt = build_packet()
    print(f"packet: {len(pkt)} bytes, prefix {pkt[0]:#x}")
    print(parse_packet(pkt))