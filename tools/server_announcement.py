"""Bounded application-message decoder for the observed server announcement.
Header bytes are source-confirmed; meanings of other message IDs remain unknown.
This is NOT a complete original-client receive dispatcher.
"""
from dataclasses import dataclass
import plistlib
from xml.parsers.expat import ExpatError

@dataclass(frozen=True)
class Announcement:
    raw: bytes
    fields: dict

@dataclass(frozen=True)
class UnknownMessage:
    raw: bytes

class MalformedAnnouncement(ValueError):
    pass


def decode_message(payload: bytes):
    if not isinstance(payload, bytes):
        raise TypeError('payload must be immutable bytes')
    if not payload.startswith(b'\x23\x26'):
        return UnknownMessage(payload)
    try:
        fields = plistlib.loads(payload[2:])
    except (ValueError, ExpatError, OverflowError) as exc:
        raise MalformedAnnouncement('announcement plist cannot be decoded') from exc
    if not isinstance(fields, dict):
        raise MalformedAnnouncement('announcement payload must be a dictionary')
    # Optional and unknown keys are retained. No invented defaults or coercion.
    return Announcement(payload, fields)
