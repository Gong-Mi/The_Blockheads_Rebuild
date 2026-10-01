#!/usr/bin/env python3
"""How a name is evidenced in a binary: a ladder, not a boolean.

Scanning raw bytes for a filename is wrong on two counts: `re.findall` over the
whole blob matches *inside* unrelated strings (the ObjC ivar
`OBJC_IVAR_$_KelpPlant.waveTimer` yields a bogus `_KelpPlant.wav`), and a plain
substring test credits a stem that only occurs buried in a longer identifier.

So extraction goes through NUL-delimited strings first, and every name is then
classified by the *strongest* evidence that exists:

  verbatim      the exact filename is its own NUL-terminated string
  format-string a printf pattern carrying this name's prefix would build it
                (e.g. "bird%d.wav" for bird7.wav) - ties the family to the binary
  suffix-composition  the binary appends this extension to a runtime value
                (e.g. "%@.vsh"): proves filenames are built, not which stem
  stem-exact    the stem (name without suffix) is its own NUL string
  stem-prefix   some NUL string starts with the stem (may be a longer identifier)
  substring     the stem only occurs inside some NUL string (weakest)
  unattributed  no evidence in the binary

Callers record the class per row instead of collapsing it, so "we found nothing"
and "we found something weaker than a filename" stay distinguishable.
"""
from __future__ import annotations

import re

_PRINTABLE_TAIL = re.compile(rb"[\x20-\x7e]{3,}$")
_SUFFIXES = (".wav", ".mp4", ".m4a", ".ogg", ".vsh", ".fsh", ".png", ".fnt")


def nul_strings(blob: bytes) -> list[str]:
    """Every printable NUL-terminated run, in order, de-duplicated."""
    out: list[str] = []
    seen: set[str] = set()
    for chunk in blob.split(b"\0"):
        match = _PRINTABLE_TAIL.search(chunk)
        if not match:
            continue
        text = match.group().decode("ascii")
        if text not in seen:
            seen.add(text)
            out.append(text)
    return out


def suffix_of(name: str) -> str:
    stem, dot, suffix = name.rpartition(".")
    return f".{suffix}" if dot else ""


def specific_patterns(name: str) -> list[str]:
    """printf patterns carrying a prefix from this name (ties it to a family).

    bird7.wav -> bird%d.wav: the binary builds exactly this family at runtime.
    """
    stem, dot, suffix = name.rpartition(".")
    if not dot:
        return []
    digits = re.search(r"(\d+)$", stem)
    if not digits:
        return []
    head = stem[: digits.start()]
    return [f"{head}%d.{suffix}", f"{head}%i.{suffix}"]


def generic_patterns(name: str) -> list[str]:
    """Extension-only composition: the binary appends this suffix to *something*.

    `%@.vsh` proves the loader builds shader filenames at runtime; it does not
    tie any particular stem to a call site, so it is graded below a specific
    pattern.
    """
    suffix = suffix_of(name)
    return [f"%s{suffix}", f"%@{suffix}"] if suffix else []


def classify(name: str, strings: list[str], string_set: set[str] | None = None) -> tuple[str, str]:
    """Strongest evidence for `name`; returns (class, detail)."""
    pool = string_set if string_set is not None else set(strings)
    if name in pool:
        return "verbatim", name
    for pattern in specific_patterns(name):
        if pattern in pool:
            return "format-string", pattern
    for pattern in generic_patterns(name):
        if pattern in pool:
            return "suffix-composition", pattern
    stem = name
    for suffix in _SUFFIXES:
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    if len(stem) >= 3:
        if stem in pool:
            return "stem-exact", stem
        for candidate in strings:
            if candidate.startswith(stem):
                return "stem-prefix", candidate
        for candidate in strings:
            if stem in candidate:
                return "substring", candidate
    return "unattributed", ""

_NAME_CHAR = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
)


def contains_token(blob: bytes, token: str) -> bool:
    """Boundary-aware search for `token` in raw bytes.

    For inputs that are not NUL-terminated string tables (JSON, plist, nib,
    dex), the token must be delimited on both sides: neither the byte before nor
    the byte after may be a name character. That is what rejects
    `_KelpPlant.wav` inside `OBJC_IVAR_$_KelpPlant.waveTimer` - there the `_`
    before and the `e` after are both name characters, so the match is not a
    filename reference.
    """
    needle = token.encode()
    start = 0
    while True:
        index = blob.find(needle, start)
        if index < 0:
            return False
        before = blob[index - 1:index]
        after = blob[index + len(needle):index + len(needle) + 1]
        if (not before or chr(before[0]) not in _NAME_CHAR) and (
                not after or chr(after[0]) not in _NAME_CHAR):
            return True
        start = index + 1
