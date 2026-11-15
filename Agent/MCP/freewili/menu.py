"""Text parsing for the Free-WILi OG's console menu protocol.

Independently written against the observed wire format (letter-key menus,
`[*id tick seq payload ok]` event frames) described in the parent project's
README/REPAIR-REPORT and the vendor's own main-menu-commands documentation.
No code is copied from wireless_tests.py; the regular expressions and
parsing logic here are new.
"""
from __future__ import annotations

import re

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MENU_LINE_RE = re.compile(r"^\s*([a-zA-Z0-9?])\)\s*(.+?)\s*$", re.MULTILINE)
# Event/response frames of the form: [id tick seq payload ok]
EVENT_FRAME_RE = re.compile(
    r"\[(?P<id>\*\w+|[a-zA-Z?](?:\\[a-zA-Z0-9?])*)"
    r"[ \t]+(?P<tick>[0-9a-fA-F]+)[ \t]+(?P<seq>\d+)[ \t]"
    r"(?P<payload>.*?)\s+(?P<ok>[01])\s*\]",
    re.DOTALL,
)
MAC_PATTERN = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def normalize_label(value: str) -> str:
    """Collapse a menu label to lowercase alphanumerics for robust matching."""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def parse_menu(text: str) -> dict[str, str]:
    """Extract {key: label} pairs from a 'x) Label' style menu dump."""
    clean = strip_ansi(text).replace("\r\n", "\n").replace("\r", "\n")
    return {key: label for key, label in MENU_LINE_RE.findall(clean)}


def parse_event_frames(text: str) -> list[dict]:
    """Extract every [*id tick seq payload ok] frame found in text."""
    return [
        dict(
            id=m["id"],
            device_tick_hex=m["tick"],
            sequence=int(m["seq"]),
            payload=m["payload"].strip(),
            ok=m["ok"] == "1",
        )
        for m in EVENT_FRAME_RE.finditer(text)
    ]


def frames_matching(text: str, frame_id: str) -> list[dict]:
    target = frame_id.lower()
    return [f for f in parse_event_frames(text) if f["id"].lower() == target]
