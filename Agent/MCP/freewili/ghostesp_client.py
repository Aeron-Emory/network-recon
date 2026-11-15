"""Client for the GhostESP firmware running on Bottlenose's ESP32-C6.

Independently written against GhostESP's public CLI command surface
(https://github.com/GhostESP-Revival/GhostESP) and the OG's raw-UART
write/read API (documented in the vendor's main-menu-commands reference).
No code is shared with ghostesp_tests.py in the parent workshop folder.

Only a fixed grammar of discovery/status commands is sent:
  chipinfo, stop, scanap, blescan -adv, blescan -g, blescan -s, listadv,
  listgatt, selectgatt, enumgatt, capture -wireshark, capture -stop.
Discovery may send standard scan/probe requests. This module cannot send blespam, badble,
chameleon write/emulate, AP-join, or arbitrary transmit/attack commands.
"""
from __future__ import annotations

import time
import re
from dataclasses import dataclass
from typing import Optional

from .menu import parse_event_frames
from .og_client import OgConsole, UnsupportedFeature
from .parsers import (
    ghostesp_ble_records, ghostesp_chip_info, ghostesp_gatt_device_records,
    ghostesp_gatt_service_records, ghostesp_wifi_records, extract_radiotap_pcap,
)
from .transport import DeviceCommunicationError, SerialLink, find_og_main, operation_deadline

EXPECTED_FIRMWARE_MARKER = "GhostESP Revival"
EXPECTED_MODEL_MARKER = "ESP32-C6"

# The only commands this client is allowed to construct and send. Enforced
# centrally in _send_allowed so no call site can smuggle another command in.
_ALLOWED_COMMAND = re.compile(
    r'(?:chipinfo|stop|blescan -(?:adv|g|s)|listadv|listgatt|enumgatt|'
    r'selectgatt [0-9]{1,3}|scanap (?:[1-9]|[12][0-9]|30)|'
    r'capture -wireshark -c (?:[1-9]|1[01])|capture -stop)')


def _duration(seconds):
    if type(seconds) is not int or not 1 <= seconds <= 30:
        raise ValueError('seconds must be an integer from 1 through 30.')


class GhostEspProtocolError(RuntimeError):
    pass


def _uart_chunks(payload: bytes) -> list[bytes]:
    # The OG's legacy console input line is short; a long hex-encoded
    # command would overflow it, so it is always sent in bounded pieces.
    return [payload[i:i + 16] for i in range(0, len(payload), 16)]


@dataclass
class GhostEspIdentity:
    firmware: Optional[str]
    model: Optional[str]
    matches_expected: bool
    raw_chipinfo: dict


class GhostEspLink:
    """Talks to GhostESP either directly over its own USB serial, or
    bridged through the OG MAIN console's raw-UART write/read API.
    """

    def __init__(self, via_og: bool, port: str):
        self.via_og = via_og
        self.port = port
        self.og: Optional[OgConsole] = None
        self.direct: Optional[SerialLink] = None
        self._pending = ""
        self._stream_events_enabled = False
        self._active = None

    def __enter__(self) -> "GhostEspLink":
        raw_bridge = self.via_og and find_og_main(self.port).is_raw_bridge
        if self.via_og and not raw_bridge:
            self.og = OgConsole(self.port).__enter__()
            if not self.og.identity or self.og.identity.firmware_kind != "menu":
                self.og.__exit__()
                raise UnsupportedFeature(
                    f"Expected the OG MAIN menu console on {self.port}, got "
                    f"{self.og.identity.firmware_kind if self.og.identity else 'no identity'}.")
            state_match = __import__("re").search(
                r"gpiouart[^\r\n]*stream\s*:\s*([01])", self.og.identity.root_menu_text)
            if not state_match:
                self.og.__exit__()
                raise GhostEspProtocolError(
                    "Could not read the OG's UART read-event streaming state from its menu header.")
            self._stream_events_enabled = state_match[1] == "0"
            self.og.link.send(b"\x02\n", 0.5)  # stateless API mode
            if self._stream_events_enabled:
                self.og.link.send(b"u\nr\n1\n", 0.5)
        else:
            self.direct = SerialLink(self.port, baudrate=115200, rtscts=False)
            self.direct.open()
        try:
            self._read_for(0.3)
        except BaseException:
            if self.direct:
                self.direct.close()
            if self.og:
                self.og.link.close()
            raise
        return self

    def __exit__(self, *_exc):
        if self._active:
            try:
                with operation_deadline(5):
                    self._send_allowed('capture -stop' if self._active == 'capture' else 'blescan -s', 2)
            except (DeviceCommunicationError, OSError):
                pass
        if self.og:
            try:
                if self._stream_events_enabled:
                    self.og.link.send(b"u\nr\n0\n", 0.5)
                self.og.root()
            finally:
                self.og.__exit__()
        elif self.direct:
            self.direct.close()

    # -- transport plumbing ----------------------------------------------
    def _unwrap_og_events(self, text: str) -> bytes:
        self._pending += text
        output = bytearray()
        used = 0
        for match in __import__("re").finditer(
            r"\[(?P<id>\*\w+)[ \t]+[0-9a-fA-F]+[ \t]+\d+[ \t](?P<payload>.*?)\s+(?P<ok>[01])\s*\]",
            self._pending, __import__("re").DOTALL,
        ):
            used = match.end()
            if match["id"].lower() == "*uart1" and match["ok"] == "1":
                try:
                    output.extend(bytes.fromhex(match["payload"]))
                except ValueError:
                    pass
        self._pending = self._pending[used:][-2_000_000:]
        return bytes(output)

    def _read_for(self, seconds: float) -> bytes:
        if self.og:
            text = self.og.link.read_for(seconds).decode("utf-8", errors="replace")
            return self._unwrap_og_events(text)
        return self.direct.read_for(seconds)

    def _send_allowed(self, command: str, seconds: float = 2.0) -> bytes:
        if not _ALLOWED_COMMAND.fullmatch(command):
            raise PermissionError(
                f"Refusing to send non-allow-listed GhostESP command: {command!r}. "
                "This client can only send the fixed passive/read command set.")
        if "\n" in command or "\r" in command or len(command) > 160:
            raise ValueError("Expected one bounded, single-line CLI command.")
        payload = (command + "\n").encode("ascii")
        if self.og:
            output = bytearray()
            chunks = _uart_chunks(payload)
            for i, chunk in enumerate(chunks):
                self.og.link.write(("u\nw\n" + chunk.hex(" ") + "\n").encode("ascii"))
                output.extend(self._read_for(seconds if i == len(chunks) - 1 else 0.4))
            return bytes(output)
        self.direct.write(payload)
        return self._read_for(seconds)

    # -- identity ----------------------------------------------------------
    def identify(self) -> GhostEspIdentity:
        raw = self._send_allowed("chipinfo", 3).decode("utf-8", errors="replace")
        info = ghostesp_chip_info(raw)
        firmware = info.get("firmware")
        model = info.get("model")
        matches = bool(firmware and EXPECTED_FIRMWARE_MARKER in firmware
                       and model == EXPECTED_MODEL_MARKER and 'CHIPINFO_END' in raw)
        return GhostEspIdentity(firmware=firmware, model=model, matches_expected=matches, raw_chipinfo=info)

    def stop_all(self) -> None:
        self._send_allowed("stop", 1.5)

    # -- Wi-Fi / BLE discovery ---------------------------------------------
    def wifi_scan(self, seconds: int) -> dict:
        _duration(seconds)
        text = self._send_allowed(f"scanap {seconds}", seconds + 4).decode("utf-8", errors="replace")
        records = ghostesp_wifi_records(text)
        return dict(status='ok' if records else 'inconclusive', records=records, raw_text=text)

    def ble_advertiser_scan(self, seconds: int) -> dict:
        _duration(seconds)
        self._active = 'ble'
        try:
            self._send_allowed("blescan -adv", seconds)
        finally:
            with operation_deadline(5):
                self._send_allowed("blescan -s", 1.5)
                self._active = None
        text = self._send_allowed("listadv", 2).decode("utf-8", errors="replace")
        records = ghostesp_ble_records(text)
        return dict(status='ok' if records else 'inconclusive', records=records, raw_text=text)

    # -- BLE GATT (active: connects to a specific device) ------------------
    def gatt_scan_for_devices(self, seconds: int) -> dict:
        """Passive discovery of connectable BLE devices. Does not connect."""
        _duration(seconds)
        self._active = 'ble'
        try:
            self._send_allowed("blescan -g", seconds)
        finally:
            with operation_deadline(5):
                self._send_allowed("blescan -s", 1.5)
                self._active = None
        text = self._send_allowed("listgatt", 2).decode("utf-8", errors="replace")
        return dict(devices=ghostesp_gatt_device_records(text), raw_text=text)

    def gatt_enumerate(self, device_index: int, confirm_active_connection: bool) -> dict:
        """Connect to one previously discovered device (by its listgatt
        index) and enumerate its GATT services/characteristics.

        This is an ACTIVE operation: it opens a real BLE connection to a
        third-party device and, per GhostESP's own documentation, will
        auto-initiate pairing if the link is not already encrypted. It is
        gated behind `confirm_active_connection=True`, which the MCP tool
        layer only sets after the caller has explicitly opted in for this
        specific device.
        """
        if not confirm_active_connection:
            raise PermissionError(
                "gatt_enumerate connects to a third-party BLE device and may trigger "
                "pairing. Call with confirm_active_connection=True only after explicit "
                "user approval for this specific device.")
        if type(device_index) is not int or not 0 <= device_index <= 999:
            raise ValueError('device_index must be an integer from 0 through 999.')
        self._send_allowed(f"selectgatt {device_index}", 1.5)
        text = self._send_allowed("enumgatt", 12).decode("utf-8", errors="replace")
        return ghostesp_gatt_service_records(text)

    # -- Wi-Fi packet monitor (passive receive only) -----------------------
    def capture(self, channel: int, seconds: int) -> dict:
        _duration(seconds)
        if type(channel) is not int or not 1 <= channel <= 11:
            raise ValueError('channel must be an integer from 1 through 11.')
        self._active = 'capture'
        try:
            raw = self._send_allowed(f"capture -wireshark -c {channel}", seconds)
        finally:
            with operation_deadline(5):
                stopped_raw = self._send_allowed("capture -stop", 3)
                self._active = None
        raw += stopped_raw
        post = self._send_allowed("chipinfo", 3)
        stopped = b"CHIPINFO_END" in post
        try:
            pcap_bytes, packet_rows, details = extract_radiotap_pcap(raw)
        except ValueError as exc:
            pcap_bytes, packet_rows, details = b"", [], dict(error=str(exc))
        intact = details.get('tail_kind') in ('none', 'console_text')
        return dict(pcap_bytes=pcap_bytes, packets=packet_rows, extraction=details,
                    status='ok' if packet_rows and intact and stopped else 'inconclusive',
                    capture_stream_intact=intact, raw_capture_bytes=raw,
                    monitor_stopped_cleanly=stopped)
