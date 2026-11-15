"""Client for the Free-WILi OG's MAIN-processor USB console.

Independently written. Navigates the OG's letter-key menu tree to run its
own advertised Wi-Fi scan, BLE scan, and sub-GHz radio checks. Never sends
a command that is not an exact, currently-displayed menu entry; never saves
settings, flashes firmware, or restarts the device unless the caller
explicitly requests the (clearly labeled) reset action.
"""
from __future__ import annotations

import os
import sys
import re
from dataclasses import dataclass, field
from typing import Optional

from .menu import normalize_label, parse_event_frames, parse_menu

_DEBUG_MENU = bool(os.environ.get("FREEWILI_DEBUG_MENU"))
from .parsers import og_ble_records, og_wifi_records
from .transport import DeviceCommunicationError, SerialLink

CTRL_C = b"\x03\n"


class UnsupportedFeature(RuntimeError):
    """Raised when the connected firmware does not advertise a needed menu."""


class CommandFailed(RuntimeError):
    """Raised when a command is sent but the device reports/implies failure."""


@dataclass
class OgIdentity:
    port: str
    firmware_kind: str  # "menu", "wilidoro", "bootloader", "unresponsive", "unknown"
    banner: str
    root_menu_text: str = ""
    menu_capabilities: dict = field(default_factory=dict)


class OgConsole:
    """Owns one SerialLink to the OG MAIN console and knows its menu
    protocol. Does not itself acquire the cross-process port lock; callers
    are expected to wrap use of this class with transport.PortLock.
    """

    def __init__(self, port: str):
        self.port = port
        self.link = SerialLink(port, baudrate=115200, rtscts=False)
        self.identity: Optional[OgIdentity] = None

    def __enter__(self) -> "OgConsole":
        from .transport import find_og_main
        if find_og_main(self.port).is_raw_bridge:
            raise UnsupportedFeature('The OG runs bnbridge. Use its GhostESP Wi-Fi/BLE/capture tools; legacy menus and sub-GHz controls are unavailable.')
        self.link.open()
        try:
            self.identity = self._identify()
        except BaseException:
            self.link.close()
            raise
        return self

    def __exit__(self, *_exc):
        self.link.close()

    # -- identification -------------------------------------------------
    def _identify(self) -> OgIdentity:
        banner = self.link.read_for(2).decode("utf-8", errors="replace")
        if "[wilidoro]" in banner.lower():
            return OgIdentity(self.port, "wilidoro", banner)
        if re.search(r"bootloader|FWOG.*boot", banner, re.I):
            return OgIdentity(self.port, "bootloader", banner)
        try:
            probe = self.link.send(CTRL_C, 1.2).decode("utf-8", errors="replace")
        except DeviceCommunicationError:
            return OgIdentity(self.port, "unresponsive", banner)
        menu = parse_menu(probe)
        if len(menu) >= 3 and re.search(r"Enter Letter|Main Menu|IO functions", probe, re.I):
            root_text = self.root()
            return OgIdentity(self.port, "menu", banner, root_text)
        return OgIdentity(self.port, "unknown", banner)

    def require_menu(self) -> None:
        if not self.identity or self.identity.firmware_kind != "menu":
            kind = self.identity.firmware_kind if self.identity else "unidentified"
            raise UnsupportedFeature(
                f"{self.port}: firmware interface is '{kind}', which does not expose "
                "the standard letter-key radio menu. This capability is unavailable "
                "on the currently running firmware, not merely unverified.")

    def _send_until_settled(self, data: bytes, seconds: float = 0.65, retries: int = 6) -> str:
        """Send data and read the response, retrying extra reads until the
        console prompt looks genuinely complete: it must contain
        'Enter Letter', parse to a non-empty menu, AND have gone briefly
        quiet (no more bytes arriving), before being trusted.

        The OG can still be mid-print when an earlier, shorter read window
        closed; trusting that partial read corrupts the next menu parse
        with a truncated fragment or an apparently empty menu. This was
        observed as an intermittent race specifically on the first menu
        navigation after identification.
        """
        text = self.link.send(data, seconds).decode("utf-8", errors="replace")
        attempt = 0
        while attempt < retries and ("Enter Letter" not in text or not parse_menu(text)):
            if _DEBUG_MENU:
                print(f"[menu-debug]   settle retry {attempt} after send {data!r}; text so far: {text!r}", flush=True, file=sys.stderr)
            text += self.link.read_for(0.5).decode("utf-8", errors="replace")
            attempt += 1
        return text

    def root(self) -> str:
        """Return to, and verify arrival at, the OG's actual top-level menu.

        A single 'q' only backs out one menu level, and the previous
        command's own response text can still be arriving when the next
        read window closes. Observed in practice: a navigation into a
        deep/argument-taking submenu (e.g. Radio Functions' hex 'Write')
        can leave enough residual state that one root() call returns an
        incomplete or wrong screen. This retries the full exit sequence,
        and verifies the result against the known fixed set of top-level
        keys rather than just "parses as some menu", before trusting it.
        """
        expected_root_keys = {"o", "s", "r", "i", "u", "e", "g", "w", "m", "d", "x", "z"}
        for full_attempt in range(3):
            self.link.send(b"q\nq\nq\nq\n", 0.5)
            text = self._send_until_settled(CTRL_C, 0.7, retries=2)
            if expected_root_keys <= set(parse_menu(text).keys()):
                return text
        # Give up trying to be clever; return whatever the last attempt saw
        # so callers see an honest (possibly empty) menu rather than hang.
        return text

    def _reset_to_root_hard(self) -> None:
        """Best-effort recovery when root() keeps failing to verify: send a
        burst of 'q' and Ctrl-C with pauses, draining any stale buffered
        output in between."""
        for _ in range(3):
            self.link.write(b"q\n")
            self.link.read_for(0.3)
        self.link.write(CTRL_C)
        self.link.read_for(0.5)

    def navigate(self, path: tuple[str, ...]) -> str:
        text = self.root()
        for key in path:
            if key not in parse_menu(text):
                raise UnsupportedFeature(
                    f"Menu entry {key!r} is not present at this step; refusing to guess a command.")
            text = self._send_until_settled((key + "\n").encode("ascii"), 0.65)
        return text

    def find_submenu(self, target: str) -> tuple[tuple[str, ...], str]:
        """Breadth-first search for a submenu by normalized label, following
        only known safe container menus (never settings/flasher/AP-start).

        Container labels are scoped per target: the OG's "Radio Functions"
        menu (sub-GHz CC1101 control, including a raw hex 'Write' command
        that expects an argument) is never entered while searching for
        wifi/ble, both because it is irrelevant to those targets and
        because briefly visiting it has been observed to leave the
        console's input parser in a state that stalls the next root-menu
        navigation (likely related to its argument-expecting commands).
        """
        self.require_menu()
        target_labels = {
            "wifi": {"wififunctions", "wifi"},
            "ble": {"btfunctions", "bluetoothle", "bluetooth", "bt"},
            "radio": {"radio", "radiofunctions"},
        }[target]
        container_labels = {
            "wifi": {"wireless", "extendedmenus", "extendedmenu", "extendedfunctions",
                    "wififunctions", "wifi", "iofunctions"},
            "ble": {"wireless", "extendedmenus", "extendedmenu", "extendedfunctions",
                   "btfunctions", "bluetoothle", "bluetooth", "bt", "iofunctions"},
            "radio": {"radio", "radiofunctions"},
        }[target]

        def navigate_verified(path: tuple[str, ...]) -> str:
            """Like navigate(), but retries once from a hard-reset root if
            the destination menu comes back empty. The OG's console has
            been observed to occasionally return only the echoed keystroke
            for one navigation step after earlier, unrelated submenu
            visits in the same session; a hard resync recovers it."""
            text = self.navigate(path)
            if path and not parse_menu(text):
                self._reset_to_root_hard()
                text = self.navigate(path)
            return text

        queue = [()]
        visited: set[tuple[str, ...]] = set()
        max_iterations = 64  # hard safety cap: never loop indefinitely
        iterations = 0
        while queue:
            iterations += 1
            if iterations > max_iterations:
                raise UnsupportedFeature(
                    f"Gave up looking for a {target} submenu after {max_iterations} menu "
                    "navigations without finding one; the menu tree may be larger or more "
                    "dynamic than expected.")
            path = queue.pop(0)
            if path in visited:
                continue
            visited.add(path)
            text = navigate_verified(path)
            if _DEBUG_MENU:
                print(f"[menu-debug] visit {path} -> {parse_menu(text)}", flush=True, file=sys.stderr)
            if len(path) >= 4:
                continue
            for key, label in parse_menu(text).items():
                norm = normalize_label(label)
                if _DEBUG_MENU:
                    print(f"[menu-debug]   key={key!r} label={label!r} norm={norm!r} "
                          f"in_target={norm in target_labels} in_container={norm in container_labels}", flush=True, file=sys.stderr)
                if norm in target_labels:
                    found_path = path + (key,)
                    child_text = navigate_verified(found_path)
                    if _DEBUG_MENU:
                        print(f"[menu-debug] target candidate {found_path} -> {parse_menu(child_text)}", flush=True, file=sys.stderr)
                    if len(parse_menu(child_text)) >= 2:
                        return found_path, child_text
                elif norm in container_labels and (path + (key,)) not in visited:
                    queue.append(path + (key,))
                    if _DEBUG_MENU:
                        print(f"[menu-debug]   queued {path + (key,)}; queue now {queue}", flush=True, file=sys.stderr)
        raise UnsupportedFeature(
            f"No {target} submenu is advertised by this firmware's menu tree.")

    def run_menu_action(self, path: tuple[str, ...], menu_text: str, accepted_labels: set[str],
                        argument: Optional[str] = None, seconds: float = 1.0) -> tuple[str, tuple[str, ...]]:
        wanted = {normalize_label(label) for label in accepted_labels}
        entries = parse_menu(menu_text)
        matches = [key for key, label in entries.items()
                   if normalize_label(label.split("[")[0]) in wanted]
        if len(matches) != 1:
            raise UnsupportedFeature(
                f"None (or more than one) of the expected menu actions {sorted(accepted_labels)} "
                "is currently advertised.")
        live_menu = self.navigate(path)
        live_label = parse_menu(live_menu).get(matches[0], "")
        if normalize_label(live_label.split("[")[0]) not in wanted:
            raise UnsupportedFeature("The menu changed between inspection and execution; refusing to proceed.")
        command_path = path + (matches[0],)
        command = matches[0] + "\n"
        if argument is not None:
            command += argument + "\n"
        text = self.link.send(command.encode("ascii"), seconds).decode("utf-8", errors="replace")
        responses = [f for f in parse_event_frames(text) if f["id"] == "\\".join(command_path)]
        if not responses:
            raise CommandFailed("No command-response frame arrived; execution could not be verified.")
        if not responses[-1]["ok"]:
            raise CommandFailed(responses[-1]["payload"])
        if re.search(r"ESP32\s+Not Connected|radio not responding|module not connected", text, re.I):
            raise CommandFailed(
                "Wireless module is not responding. Check Bottlenose's Orca-communication "
                "selection and that its firmware is actually running.")
        return text, command_path

    # -- capability probing ---------------------------------------------
    def probe_capabilities(self) -> dict:
        """Report, without changing device state, which menus/features this
        firmware actually advertises. Used to answer 'is X available?'
        honestly instead of assuming vendor defaults.

        Each of the three lookups (wifi/ble/radio) is independent: if one
        is slow or fails against a currently flaky link, the others are
        still attempted and reported, rather than one bad lookup blocking
        every result.
        """
        result = dict(firmware_kind=self.identity.firmware_kind if self.identity else "unidentified")
        if not self.identity or self.identity.firmware_kind != "menu":
            result["wifi"] = result["ble"] = result["subghz"] = "unavailable"
            result["reason"] = (
                f"Firmware interface is '{result['firmware_kind']}'; it does not expose "
                "the standard radio menu at all.")
            return result
        for target in ("wifi", "ble", "radio"):
            key = "subghz" if target == "radio" else target
            try:
                _, menu_text = self.find_submenu(target)
                result[key] = "available"
                result[key + "_menu_entries"] = parse_menu(menu_text)
            except UnsupportedFeature as exc:
                result[key] = "unavailable"
                result[key + "_reason"] = str(exc)
            except CommandFailed as exc:
                result[key] = "error"
                result[key + "_reason"] = str(exc)
        return result

    # -- Wi-Fi / BLE discovery -------------------------------------------
    def wifi_scan(self, seconds: int) -> dict:
        path, menu = self.find_submenu("wifi")
        changed_stream = False
        try:
            if re.search(r"Stream\s+Wifi\s+Events\s*:\s*0\b", menu, re.I):
                self.run_menu_action(path, menu, {"Enable Wifi Events"})
                changed_stream = True
            text, _ = self.run_menu_action(path, menu, {"Scan for Access Points"}, None, seconds + 2)
        finally:
            if changed_stream:
                self.run_menu_action(path, menu, {"Enable Wifi Events"})
        return dict(records=og_wifi_records(text), raw_text=text)

    def ble_scan(self, seconds: int) -> dict:
        path, menu = self.find_submenu("ble")
        text, _ = self.run_menu_action(path, menu, {"Scan for BT Devices"}, str(seconds * 1000), seconds + 2)
        return dict(records=og_ble_records(text), raw_text=text)

    # -- Sub-GHz (CC1101 x2) ----------------------------------------------
    def subghz_radio_status(self, radio_index: int) -> dict:
        """Select a radio index and read RSSI only. Does not enable event
        streaming and does not change frequency/modulation settings."""
        if radio_index not in (1, 2):
            raise ValueError("radio_index must be 1 or 2.")
        path, menu = self.find_submenu("radio")
        entries = {normalize_label(label.split("[")[0]) for label in parse_menu(menu).values()}
        if not ({"selectradio", "selectradio12"} & entries):
            raise UnsupportedFeature(
                "This firmware's radio menu does not advertise the two-radio selector command.")
        self.run_menu_action(path, menu, {"Select Radio", "Select Radio (1/2)"}, str(radio_index))
        rssi_values = []
        rssi_labels = {"RSSI", "Read RSSI", "Get RSSI"}
        if entries & {normalize_label(x) for x in rssi_labels}:
            for _ in range(3):
                text, cmd_path = self.run_menu_action(path, menu, rssi_labels)
                reply = [f for f in parse_event_frames(text) if f["id"] == "\\".join(cmd_path) and f["ok"]]
                if reply and re.fullmatch(r"-?\d+", reply[-1]["payload"]):
                    rssi_values.append(int(reply[-1]["payload"]))
        return dict(radio_index=radio_index, rssi_dbm=rssi_values,
                    frequency_note=("The OG does not report which physical frequency this radio "
                                    "index is tuned to; that is a device setting made separately "
                                    "in the OG menu and is not read back here."))

    def subghz_listen(self, radio_index: int, seconds: int) -> dict:
        """Temporarily enable this radio's receive-event stream, collect
        whatever arrives for `seconds`, then always disable it again.

        This only *listens*; it never transmits, and it restores the
        previous streaming state (off) before returning, even on error.
        """
        if radio_index not in (1, 2):
            raise ValueError("radio_index must be 1 or 2.")
        path, menu = self.find_submenu("radio")
        entries = {normalize_label(label.split("[")[0]) for label in parse_menu(menu).values()}
        if not ({"selectradio", "selectradio12"} & entries):
            raise UnsupportedFeature(
                "This firmware's radio menu does not advertise the two-radio selector command.")
        self.run_menu_action(path, menu, {"Select Radio", "Select Radio (1/2)"}, str(radio_index))
        event_labels = {"Enable Radio Events", "Enable Radio Event Streaming", "Enable Read Events"}
        if not (entries & {normalize_label(x) for x in event_labels}):
            raise UnsupportedFeature(
                "This firmware's radio menu does not advertise a receive-event-streaming command.")
        events, diagnostics = [], []
        try:
            text, _ = self.run_menu_action(path, menu, event_labels, "1", seconds)
            received = [f for f in parse_event_frames(text) if f["id"].lower() == f"*radio{radio_index}" and f["ok"]]
            for frame in received:
                if re.fullmatch(r"(?:[0-9a-fA-F]{2}\s*)+", frame["payload"]):
                    events.append(frame)
                else:
                    diagnostics.append(frame)
        finally:
            self.run_menu_action(path, menu, event_labels, "0")
        return dict(radio_index=radio_index, events=events, diagnostic_events=diagnostics,
                    frequency_note=("The OG does not report which physical frequency this radio "
                                    "index is tuned to; pass the band you know it was configured "
                                    "for separately."))

    def software_reset(self, confirm: bool) -> None:
        """Explicit, opt-in MAIN software reset. Never called implicitly by
        any scan/listen method in this module."""
        if not confirm:
            raise PermissionError("software_reset requires confirm=True from an explicit user approval.")
        self.require_menu()
        settings_text = self.navigate(("z",))
        reset_key = next((k for k, v in parse_menu(settings_text).items()
                          if normalize_label(v) == "softwarereset"), None)
        if not reset_key:
            raise UnsupportedFeature("No 'Software Reset' entry is advertised in Settings.")
        self.link.send((reset_key + "\n").encode("ascii"), 0.3)
