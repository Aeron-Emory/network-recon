"""Free-WILi Recon MCP server (standalone).

Fully independent of the parent "FreeWlli workshop" project: it never
imports, executes, or reads result files from wireless_tests.py or
ghostesp_tests.py. All hardware communication is implemented in the
freewili/ package inside this directory. All new files, logs, and results
are written exclusively under MCP/results/.

Safety boundaries enforced here and in freewili/*:
- Scan tools send a fixed grammar of discovery/status commands
  (ghostesp_client.py). Discovery may emit normal probe/scan requests.
  There is no arbitrary injection, deauthentication, spoofing, or GhostESP
  blespam/badble/chameleon-write features.
- gatt_enumerate_device is the one operation that actively connects to a
  third-party BLE device (and may trigger pairing, per GhostESP's own
  documentation); it refuses to run unless the caller passes
  confirm_active_connection=True after the user has explicitly approved it
  for that specific device.
- reset_og_main_processor is the one operation that restarts the OG; it
  refuses to run unless confirm=True.
- No tool changes UART settings, flashes firmware, or writes startup
  settings.
- Raw observation tools (get_*) return only what the device said.
  analyze_* tools add rule-based, clearly-labeled heuristic findings on top;
  they never fabricate a "confirmed vulnerability".
- If a capability is not advertised by the currently running firmware, the
  relevant tool reports it as unavailable with a reason instead of
  pretending it works.
"""
from __future__ import annotations

from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

import analysis
from freewili import device, transport
from freewili.ghostesp_client import GhostEspLink, GhostEspProtocolError
from freewili.radio_client import RadioClient, find_radio_port
from freewili.og_client import CommandFailed, OgConsole, UnsupportedFeature
from freewili.results_store import list_runs, load_observation, new_run_dir, save_json, observation_page
from freewili.transport import DeviceCommunicationError, DeviceNotFoundError, PortBusyError

mcp = FastMCP(
    "freewili-recon",
    instructions=(
        "Standalone tools for Wi-Fi/BLE discovery, passive 802.11 capture, "
        "and CC1101 sub-GHz data from a Free-WILi OG + Bottlenose device, and "
        "for inferring likely security weaknesses from that data. All "
        "'analyze_*' findings are heuristic indicators for a human to verify, "
        "not confirmed vulnerabilities. Use only on networks/devices the user "
        "is authorized to assess. Everything here is independent of any other "
        "project in this workspace. gatt_enumerate_device actively connects to "
        "a BLE device and may trigger pairing; it requires explicit per-device "
        "approval. reset_og_main_processor restarts the OG; it requires "
        "explicit approval. No tool flashes firmware, changes UART settings, "
        "or performs active attacks."
        " Saved scan/capture replies contain bounded previews with full counts. "
        "Use analyze_* with run_name=saved_to to analyze the entire saved observation, "
        "and get_saved_observation for pages. list_saved_runs returns paginated metadata."
    ),
)


_HARDWARE_CALL_HARD_TIMEOUT_S = 90


def _saved_reply(result, save):
    return observation_page(result) if save else result


def _analysis_input(value, run_name, field=None):
    if (value is None) == (run_name is None):
        raise ValueError('Supply exactly one of inline data or run_name; run_name analyzes the FULL saved observation.')
    if run_name is not None:
        value = load_observation(run_name)
        if field is not None:
            if field not in value:
                raise ValueError(f'Saved run has no {field} array.')
            value = value[field]
    expected = list if field is not None else dict
    if not isinstance(value, expected):
        raise ValueError(f'Expected {expected.__name__} input.')
    return value


def _wrap_hardware_errors(func, *args, timeout=_HARDWARE_CALL_HARD_TIMEOUT_S, **kwargs):
    """Bound serial loops in this call; no abandoned background workers."""
    try:
        with transport.operation_deadline(timeout):
            return func(*args, **kwargs)
    except (DeviceNotFoundError, PortBusyError, UnsupportedFeature) as exc:
        return {"status": "unavailable", "reason": str(exc)}
    except (CommandFailed, DeviceCommunicationError, GhostEspProtocolError) as exc:
        return {"status": "error", "reason": str(exc)}
    except ValueError as exc:
        return {"status": "refused", "reason": str(exc)}


# ---------------------------------------------------------------------------
# Device detection / capability probing
# ---------------------------------------------------------------------------

@mcp.tool()
def detect_connection() -> dict[str, Any]:
    """List every Free-WILi-related serial port currently visible to this
    PC (OG MAIN, OG DISPLAY, and Bottlenose's own direct USB port), without
    opening any of them. Use this first to see what is actually plugged in.
    """
    return _wrap_hardware_errors(device.detect_connection)


@mcp.tool()
def get_bridge_status(port: Optional[str] = None) -> dict[str, Any]:
    """Read bnbridge's forwarding counters from the OG DISPLAY USB port
    (COM9), without sending any command. Compare counter differences over
    an operation to detect queue drops or UART errors; initial boot-time
    errors are not capture errors. Requires bnbridge firmware.
    """
    return _wrap_hardware_errors(device.bridge_status, port)


@mcp.tool()
def identify_og(port: Optional[str] = None) -> dict[str, Any]:
    """Open the OG MAIN USB console just long enough to identify its
    firmware and report which menu capabilities (Wi-Fi/BLE/sub-GHz) it
    actually advertises. Read-only: no settings are changed, nothing is
    flashed or reset.
    """
    return _wrap_hardware_errors(device.identify_og, port)


@mcp.tool()
def identify_bottlenose(via_og: bool = True, port: Optional[str] = None) -> dict[str, Any]:
    """Identify the firmware running on Bottlenose's ESP32-C6 (expected:
    GhostESP Revival v2.2.x), either through the OG's UART bridge
    (via_og=True, recommended) or Bottlenose's own direct USB port
    (via_og=False). Read-only.
    """
    return _wrap_hardware_errors(device.identify_ghostesp, via_og, port)


# ---------------------------------------------------------------------------
# Wi-Fi discovery
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_wifi_via_og(seconds: int = 8, port: Optional[str] = None, save: bool = True) -> dict[str, Any]:
    """Scan Wi-Fi through OG USB, using bnbridge/GhostESP when installed
    or the legacy OG menu otherwise, and
    return raw discovery records (ssid, bssid, rssi_dbm, channel, ...).

    This is read-only observation; it does not interpret the results. Use
    analyze_wifi_records for heuristic findings. Reports 'unavailable' with
    a reason if the running OG firmware does not expose a Wi-Fi menu.
    """
    def run():
        info = transport.find_og_main(port)
        if info.is_raw_bridge:
            return scan_wifi_via_ghostesp(seconds=seconds, via_og=True, port=info.port, save=save)
        with transport.PortLock(info.port):
            with OgConsole(info.port) as console:
                result = console.wifi_scan(seconds)
        if save:
            run_dir = new_run_dir("wifi-og")
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def scan_wifi_via_ghostesp(seconds: int = 8, via_og: bool = True, port: Optional[str] = None,
                           save: bool = True) -> dict[str, Any]:
    """Run GhostESP's 'scanap' command (through the OG bridge or
    Bottlenose's direct USB) and return raw discovery records (ssid, bssid,
    rssi_dbm, channel, band, security). Read-only observation.
    """
    def run():
        resolved = transport.find_og_main(port) if via_og else transport.find_bottlenose_usb(port)
        with transport.PortLock(resolved.port):
            with GhostEspLink(via_og=via_og, port=resolved.port) as link:
                identity = link.identify()
                if not identity.matches_expected:
                    return {"status": "unavailable",
                            "reason": f"Unexpected firmware/model on this port: {identity.firmware!r} / {identity.model!r}."}
                link.stop_all()
                result = link.wifi_scan(seconds)
        if save:
            run_dir = new_run_dir("wifi-ghostesp")
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def analyze_wifi_records(records: Optional[list[dict[str, Any]]] = None, run_name: Optional[str] = None) -> dict[str, Any]:
    """Analyze ALL saved data by supplying run_name=saved_to, or supply inline data.
    Run heuristic security checks over a list of Wi-Fi records already
    returned by scan_wifi_via_og/scan_wifi_via_ghostesp (or loaded from a
    saved run). Flags open/WEP/WPA1 networks, hidden SSIDs, SSIDs broadcast
    from inconsistent BSSIDs (possible evil-twin/rogue AP), and channel
    congestion. Findings are indicators for human review, not confirmed
    vulnerabilities.
    """
    return analysis.analyze_wifi(_analysis_input(records, run_name, 'records'))


# ---------------------------------------------------------------------------
# BLE advertisement discovery
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_ble_via_og(seconds: int = 8, port: Optional[str] = None, save: bool = True) -> dict[str, Any]:
    """Scan BLE through OG USB, selecting bnbridge/GhostESP or the legacy
    OG menu as appropriate, and return
    raw advertisement records (name, address, rssi_dbm). Read-only.
    """
    def run():
        info = transport.find_og_main(port)
        if info.is_raw_bridge:
            return scan_ble_via_ghostesp(seconds=seconds, via_og=True, port=info.port, save=save)
        with transport.PortLock(info.port):
            with OgConsole(info.port) as console:
                result = console.ble_scan(seconds)
        if save:
            run_dir = new_run_dir("ble-og")
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def scan_ble_via_ghostesp(seconds: int = 8, via_og: bool = True, port: Optional[str] = None,
                          save: bool = True) -> dict[str, Any]:
    """Run GhostESP's BLE advertiser scan ('blescan -adv' then 'listadv')
    and return raw advertisement records (address, rssi_dbm, name,
    manufacturer, address_type, services, adv_type). Read-only; does not
    connect to any device.
    """
    def run():
        resolved = transport.find_og_main(port) if via_og else transport.find_bottlenose_usb(port)
        with transport.PortLock(resolved.port):
            with GhostEspLink(via_og=via_og, port=resolved.port) as link:
                identity = link.identify()
                if not identity.matches_expected:
                    return {"status": "unavailable",
                            "reason": f"Unexpected firmware/model on this port: {identity.firmware!r} / {identity.model!r}."}
                link.stop_all()
                result = link.ble_advertiser_scan(seconds)
        if save:
            run_dir = new_run_dir("ble-ghostesp")
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def analyze_ble_records(records: Optional[list[dict[str, Any]]] = None, run_name: Optional[str] = None) -> dict[str, Any]:
    """Analyze ALL saved data by supplying run_name=saved_to, or supply inline data.
    Run heuristic privacy/exposure checks over a list of BLE advertisement
    records already returned by scan_ble_via_og/scan_ble_via_ghostesp. Flags
    devices broadcasting a readable name on a non-randomized (public)
    address, and standard GATT-in-advertisement service exposure worth
    confirming is access-controlled. Findings are indicators for human review.
    """
    return analysis.analyze_ble(_analysis_input(records, run_name, 'records'))


# ---------------------------------------------------------------------------
# BLE GATT service/characteristic enumeration
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_gatt_devices(seconds: int = 15, via_og: bool = True, port: Optional[str] = None,
                      save: bool = True) -> dict[str, Any]:
    """Discover connectable BLE devices without connecting using GhostESP's GATT
    scanner ('blescan -g' then 'listgatt'). Does NOT connect to any device;
    returns an index, name/MAC, RSSI, and auto-detected tracker type per
    device. Use gatt_enumerate_device with one of these indices to actually
    connect and read services, which requires separate explicit approval.
    """
    def run():
        resolved = transport.find_og_main(port) if via_og else transport.find_bottlenose_usb(port)
        with transport.PortLock(resolved.port):
            with GhostEspLink(via_og=via_og, port=resolved.port) as link:
                identity = link.identify()
                if not identity.matches_expected:
                    return {"status": "unavailable",
                            "reason": f"Unexpected firmware/model on this port: {identity.firmware!r} / {identity.model!r}."}
                link.stop_all()
                result = link.gatt_scan_for_devices(seconds)
        if save:
            run_dir = new_run_dir("gatt-devices")
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def gatt_enumerate_device(device_index: int, confirm_active_connection: bool,
                          via_og: bool = True, port: Optional[str] = None,
                          save: bool = True) -> dict[str, Any]:
    """Connect to one BLE device (by the index from scan_gatt_devices) and
    enumerate its GATT services and characteristics.

    THIS IS AN ACTIVE OPERATION on a third-party device, not passive
    observation. GhostESP's own documentation states it will automatically
    attempt pairing (auto-confirming numeric comparison) if the link is not
    already encrypted. Only call this with confirm_active_connection=True
    after the user has explicitly approved connecting to this specific
    device. It refuses to run otherwise.
    """
    if not confirm_active_connection:
        return {"status": "refused",
                "reason": ("gatt_enumerate_device connects to a third-party BLE device and "
                          "may trigger pairing. Ask the user to explicitly approve connecting "
                          "to this specific device, then retry with confirm_active_connection=True.")}

    def run():
        resolved = transport.find_og_main(port) if via_og else transport.find_bottlenose_usb(port)
        with transport.PortLock(resolved.port):
            with GhostEspLink(via_og=via_og, port=resolved.port) as link:
                identity = link.identify()
                if not identity.matches_expected:
                    return {"status": "unavailable",
                            "reason": f"Unexpected firmware/model on this port: {identity.firmware!r} / {identity.model!r}."}
                result = link.gatt_enumerate(device_index, confirm_active_connection=True)
        if save:
            run_dir = new_run_dir("gatt-enum")
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def analyze_gatt_enumeration(enumeration: Optional[dict[str, Any]] = None, run_name: Optional[str] = None) -> dict[str, Any]:
    """Analyze ALL saved data by supplying run_name=saved_to, or supply inline data.
    Run heuristic checks over one device's GATT enumeration result
    (from gatt_enumerate_device): flags standard services whose
    characteristics were readable once connected, and vendor-specific
    service UUIDs worth manual follow-up. Findings are indicators for human
    review, not confirmed vulnerabilities.
    """
    return analysis.analyze_gatt(_analysis_input(enumeration, run_name))


# ---------------------------------------------------------------------------
# Wi-Fi packet monitoring (passive 802.11 capture)
# ---------------------------------------------------------------------------

@mcp.tool()
def capture_wifi_packets(channel: int = 6, seconds: int = 10, via_og: bool = True,
                         port: Optional[str] = None, save: bool = True) -> dict[str, Any]:
    """Passively capture the firmware's selected 802.11 frames on one 2.4 GHz
    channel using GhostESP's monitor mode ('capture -wireshark'), and parse
    them into packet records. This only listens; it never transmits,
    injects, or deauthenticates.

    Returns parsed packet records (frame_type/subtype, addresses, RSSI,
    frequency) and, if save=True, writes a complete .pcap (Wireshark
    compatible) under MCP/results/.
    """
    def run():
        resolved = transport.find_og_main(port) if via_og else transport.find_bottlenose_usb(port)
        with transport.PortLock(resolved.port):
            with GhostEspLink(via_og=via_og, port=resolved.port) as link:
                identity = link.identify()
                if not identity.matches_expected:
                    return {"status": "unavailable",
                            "reason": f"Unexpected firmware/model on this port: {identity.firmware!r} / {identity.model!r}."}
                link.stop_all()
                result = link.capture(channel, seconds)
        pcap_bytes = result.pop("pcap_bytes", b"")
        raw_capture = result.pop("raw_capture_bytes", b"")
        if save:
            run_dir = new_run_dir("wifi-capture")
            if pcap_bytes:
                (run_dir / "capture.pcap").write_bytes(pcap_bytes)
            (run_dir / 'capture-wire.bin').write_bytes(raw_capture)
            save_json(run_dir, "observation.json", result)
            result["saved_to"] = run_dir.name
            result["pcap_saved"] = bool(pcap_bytes)
        if not result.get("monitor_stopped_cleanly"):
            result["warning"] = ("The monitor did not confirm a clean stop. If Bottlenose stops "
                                 "responding, press its RESET button only (not BOOT).")
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def analyze_packet_capture(packets: Optional[list[dict[str, Any]]] = None, run_name: Optional[str] = None) -> dict[str, Any]:
    """Analyze ALL saved data by supplying run_name=saved_to, or supply inline data.
    Summarize parsed 802.11 packet records from capture_wifi_packets:
    frame-type mix, and flags for observed deauth/disassociation frames
    (only ever recorded, never sent, by this capture) and probe requests.
    Findings are indicators for human review.
    """
    return analysis.analyze_packets(_analysis_input(packets, run_name, 'packets'))


# ---------------------------------------------------------------------------
# Sub-GHz (CC1101 x2): 315/433/915 MHz
# ---------------------------------------------------------------------------

@mcp.tool()
def subghz_radio_status(radio_index: int, port: Optional[str] = None) -> dict[str, Any]:
    """Read CC1101 identity, register frequency and receive state through
    bnbridge 003 DISPLAY USB. radio 1 uses CS1/GPIO18; radio 2 uses CS0/GPIO5.
    port may name MAIN (one board connected) or DISPLAY explicitly. Does not
    retune or start RX. RSSI is reported only if already in receive mode.
    """
    def run():
        info = find_radio_port(port)
        with transport.PortLock(info.port), RadioClient(info.port) as client:
            return client.status(radio_index)
    return _wrap_hardware_errors(run)


@mcp.tool()
def subghz_listen(radio_index: int, seconds: int = 10, band_mhz_hint: Optional[float] = None,
                  port: Optional[str] = None, save: bool = True,
                  frequency_mhz: Optional[float] = None, modulation: str = 'ook') -> dict[str, Any]:
    """Tune one CC1101 and receive for 1?30 seconds through bnbridge 003.
    Default frequencies: radio 1 = 433.92 MHz, radio 2 = 915 MHz. Explicit
    frequency_mhz overrides the default. Supported demodulators: ook, 2fsk,
    gfsk, at 4800 baud and 203.125 kHz bandwidth. Raw demodulator bytes may be
    noise: they are not decoded packets. RSSI samples and register readback
    are returned separately. RX stops on completion/error and independently
    times out in firmware. Never transmits. band_mhz_hint only labels data;
    it does not tune the receiver. Select frequency_mhz to tune it.
    """
    def run():
        info = find_radio_port(port)
        with transport.PortLock(info.port), RadioClient(info.port) as client:
            result = client.listen(radio_index, seconds, frequency_mhz, modulation)
            result['raw_control_text'] = ''.join(e.text for e in client.link.transcript if e.direction == 'rx')
        result['band_mhz_hint'] = band_mhz_hint
        if save:
            run_dir = new_run_dir(f'subghz-radio{radio_index}')
            save_json(run_dir, 'observation.json', result)
            result['saved_to'] = run_dir.name
        return _saved_reply(result, save)
    return _wrap_hardware_errors(run)


@mcp.tool()
def analyze_subghz_observation(observation: Optional[dict[str, Any]] = None, band_mhz: Optional[float] = None,
                               run_name: Optional[str] = None) -> dict[str, Any]:
    """Analyze ALL saved data by supplying run_name=saved_to, or supply inline data.
    Run heuristic checks over one subghz_listen() result: flags
    low-diversity/fixed-code-like traffic (a common replay weakness in
    simple garage-door/doorbell/key-fob remotes), idle-only captures, and
    notable RSSI. Pass `band_mhz` (315, 433.92, or 915) to label findings
    with the band you know this radio was tuned to; omit it if unknown.
    """
    return analysis.analyze_subghz(_analysis_input(observation, run_name), band_mhz=band_mhz)


# ---------------------------------------------------------------------------
# Maestro (I/O/debug board - no wireless capability)
# ---------------------------------------------------------------------------

@mcp.tool()
def maestro_capabilities() -> dict[str, Any]:
    """Report what Maestro can and cannot do for this toolset.

    Maestro is an I/O/debug expansion board (GPIO test points, a debug
    probe connection, and logic-analyzer/indicator access). It has no
    wireless transceiver of its own and is not reachable as a separate
    serial endpoint for Wi-Fi/BLE/sub-GHz data. This tool always returns
    'unavailable' for wireless scanning through Maestro; it exists so an
    agent gets an explicit, honest answer instead of silently skipping it.
    """
    return {
        "status": "unavailable_by_design",
        "reason": ("Maestro is a GPIO/debug-probe expansion board with no onboard wireless "
                  "radio. Wi-Fi, BLE, and sub-GHz data for this device stack all come from "
                  "the OG's two CC1101 radios and the Bottlenose ESP32-C6, not from Maestro."),
        "maestro_known_capabilities": [
            "GPIO test points for probing signals",
            "Debug probe / logic-analyzer connection",
            "Status/IO indicators",
        ],
    }


# ---------------------------------------------------------------------------
# Saved results (this server's own MCP/results/ only)
# ---------------------------------------------------------------------------

@mcp.tool()
def list_saved_runs(limit: int = 20, offset: int = 0) -> dict[str, Any]:
    """List paginated saved-run metadata/counts, newest first. Full observations
    are not inlined. Follow next_offset or use analyze_* with a run_name.
    """
    return list_runs(limit=limit, offset=offset)


@mcp.tool()
def get_saved_observation(run_name: str, field: Optional[str] = None,
                          offset: int = 0, limit: int = 50) -> dict[str, Any]:
    """Get a bounded page from a saved observation (default 50 items, max 200).
    field selects records, packets, events, devices, services or rssi_dbm.
    Array totals/next_offset are explicit; raw console text remains on disk.
    Use analyze_* with run_name for full-data analysis without resending arrays.
    """
    result = observation_page(load_observation(run_name), offset, limit, field)
    result['run_name'] = run_name
    return result


# ---------------------------------------------------------------------------
# Explicit, opt-in device-state-changing operation
# ---------------------------------------------------------------------------

@mcp.tool()
def reset_og_main_processor(confirm: bool, port: Optional[str] = None) -> dict[str, Any]:
    """Restart the OG's MAIN processor via its advertised 'Software Reset'
    settings command. This is a device-state-changing operation (briefly
    disconnects both OG USB ports while it reboots) and is refused unless
    confirm=True, which should only be set after explicit user approval.
    Does not flash firmware and does not change UART/orca settings.
    """
    if not confirm:
        return {"status": "refused",
                "reason": "reset_og_main_processor requires confirm=True after explicit user approval."}

    def run():
        info = transport.find_og_main(port)
        with transport.PortLock(info.port):
            with OgConsole(info.port) as console:
                console.software_reset(confirm=True)
        return {"status": "reset_sent", "port": info.port}
    return _wrap_hardware_errors(run)


if __name__ == "__main__":
    mcp.run()
