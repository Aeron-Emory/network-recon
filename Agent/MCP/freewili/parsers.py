"""Convert raw device text into structured observation records.

These functions only describe what the device said; they never judge
whether it represents a vulnerability. That judgment is left entirely to
analysis.py (rule-based "findings") or to the AI agent reading the raw
records returned by the MCP tools.

Independently written; no code shared with the parent workshop's scripts.
"""
from __future__ import annotations

import re
import struct

from .menu import MAC_PATTERN, parse_event_frames


def og_wifi_records(text: str) -> list[dict]:
    """Parse '*wifiscan' event frames from the OG's legacy MAIN console."""
    records = []
    for frame in parse_event_frames(text):
        if frame["id"].lower() != "*wifiscan" or not frame["ok"]:
            continue
        payload = frame["payload"]
        record = dict(raw_payload=payload, device_tick_hex=frame["device_tick_hex"],
                      source="og_main_console")
        match = re.fullmatch(
            rf"({MAC_PATTERN})\s+(-?\d+)\s+(\d+)\s+(\d+)\s+(\d+)(?:\s+(.*))?", payload, re.DOTALL)
        if match:
            record.update(bssid=match[1], rssi_dbm=int(match[2]), channel=int(match[3]),
                          band_code=int(match[4]), auth_mode_code=int(match[5]),
                          ssid=match[6] or "")
        else:
            legacy = re.fullmatch(rf"(.*?)\s*(-?\d+)\s+({MAC_PATTERN})", payload, re.DOTALL)
            if legacy:
                rssi = int(legacy[2])
                record.update(ssid=legacy[1].strip(), bssid=legacy[3],
                              rssi_dbm=rssi if -127 <= rssi <= 0 else None,
                              event_format="legacy")
        records.append(record)
    return records


def og_ble_records(text: str) -> list[dict]:
    """Parse '*btscan' event frames from the OG's legacy MAIN console."""
    records = []
    for frame in parse_event_frames(text):
        if frame["id"].lower() != "*btscan" or not frame["ok"]:
            continue
        payload = frame["payload"]
        record = dict(raw_payload=payload, device_tick_hex=frame["device_tick_hex"],
                      source="og_main_console")
        match = re.fullmatch(rf"(.*?)\s*({MAC_PATTERN})\s+(-?\d+)", payload, re.DOTALL)
        if match:
            record.update(name=match[1].strip(), address=match[2], rssi_dbm=int(match[3]))
        records.append(record)
    return records


def ghostesp_wifi_records(text: str) -> list[dict]:
    """Parse GhostESP 'scanap' text output lines."""
    pattern = (rf"\[\d+\] SSID: (.*?),\s+BSSID: ({MAC_PATTERN}),\s+"
               r"RSSI: (-?\d+),\s+Channel: (\d+),\s+Band: (.*?),\s+Security: ([^\r\n]+)")
    return [
        dict(ssid=m[1], bssid=m[2], rssi_dbm=int(m[3]), channel=int(m[4]),
             band=m[5], security=m[6].strip(), source="ghostesp")
        for m in re.finditer(pattern, text)
    ]


def ghostesp_ble_records(text: str) -> list[dict]:
    """Parse GhostESP 'listadv' BLE advertiser blocks."""
    rows = []
    for block in re.split(r"\[\d+\] BLE Advertiser", text)[1:]:
        mac_match = re.search(rf"MAC: ({MAC_PATTERN})", block)
        rssi_match = re.search(r"RSSI: (-?\d+)", block)
        if not mac_match or not rssi_match:
            continue
        row = dict(address=mac_match[1], rssi_dbm=int(rssi_match[1]), source="ghostesp")
        for field in ("Name", "Address Type", "Manufacturer", "Services", "Adv Type"):
            match = re.search(re.escape(field) + r": ([^\r\n]+)", block)
            if match:
                row[field.lower().replace(" ", "_")] = match[1]
        rows.append(row)
    return rows


def ghostesp_gatt_device_records(text: str) -> list[dict]:
    """Parse GhostESP 'listgatt' device list output.

    Example line group:
        [0] Name: <unknown>,
             MAC: 5C:94:F2:xx:xx:xx,
             RSSI: -67,
             Type: AirTag,
    """
    rows = []
    pattern = re.compile(
        rf"\[(\d+)\]\s*Name:\s*([^,\r\n]*),?\s*"
        rf"MAC:\s*({MAC_PATTERN}),?\s*"
        r"RSSI:\s*(-?\d+),?\s*"
        r"(?:Type:\s*([^,\r\n]*),?)?",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        rows.append(dict(
            index=int(match[1]),
            name=match[2].strip() if match[2] and match[2].strip() != "<unknown>" else None,
            address=match[3],
            rssi_dbm=int(match[4]),
            tracker_type=match[5].strip() if match[5] else None,
            source="ghostesp_gatt_scan",
        ))
    return rows


def ghostesp_gatt_service_records(text: str) -> dict:
    """Parse GhostESP 'enumgatt' service enumeration output.

    Example line:
        Service: Battery Service (0x180F) [handles 12-15]
    Followed, when present, by decoded Device Information/Battery/Current
    Time characteristic lines emitted directly beneath a service.
    """
    services = []
    service_pattern = re.compile(
        r"Service:[ \t]*(?P<name>[^\r\n(]+)\((?P<uuid>[^)\r\n]+)\)"
        r"[ \t]*\[?handles[ \t]*(?P<lo>\d+)-(?P<hi>\d+)\]?", re.I
    )
    matches = list(service_pattern.finditer(text))
    for i, match in enumerate(matches):
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = re.split(r'Service discovery complete|Initiating pairing|Encryption failed|Disconnected\.',
                         text[start:end], maxsplit=1, flags=re.I)[0]
        characteristics = {}
        for line in block.splitlines():
            char_match = re.match(r"[ \t]{2,}([A-Za-z][A-Za-z0-9 ]*):[ \t]*(.+?)\s*$", line)
            if char_match and char_match[1].strip().lower() not in {'error', 'encryption failed', 'status'}:
                characteristics[char_match[1].strip()] = char_match[2].strip()
        services.append(dict(
            service_name=match["name"].strip(),
            uuid=match["uuid"],
            uuid_is_truncated='...' in match['uuid'] or '\u2026' in match['uuid'],
            handle_range=[int(match["lo"]), int(match["hi"])],
            characteristics=characteristics,
            source="ghostesp_gatt_enum",
        ))
    connection_failed = bool(re.search(r"connection failed|failed to connect", text, re.I))
    pairing_error = re.search(r'(?:Encryption|Pairing) failed:\s*([^\r\n]+)', text, re.I)
    complete = re.search(r'Service discovery complete\. Found (\d+) services', text, re.I)
    return dict(services=services, connection_failed=connection_failed,
                pairing_attempted=bool(re.search(r'Initiating pairing', text, re.I)),
                pairing_failed=bool(pairing_error), pairing_error=pairing_error[1].strip() if pairing_error else None,
                reported_service_count=int(complete[1]) if complete else None,
                service_discovery_complete=bool(complete),
                status='error' if connection_failed else 'partial' if pairing_error else 'ok' if complete else 'inconclusive',
                raw_text=text)


def ghostesp_chip_info(text: str) -> dict:
    """Parse GhostESP 'chipinfo' output into a dict of known fields."""
    info = {}
    patterns = {
        "firmware": r"Firmware:\s*([^\r\n]+)",
        "model": r"Model:\s*([^\r\n]+)",
        "features": r"Features:\s*([^\r\n]+)",
        "free_heap_bytes": r"Free Heap:\s*(\d+)\s*bytes",
        "idf_version": r"IDF Version:\s*([^\r\n]+)",
        "build_config": r"Config:\s*([^\r\n]+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            value = match[1].strip()
            info[key] = int(value) if key == "free_heap_bytes" and value.isdigit() else value
    info["raw_text"] = text
    return info


def extract_radiotap_pcap(wire: bytes) -> tuple[bytes, list[dict], dict]:
    """Extract complete radiotap/802.11 PCAP records from a raw capture
    stream that may interleave diagnostic console text between records.

    Returns (pcap_bytes, packet_summary_rows, extraction_details). Never
    guesses inside a corrupt/incomplete binary record; stops and reports the
    unparsed tail instead.
    """
    start = wire.find(b"\xd4\xc3\xb2\xa1")
    if start < 0 or start + 24 > len(wire):
        raise ValueError("No complete little-endian PCAP global header found in capture.")
    _, major, minor, _, _, snaplen, link = struct.unpack_from("<IHHIIII", wire, start)
    if (major, minor, link) != (2, 4, 127) or not 0 < snaplen <= 65535:
        raise ValueError("Unsupported PCAP header; expected a radiotap (DLT 127) capture.")
    output = bytearray(wire[start:start + 24])
    rows: list[dict] = []
    log_bytes = 0
    pos = start + 24
    while pos < len(wire):
        # This prompt has no newline. Accept it only BETWEEN validated
        # records, never by removing matching bytes inside a packet.
        prompt = re.match(rb'(?:\x1b\[[0-9;]*m)*ghost(?:\x1b\[[0-9;]*m)*> ?', wire[pos:])
        if prompt:
            pos += prompt.end()
            log_bytes += prompt.end()
            continue
        if pos + 16 <= len(wire):
            seconds, micros, length, original = struct.unpack_from("<IIII", wire, pos)
            if micros < 1_000_000 and 18 <= length <= original <= snaplen and pos + 16 + length <= len(wire):
                data = wire[pos + 16:pos + 16 + length]
                rtlen = struct.unpack_from("<H", data, 2)[0]
                if data[:2] == b"\0\0" and 8 <= rtlen <= 256 and rtlen + 10 <= len(data):
                    frame_control = struct.unpack_from("<H", data, rtlen)[0]
                    if frame_control & 3 == 0:
                        row = dict(
                            timestamp_s=seconds + micros / 1e6, captured_bytes=length,
                            frame_type=(frame_control >> 2) & 3, frame_subtype=(frame_control >> 4) & 15,
                            receiver=":".join(f"{v:02x}" for v in data[rtlen + 4:rtlen + 10]),
                        )
                        if rtlen + 16 <= len(data):
                            row["address_2"] = ":".join(f"{v:02x}" for v in data[rtlen + 10:rtlen + 16])
                        if rtlen == 16 and struct.unpack_from("<I", data, 4)[0] == 0x2C:
                            row["frequency_mhz"] = struct.unpack_from("<H", data, 10)[0]
                            row["rssi_dbm"] = struct.unpack_from("b", data, 14)[0]
                        rows.append(row)
                        output.extend(wire[pos:pos + 16 + length])
                        pos += 16 + length
                        continue
        end = wire.find(b"\n", pos, min(len(wire), pos + 2048))
        if end >= 0 and all(v in (9, 10, 13, 27) or 32 <= v < 127 for v in wire[pos:end + 1]):
            log_bytes += end + 1 - pos
            pos = end + 1
            continue
        break
    tail = wire[pos:]
    tail_kind = ("none" if not tail else "console_text" if
                 all(v in (9, 10, 13, 27) or 32 <= v < 127 for v in tail) else "unparsed_binary")
    details = dict(prefix_bytes=start, diagnostic_bytes=log_bytes,
                   unparsed_tail_bytes=len(wire) - pos, tail_kind=tail_kind,
                   timestamp_note="Timestamps are device supplied; wall-clock accuracy is not verified.")
    return bytes(output), rows, details
