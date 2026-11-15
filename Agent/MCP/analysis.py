"""Rule-based, read-only vulnerability-inference helpers.

Every function here takes plain Python data structures already returned by
freewili/*.py (raw observation records) and returns heuristic "findings".
Nothing in this module touches a serial port, a file, or the parent
workshop folder. Findings are indicators meant to prioritize human review,
not proof of an exploitable vulnerability; every finding carries a severity
("high"/"medium"/"low"/"info") and the raw evidence it was derived from, so
an AI agent or human can see exactly why it was raised and re-judge it.

Raw observations and findings are kept in two different data shapes
throughout this codebase: freewili/*.py functions return observations only
(what the device said), and analyze_* functions here are the only place
that adds judgment on top.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

OPEN_SECURITY_TOKENS = {"open", "none"}
WEAK_SECURITY_TOKENS = {"wep"}
LEGACY_SECURITY_TOKENS = {"wpa", "wpa-psk", "wpa1"}


def _finding(severity: str, title: str, detail: str, evidence: Any) -> dict[str, Any]:
    return {"severity": severity, "title": title, "detail": detail, "evidence": evidence}


def analyze_wifi(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Heuristic findings over Wi-Fi scan records (from og_client.wifi_scan
    or ghostesp_client.wifi_scan): ssid, bssid, rssi_dbm, channel, security/band.
    """
    findings: list[dict[str, Any]] = []
    if not rows:
        return {"record_count": 0, "findings": findings}

    by_ssid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    oui_counter: Counter[str] = Counter()
    channel_counter: Counter[str] = Counter()
    seen_bssids: set[str] = set()

    for row in rows:
        raw_ssid = row.get('ssid')
        ssid = str(raw_ssid).strip() if raw_ssid is not None else ''
        hidden = raw_ssid is not None and ssid.casefold() in {'', '(hidden)', '<hidden>'}
        if hidden:
            ssid = ''
        bssid = (row.get("bssid") or "").strip().upper()
        security = str(row.get("security") or "").strip().lower()
        channel = str(row.get("channel") or "").strip()

        if ssid:
            by_ssid[ssid].append(row)
        if bssid:
            seen_bssids.add(bssid)
            oui_counter[bssid[:8]] += 1
        if channel:
            channel_counter[channel] += 1

        if security in OPEN_SECURITY_TOKENS:
            findings.append(_finding(
                "medium", "Open network observed",
                f"'{ssid or '(hidden)'}' ({bssid}) advertises no encryption. "
                "The Wi-Fi link is unencrypted; application-layer encryption was not assessed.",
                row))
        elif security in WEAK_SECURITY_TOKENS:
            findings.append(_finding(
                "high", "WEP network observed",
                f"'{ssid or '(hidden)'}' ({bssid}) uses WEP, which is broken and "
                "crackable with publicly available tools.",
                row))
        elif security in LEGACY_SECURITY_TOKENS:
            findings.append(_finding(
                "medium", "Legacy WPA1 network observed",
                f"'{ssid or '(hidden)'}' ({bssid}) advertises WPA1-only, which has "
                "known weaknesses relative to WPA2/WPA3.",
                row))

        if hidden:
            findings.append(_finding(
                "info", "Hidden SSID",
                f"BSSID {bssid} is broadcasting without a visible SSID. Hidden "
                "SSIDs offer no real confidentiality and still leak the BSSID/vendor.",
                row))

    for ssid, entries in by_ssid.items():
        bssids = {str(e.get("bssid", "")).upper() for e in entries}
        securities = {str(e.get("security") or "").strip().lower() for e in entries}
        if len(bssids) > 1 and len(securities) > 1:
            findings.append(_finding(
                "medium", "Same SSID with inconsistent security settings",
                f"SSID '{ssid}' appears from {len(bssids)} different BSSIDs "
                f"advertising different security modes ({sorted(securities)}). "
                "This pattern can indicate a rogue/evil-twin access point, though "
                "it can also be legitimate multi-AP roaming misconfiguration.",
                {"ssid": ssid, "bssids": sorted(bssids), "securities": sorted(securities)}))
        elif len(bssids) > 4:
            findings.append(_finding(
                "info", "SSID broadcast from many BSSIDs",
                f"SSID '{ssid}' appears from {len(bssids)} BSSIDs. Likely a large "
                "legitimate multi-AP deployment (e.g. mesh/enterprise), but worth "
                "confirming it matches the expected site inventory.",
                {"ssid": ssid, "bssid_count": len(bssids)}))

    crowded_ouis = [oui for oui, count in oui_counter.items() if count >= 4]
    if crowded_ouis:
        findings.append(_finding(
            "info", "Dense vendor clustering",
            f"{len(crowded_ouis)} vendor OUI prefix(es) account for 4+ access "
            "points each in this scan, consistent with a managed deployment "
            "(e.g. campus Wi-Fi) rather than individual rogue devices.",
            {"ouis": crowded_ouis}))

    if channel_counter:
        busiest_channel, busiest_count = channel_counter.most_common(1)[0]
        if busiest_count >= max(5, len(rows) // 3):
            findings.append(_finding(
                "info", "Channel congestion",
                f"Channel {busiest_channel} carries {busiest_count} of "
                f"{len(rows)} observed networks, which can degrade throughput "
                "and make on-channel monitoring/analysis noisier.",
                {"channel": busiest_channel, "count": busiest_count}))

    summary = {
        "total_networks": len(rows),
        "unique_bssids": len(seen_bssids),
        "unique_ssids": len(by_ssid),
        "open_count": sum(1 for r in rows if str(r.get("security") or "").strip().lower() in OPEN_SECURITY_TOKENS),
        "wep_count": sum(1 for r in rows if str(r.get("security") or "").strip().lower() in WEAK_SECURITY_TOKENS),
    }
    return {"record_count": len(rows), "summary": summary, "findings": findings}


def analyze_ble(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Heuristic findings over BLE advertisement records: address, rssi_dbm,
    address_type, manufacturer, adv_type, name, services.
    """
    findings: list[dict[str, Any]] = []
    if not rows:
        return {"record_count": 0, "findings": findings}

    public_addr_with_identity = 0
    manufacturer_counter: Counter[str] = Counter()
    named_devices = []

    for row in rows:
        address_type = str(row.get("address_type") or "").strip().lower()
        name = str(row.get("name") or "").strip()
        manufacturer = str(row.get("manufacturer") or "").strip()
        services = str(row.get("services") or "").strip()

        if manufacturer:
            manufacturer_counter[manufacturer] += 1

        if name:
            named_devices.append(row)
            if address_type == "public":
                public_addr_with_identity += 1
                findings.append(_finding(
                    "low", "BLE device broadcasting identifying name on a static address",
                    f"Device '{name}' ({row.get('address')}) uses a public "
                    "(non-randomized) address while broadcasting a human-readable "
                    "name, making it trackable across locations/time by anyone "
                    "listening passively.",
                    row))

        if services and any(tag in services for tag in ("180D", "180A", "180F")):
            findings.append(_finding(
                "info", "BLE device exposes standard health/device-info service",
                f"'{name or row.get('address')}' advertises service UUID(s) "
                f"'{services}'. Standard GATT services like Heart Rate (180D) "
                "or Device Information (180A) are commonly unauthenticated for "
                "discovery, which is normal, but confirm GATT access itself "
                "requires pairing if that device holds sensitive data.",
                row))

    if named_devices:
        findings.append(_finding(
            "info", "Named BLE devices in range",
            f"{len(named_devices)} of {len(rows)} BLE advertisers include a "
            "readable device name, which can support social-engineering or "
            "asset-tracking in a physical-security assessment.",
            {"count": len(named_devices)}))

    summary = {
        "total_advertisers": len(rows),
        "unique_addresses": len({r.get("address") for r in rows if r.get("address")}),
        "named_devices": len(named_devices),
        "public_address_identity_leaks": public_addr_with_identity,
        "top_manufacturers": manufacturer_counter.most_common(5),
    }
    return {"record_count": len(rows), "summary": summary, "findings": findings}


_SENSITIVE_GATT_SERVICE_NAME_HINTS = (
    "battery", "device information", "current time", "heart rate",
    "alert notification", "human interface device",
)


def analyze_gatt(enumeration: dict[str, Any] | None) -> dict[str, Any]:
    """Heuristic findings over one device's GATT enumeration, as returned by
    ghostesp_client.gatt_enumerate(): {services, connection_failed, raw_text}.

    This never connects to anything itself; it only interprets a result the
    caller already obtained (with explicit approval) through
    GhostEspLink.gatt_enumerate.
    """
    findings: list[dict[str, Any]] = []
    if not enumeration:
        return {"record_count": 0, "findings": findings}
    if enumeration.get("connection_failed"):
        findings.append(_finding(
            "info", "GATT connection failed",
            "The device did not complete a GATT connection/enumeration. It may be "
            "out of range, asleep, already connected elsewhere, or require bonding "
            "that was not established.",
            {}))
        return {"record_count": 0, "findings": findings}

    # Recover observations saved by the earlier parser without modifying them.
    if enumeration.get('raw_text'):
        from freewili.parsers import ghostesp_gatt_service_records
        parsed = ghostesp_gatt_service_records(enumeration['raw_text'])
        enumeration = {**enumeration, **parsed, 'services': parsed['services'] or enumeration.get('services', [])}
    services = enumeration.get('services', [])
    decoded = [s for s in services if s.get('characteristics')]
    sensitive = [s for s in decoded if any(h in s.get('service_name', '').lower()
                                          for h in _SENSITIVE_GATT_SERVICE_NAME_HINTS)]
    if enumeration.get('pairing_failed'):
        findings.append(_finding('info', 'GATT pairing/encryption failed',
            'Service discovery returned partial information; characteristic access and access controls were not established.',
            {'reported_error': enumeration.get('pairing_error')}))
    if sensitive:
        findings.append(_finding('info', 'Standard GATT values returned after connection',
            'Decoded values were reported. This does not establish access without pairing; GhostESP can initiate pairing automatically.',
            {'services': [s['service_name'] for s in sensitive]}))
    unknown = [s for s in services if s.get('service_name', '').lower().startswith('unknown')]
    if unknown:
        findings.append(_finding('info', 'Unrecognized GATT services reported',
            'The firmware did not name these services. Truncated UUIDs are preserved as reported and cannot establish vendor-specific functionality.',
            {'uuids_as_reported': [s.get('uuid') for s in unknown]}))
    if not services:
        findings.append(_finding('info', 'No structured GATT services available',
            'This result does not establish whether the device exposes services or vulnerabilities.', {}))
    return dict(record_count=len(services), status=enumeration.get('status', 'inconclusive'),
                summary=dict(service_count=len(services), services_with_decoded_characteristics=len(decoded),
                             unknown_service_count=len(unknown), pairing_failed=enumeration.get('pairing_failed', False),
                             truncated_uuid_count=sum(bool(s.get('uuid_is_truncated')) for s in services)),
                findings=findings)



def analyze_packets(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize 802.11 packet records from a passive capture: timestamp_s,
    captured_bytes, frame_type, frame_subtype, receiver, address_2,
    frequency_mhz, rssi_dbm.
    """
    findings: list[dict[str, Any]] = []
    if not rows:
        return {"record_count": 0, "findings": findings}

    DEAUTH, DISASSOC, PROBE_REQ = "12", "10", "4"
    subtype_counter: Counter[str] = Counter()
    mgmt_count = ctrl_count = data_count = 0
    addresses: set[str] = set()

    for row in rows:
        ftype = '' if row.get('frame_type') is None else str(row['frame_type']).strip()
        subtype = '' if row.get('frame_subtype') is None else str(row['frame_subtype']).strip()
        subtype_counter[f"{ftype}/{subtype}"] += 1
        if ftype == "0":
            mgmt_count += 1
        elif ftype == "1":
            ctrl_count += 1
        elif ftype == "2":
            data_count += 1
        for key in ("receiver", "address_2"):
            value = str(row.get(key) or "").strip()
            if value and value != "ff:ff:ff:ff:ff:ff":
                addresses.add(value)

    deauth_count = subtype_counter.get(f"0/{DEAUTH}", 0)
    disassoc_count = subtype_counter.get(f"0/{DISASSOC}", 0)
    if deauth_count or disassoc_count:
        findings.append(_finding(
            "medium", "Deauthentication/disassociation frames observed",
            f"Captured {deauth_count} deauth and {disassoc_count} disassoc "
            "frames passively over the air. These are commonly part of normal "
            "roaming, but a sustained flood toward one client/AP can indicate "
            "an active deauth attack already happening on the network. This "
            "capture did not send any; it only observed existing traffic.",
            {"deauth": deauth_count, "disassoc": disassoc_count}))

    probe_req_count = subtype_counter.get(f"0/{PROBE_REQ}", 0)
    if probe_req_count:
        findings.append(_finding(
            "info", "Probe requests observed",
            f"Captured {probe_req_count} probe-request frames, which can reveal "
            "client devices actively searching for known networks (useful for "
            "device inventory, weak signal for tracking since many devices "
            "randomize the source address).",
            {"probe_requests": probe_req_count}))

    summary = {
        "total_packets": len(rows),
        "management_frames": mgmt_count,
        "control_frames": ctrl_count,
        "data_frames": data_count,
        "other_or_unknown_frames": len(rows) - mgmt_count - ctrl_count - data_count,
        "deauth_frames": deauth_count,
        "disassociation_frames": disassoc_count,
        "probe_request_frames": probe_req_count,
        "unique_addresses_seen": len(addresses),
        "subtype_breakdown": dict(subtype_counter),
    }
    return {"record_count": len(rows), "summary": summary, "findings": findings}


def analyze_subghz(observation: dict[str, Any] | None, band_mhz: float | None = None) -> dict[str, Any]:
    """Heuristic findings over one radio's sub-GHz listen result, as
    returned by og_client.OgConsole.subghz_listen(): radio_index, events
    (hex payload frames), diagnostic_events, frequency_note.

    `band_mhz` should be the frequency (e.g. 315.0, 433.92, 915.0) that you
    know, from the OG's device settings, this radio index was tuned to
    during the capture; the OG cannot report that mapping itself.
    """
    if observation and observation.get('content_mode') == 'unframed_demodulated':
        rssi = [v for v in observation.get('rssi_dbm', []) if isinstance(v, (int, float))]
        return dict(record_count=len(observation.get('events', [])),
                    radio_index=observation.get('radio_index'),
                    frequency_hz=observation.get('frequency_hz'),
                    rssi_min_dbm=min(rssi) if rssi else None,
                    rssi_max_dbm=max(rssi) if rssi else None,
                    findings=[_finding('info', 'Unframed demodulator observations',
                        'Raw bytes can be noise. No decoded transmission, fixed code, rolling code or replay weakness is established.',
                        {'rf_link_validation': observation.get('rf_link_validation')})])

    findings: list[dict[str, Any]] = []
    if not observation:
        return {"record_count": 0, "findings": findings, "band_mhz": band_mhz}

    events = observation.get("events") or []
    rssi_values = observation.get("rssi_dbm") or []
    radio_index = observation.get("radio_index")
    band_label = f"{band_mhz} MHz" if band_mhz is not None else "unknown band (not reported by the device)"

    payloads = []
    for event in events:
        payload_hex = str(event.get("payload") or "").strip().replace(" ", "")
        try:
            payloads.append(bytes.fromhex(payload_hex))
        except ValueError:
            continue

    if not payloads:
        findings.append(_finding(
            "info", "No raw sub-GHz data captured",
            f"Radio index {radio_index} ({band_label}) returned no parsed data "
            "bytes during this listen window; only status/diagnostic messages, "
            "if any, were seen. This does not confirm the radio or antenna works.",
            {"diagnostic_events": observation.get("diagnostic_events", [])}))
        return {"record_count": 0, "findings": findings, "band_mhz": band_mhz, "radio_index": radio_index}

    idle_payload = bytes([0xFF]) * len(payloads[0])
    non_idle = [p for p in payloads if p != idle_payload and any(b != 0xFF for b in p)]
    unique_payloads = {p for p in non_idle}
    byte_histogram: Counter[int] = Counter()
    for payload in non_idle:
        byte_histogram.update(payload)

    if non_idle:
        repeat_ratio = 1 - (len(unique_payloads) / len(non_idle))
        if len(unique_payloads) <= 3 and len(non_idle) >= 3:
            findings.append(_finding(
                "medium", "Low-diversity / fixed-code sub-GHz traffic",
                f"Radio index {radio_index} ({band_label}) captured "
                f"{len(non_idle)} non-idle frames reducing to only "
                f"{len(unique_payloads)} distinct payload(s). Many consumer "
                "remotes/sensors (garage doors, doorbells, simple key fobs) "
                "use a static, unencrypted, replayable code; this pattern is "
                "consistent with that, though it can also just mean the same "
                "legitimate transmission was captured repeatedly.",
                {"unique_payloads_hex": [p.hex() for p in unique_payloads][:10],
                 "non_idle_frame_count": len(non_idle), "repeat_ratio": round(repeat_ratio, 2)}))
        else:
            findings.append(_finding(
                "info", "Varying sub-GHz payloads observed",
                f"Radio index {radio_index} ({band_label}) captured "
                f"{len(non_idle)} non-idle frames with {len(unique_payloads)} "
                "distinct payloads, which is less consistent with a simple "
                "static fixed-code remote and more consistent with rolling "
                "codes, sensor telemetry, or multiple nearby transmitters.",
                {"unique_payload_count": len(unique_payloads), "non_idle_frame_count": len(non_idle)}))
    else:
        findings.append(_finding(
            "info", "Only idle/all-ones frames captured",
            f"Radio index {radio_index} ({band_label}) only returned idle-line "
            "filler bytes (0xFF runs), with no decoded transmission observed "
            "in this window.",
            {"frame_count": len(payloads)}))

    findings.append(_finding(
        "info", "No known test transmitter used",
        f"Radio index {radio_index} ({band_label}) data was not checked "
        "against an expected payload from a known transmitter, so a real "
        "RF link versus ambient noise cannot be confirmed from this data "
        "alone.",
        {}))

    valid_rssi = [v for v in rssi_values if isinstance(v, (int, float)) and -140 <= v <= 10]
    if valid_rssi:
        weakest, strongest = min(valid_rssi), max(valid_rssi)
        if strongest > -40:
            findings.append(_finding(
                "low", "Strong nearby sub-GHz signal",
                f"Radio index {radio_index} ({band_label}) measured RSSI up to "
                f"{strongest} dBm, consistent with a transmitter very close to "
                "the antenna (same room/building), worth confirming it is an "
                "expected device.",
                {"rssi_values": valid_rssi}))
        findings.append(_finding(
            "info", "RSSI range observed",
            f"Radio index {radio_index} ({band_label}) RSSI ranged from "
            f"{weakest} to {strongest} dBm across {len(valid_rssi)} reading(s).",
            {"rssi_values": valid_rssi}))

    summary = {
        "radio_index": radio_index,
        "band_mhz": band_mhz,
        "total_frames": len(payloads),
        "non_idle_frames": len(non_idle),
        "unique_non_idle_payloads": len(unique_payloads),
        "diagnostic_event_count": len(observation.get("diagnostic_events", [])),
        "rssi_samples": valid_rssi,
        "common_bytes": byte_histogram.most_common(5),
    }
    return {"record_count": len(payloads), "summary": summary, "findings": findings, "band_mhz": band_mhz}


def combine_findings(*analyses: dict[str, Any]) -> list[dict[str, Any]]:
    combined: list[dict[str, Any]] = []
    for item in analyses:
        combined.extend(item.get("findings", []))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    combined.sort(key=lambda f: order.get(f["severity"], 9))
    return combined
