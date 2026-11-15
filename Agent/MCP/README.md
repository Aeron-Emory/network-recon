For remote AWS operation, use [REMOTE-SETUP.md](../../REMOTE-SETUP.md). The HTTP gateway exposes 20 tools; the local stdio interface below exposes 22. Firmware is supplied separately at the root of this bundle.

# Free-WILi Recon MCP server

This server independently controls the connected hardware and returns JSON
observations to an MCP client. It runs entirely from this folder: no imports,
subprocess calls or runtime reads of the parent workshop scripts/results.
Its scans and captures are saved under this folder's `results/` directory.

**Source-only distribution:** read [SHARING.md](SHARING.md) for installation
and packaging details. Hardware tools require compatible firmware already
installed on the OG and Bottlenose; firmware is not included or installed by
this Python package.

## Required hardware and firmware

The tested setup uses Free-WILi OG with bnbridge 004 and an attached
Bottlenose ESP32-C6 running an adjusted GhostESP Revival v2.2.2 image.
The expansion UART must match at 460800 baud, 8N1, with hardware flow
control off. Compatible firmware must be obtained and installed separately.

```text
MCP client -> this server -> OG USB COM8 -> bnbridge 004
                                           |
                                UART 460800 8N1
                                           |
                                Bottlenose GhostESP v2.2.2
```

USB stays on the **OG**. The display CPU exposes bridge diagnostics and radio
controls through its own USB serial port. COM8 and COM9 are example
assignments from the tested setup; your port numbers may differ.
Use `detect_connection()` to find them. Most tools select the matching port
automatically when only one board is connected.
Windows discovery reads the USB product string to distinguish bnbridge from
legacy OG firmware. It refuses a DISPLAY port passed as MAIN, and does not
invent identities for missing ports. Linux/macOS use pyserial's product field.
The legacy Wi-Fi/BLE menu client remains for older OG images. Sub-GHz MCP
tools require bnbridge 003 or later.

## Install and connect

From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Copy the `mcpServers` entry from [mcp-config.example.json](mcp-config.example.json) into your
MCP client's configuration. Replace both placeholder paths with the absolute
paths to your installation's Python executable and `server.py`.
For Kiro, add the entry to your workspace's `.kiro/settings/mcp.json` and
preserve existing server entries. Reconnect the server after changing its
configuration. The MCP client launches `server.py` automatically.

The command runs a stdio server and normally waits quietly for an MCP client:

```powershell
.\.venv\Scripts\python.exe server.py
```

Suggested first tool calls:

1. `detect_connection()`
2. `identify_og()`
3. `get_bridge_status()`
4. `scan_wifi_via_og(seconds=8)`
5. `scan_ble_via_og(seconds=8)`
6. `capture_wifi_packets(channel=6, seconds=10)`

Close other serial terminals first. Advisory kernel locks serialize this
server's operations. They release on process exit and cannot expire while
still owned. Serial operations have a 90-second budget, bounded OS discovery
and reads, and short bounded cleanup. There are no abandoned worker threads
retaining a port after a timeout. Discovery durations are 1-30 seconds;
monitor channels are 1-11.

## Tools and current availability

22 tools are registered:

| Tools | Purpose / current status |
| --- | --- |
| `detect_connection`, `identify_og`, `identify_bottlenose` | USB roles, bridge and C6 firmware identity; validated |
| `get_bridge_status` | Cumulative byte, queue-drop and UART-error counters on DISPLAY USB; validated |
| `scan_wifi_via_og`, `scan_wifi_via_ghostesp` | SSID, BSSID, RSSI, channel, band and security; validated over OG USB |
| `scan_ble_via_og`, `scan_ble_via_ghostesp` | BLE advertisement address, RSSI and available name/manufacturer/services; validated |
| `capture_wifi_packets` | Passive 802.11 capture, packet metadata, valid PCAP and original wire bytes; validated |
| `scan_gatt_devices` | Discovery of connectable BLE advertisers; implemented, not live-tested in this task |
| `gatt_enumerate_device` | Active BLE connection/service enumeration; requires explicit per-device approval; not live-tested |
| `subghz_radio_status`, `subghz_listen` | Dual CC1101 identity/status, tuning, RSSI samples and raw demodulator bytes through DISPLAY USB; validated |
| `maestro_capabilities` | Reports unavailable I/O/debug integration rather than claiming wireless support |
| `analyze_wifi_records`, `analyze_ble_records`, `analyze_gatt_enumeration`, `analyze_packet_capture`, `analyze_subghz_observation` | In-memory heuristic findings, separate from observations |
| `list_saved_runs`, `get_saved_observation` | This folder's saved JSON observations only |
| `reset_og_main_processor` | Explicit confirmation required; unavailable under bnbridge |

`scan_*_via_og` automatically chooses GhostESP on bnbridge, so those names
continue to work with the new firmware. GhostESP tools default to `via_og=True`.
Direct Bottlenose USB is optional (`via_og=False`), not required.

Discovery may emit normal Wi-Fi probe/BLE scan requests. Packet monitoring
is receive-only. No MCP tool flashes firmware, changes UART/startup settings,
joins networks, injects arbitrary frames or runs deauthentication/spoofing
attacks. GATT enumeration can trigger pairing and is kept behind its explicit
confirmation parameter. Findings are indicators, not confirmed vulnerabilities;
missing security metadata is not treated as evidence of an open network.

## Saved results and interpretation

Each scan gets a unique directory containing `observation.json`. Capture runs
also retain `capture.pcap` and `capture-wire.bin`. The tool reply includes the
folder name as `saved_to` and omits binary blobs. Packet parsing removes console
text only between valid records; corrupt binary data ends the valid export
and is reported as inconclusive, rather than silently resynchronized.

A valid PCAP does not prove every over-the-air packet was received. Compare
bridge counter differences over a test: initial UART errors during boot can
exist before capture begins. BLE advertiser records are not necessarily
unique physical devices. Discovery does not verify network connectivity,
BLE pairing, GATT access control or exploitation.

## Verification

Offline tests, no hardware access:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

38 tests cover simulated bridge replies, port-role checks, kernel lock
exclusion, deadline cleanup, exact command grammar, capture/BLE stop on read
failure, binary parsing, raw capture retention, explicit GATT/reset refusals,
results confinement, missing-security handling and a real stdio registration/refusal check.

Opt-in live stdio verification (performs Wi-Fi/BLE discovery and passive capture):

```powershell
.\.venv\Scripts\python.exe verify_mcp.py
```

Run this check with the OG connected and compatible firmware installed.
It performs discovery and packet capture, saves its results under `results/`,
and checks that scans still work after capture stops. Previously recorded
results and development conversations are not included in this distribution.

## Sub-GHz radio controls

Keep the same cable on the OG. Radio requests use COM9 and leave COM8's binary
capture stream alone. `port="COM8"` selects the matching DISPLAY automatically
when only one OG is attached; select COM9 explicitly if multiple boards exist.

```text
subghz_radio_status(radio_index=1, port="COM8")
subghz_listen(radio_index=1, frequency_mhz=433.92, seconds=8, modulation="ook", port="COM8")
subghz_listen(radio_index=2, frequency_mhz=915, seconds=8, modulation="ook", port="COM8")
```

Radio 1 uses CS1/GPIO18; radio 2 uses CS0/GPIO5, matching the legacy
application's variable numbering rather than a claim about connector labels.
Default frequencies are 433.92 and 915 MHz respectively. Explicit frequency
selection is supported in 300-348, 387-464 and 779-928 MHz. The attached
antennas should match the selected band. ASK/OOK, 2-FSK and GFSK receive
profiles use nominal 4800 baud / 203.125 kHz bandwidth. These are starting
profiles, not universal protocol decoders; LoRa decoding is unavailable.

RX duration is bounded to 1-30 seconds. The client stops it on completion or
error; firmware independently stops it on timeout and parks radios in idle
at startup. There are no transmit commands. `band_mhz_hint` remains metadata
only; use `frequency_mhz` for actual tuning.

The result separates hardware status, frequency readback, RSSI samples,
received raw bytes, overflow/error counters and `rf_link_validation`. The
raw byte stream may be noise. No framing, protocol identity, fixed/rolling
code, replay weakness or end-to-end RF reception is inferred from it.
A known test transmitter was unavailable; the labeled screw-on antennas
are not signal generators.

Standalone CLI (from this folder):

```powershell
.\.venv\Scripts\python.exe radio_cli.py status --radio 1
.\.venv\Scripts\python.exe radio_cli.py listen --radio 1 --frequency 433.92 --seconds 8
.\.venv\Scripts\python.exe radio_cli.py listen --radio 2 --frequency 915 --seconds 8
```

Optional receive/capture coexistence check:

```powershell
.\.venv\Scripts\python.exe verify_radios.py
```

This check runs both sub-GHz receivers alongside Wi-Fi packet capture,
compares forwarding/error counters and checks subsequent Wi-Fi/BLE scans.
It creates new results locally. It does not transmit on the sub-GHz radios
or establish reception of a known over-the-air signal.

## Analyze saved results

All five `analyze_*` tools accept **either** inline data **or** `run_name`.
A run name loads the entire saved observation server-side, without sending
large arrays through the model. Do not supply both. Replace `<saved_to>`
with the `saved_to` value returned by the matching scan or capture tool.
These examples refer to different types of saved run:

```text
analyze_packet_capture(run_name="<saved_to>")
analyze_gatt_enumeration(run_name="<saved_to>")
analyze_wifi_records(run_name="<saved_to>")
```

Saved scan/capture/listen replies now return at most 50 entries per top-level
collection, explicit complete counts and `pagination` metadata. Full
observations, PCAP and wire bytes remain saved. Raw console text is omitted
from these previews. Radio replies include full RSSI minimum/maximum/average
and valid-sample count. `save=False` retains the full inline response for
clients explicitly choosing unsaved data.

`list_saved_runs(limit=20, offset=0)` returns `{runs, total, next_offset, ...}`
with metadata/counts rather than every observation.
`get_saved_observation(run_name, field="packets", offset=50, limit=50)`
returns a page (maximum limit 200). Pagination is for inspecting data; use
`analyze_*` with `run_name` for full-data analysis.

Interpret analysis results as observations and heuristic findings, not a
security certification. GATT service discovery can return partial information
when pairing fails. Truncated UUIDs remain truncated, and returned values do
not establish that access was possible without pairing. No findings does not
establish that a device or network is free of vulnerabilities.
