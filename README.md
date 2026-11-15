# Free-WILi wireless recon with an AWS agent

The Windows PC controls USB-connected Free-WILi hardware. A Strands agent in AWS Workshop Studio calls its authenticated MCP endpoint and uses Amazon Bedrock to interpret observations. Local MCP clients can also use stdio.

```text
AWS: Strands + Bedrock
         | HTTPS /mcp + bearer token
         v
HTTPS tunnel -> Windows MCP gateway -> USB-C on Free-WILi OG
                                          | expansion UART
                                          v
                                 Bottlenose ESP32-C6
OG also supplies two CC1101 sub-GHz receivers.
```

## Start here

1. Leave USB on the powered OG, with Bottlenose attached. The demo hardware does not need reflashing.
2. Follow [REMOTE-SETUP.md](REMOTE-SETUP.md) for the Windows gateway and AWS agent. Python 3.12 is tested locally; the workshop's Python 3.13 has not been exercised here.
3. For Kiro or another local MCP client, use [Agent/MCP/README.md](Agent/MCP/README.md) instead.
4. Use [docs/FLASHING.md](docs/FLASHING.md) when provisioning another board. Source/build details are in [docs/BUILDING.md](docs/BUILDING.md).

## Contents

| Path | Contents |
| --- | --- |
| `Agent/MCP/` | USB clients, analysis, saved results, stdio and authenticated HTTP server, offline tests |
| `Agent/network-analyst-pentester/` | Interactive Strands agent, AgentCore deployment entrypoint and their skills |
| `Firmware needed/` | Five tested firmware images, install manifest and checksums |
| `sources/` | OG bridge source, exact Bottlenose patch scripts, upstream GhostESP build source |
| `licenses/` | Component licenses and notices |
| `scripts/verify_package.py` | Check the distributed SHA-256 inventory without hardware |

Virtual environments, caches, captured data, device backups, credentials, live tunnel URLs, old firmware, build outputs and toolchain binaries are excluded. Install third-party dependencies from the requirements files. The five firmware binaries are intentional deliverables.

## Capabilities and limits

Wi-Fi discovery and single-channel 2.4 GHz packet capture; BLE advertiser discovery; dual CC1101 reception with RSSI and raw demodulator bytes. Discovery can emit standard probe/scan requests. Capture and sub-GHz reception are passive. Analysis produces heuristic indicators for human review, not confirmed vulnerabilities or decrypted protected traffic.

HTTP exposes 20 tools. Local stdio exposes 22, adding explicitly approved active BLE GATT enumeration and processor reset (reset is unavailable under bnbridge). The MCP interface has no arbitrary transmit, injection, deauthentication or flashing tools.

Maestro GPIO/debug features are not integrated. CC1101 reception has not been verified against a known transmitter; noise bytes do not prove a working RF link. CC1101 cannot demodulate Meshtastic LoRa. The bridge replaces legacy OG menus; the DISPLAY application is embedded in the MAIN image.

Use only in an authorized environment. Remote observations/results go to AWS/Bedrock; saved raw runs remain on the PC until requested through tools.

See [licenses/README.md](licenses/README.md). This package combines differently licensed components; no blanket license is asserted. In particular, the FreeWili BSP uses a hardware-restricted license, not ordinary MIT.
