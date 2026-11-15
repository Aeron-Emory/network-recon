# Sharing this MCP server

This subfolder contains the Free-WILi Recon MCP server source. Firmware, source archives and notices are supplied separately at the bundle root. For remote operation use `../../REMOTE-SETUP.md`.

## Install (Windows)

1. Extract `MCP/` to a writable location on the Windows PC connected to your Free-WILi OG.
2. In PowerShell, `cd` into `MCP/`.
3. Run `python -m venv .venv`.
4. Run `.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
5. Update BOTH absolute paths in `mcp-config.example.json` to your extracted location, then insert its `mcpServers` entry into your MCP client's configuration. Each client can point to this same installation.
6. Connect an OG running compatible `bnbridge` firmware and Bottlenose running compatible GhostESP firmware. This Python subfolder does not install firmware; see `../../docs/FLASHING.md` for the separate images.
7. Optional offline verification: `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.

## Files not distributed

- `.venv/` (automatically recreated by steps 3-4)
- `__pycache__/` and `*.pyc` (automatically recreated by Python)
- `results/`, `.port-locks/`, `.pcap`, `.bin`, logs (created when needed; previously recorded data intentionally omitted)
- Private chat transcripts, troubleshooting probes and local path-specific config

The MCP server can run without the hardware, but hardware scan tools require a compatible Free-WILi OG + Bottlenose and their installed firmware.

Only scan networks and devices you are authorized to assess.
