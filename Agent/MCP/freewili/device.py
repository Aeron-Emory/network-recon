"""High-level device session: discovery, locking, identification, and
capability reporting, tying together transport/og_client/ghostesp_client.

This is the only module server.py should need to import for hardware
access. It never imports or shells out to anything in the parent workshop
folder.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re

from . import transport
from .ghostesp_client import GhostEspLink
from .og_client import OgConsole, UnsupportedFeature


@dataclass
class ConnectionTarget:
    og_port: Optional[str] = None
    bottlenose_usb_port: Optional[str] = None


def detect_connection() -> dict:
    """Report every Free-WILi-related serial port currently visible, and
    which roles are present, without opening any of them.
    """
    ports = transport.enumerate_ports()
    relevant = [p for p in ports if p.is_og_main or p.is_og_display or p.is_bottlenose_usb]
    return dict(
        all_ports=[p.to_dict() for p in ports],
        relevant_ports=[p.to_dict() for p in relevant],
        og_main_found=any(p.is_og_main for p in relevant),
        og_display_found=any(p.is_og_display for p in relevant),
        bottlenose_direct_usb_found=any(p.is_bottlenose_usb for p in relevant),
    )


def identify_og(port: Optional[str] = None) -> dict:
    """Open the OG MAIN console just long enough to identify its firmware
    and report menu capabilities. Read-only: no settings are changed.
    """
    info = transport.find_og_main(port)
    with transport.PortLock(info.port):
        if info.is_raw_bridge:
            with GhostEspLink(via_og=True, port=info.port) as link:
                identity = link.identify()
            state = 'available' if identity.matches_expected else 'unresponsive'
            return dict(port=info.port, firmware_kind='raw_bridge', firmware=info.product,
                        bottlenose_firmware=identity.firmware, model=identity.model,
                        capabilities=dict(wifi=state, ble=state, packet_capture=state,
                                          subghz='receive_only' if int(info.product.rsplit(' ', 1)[-1]) >= 3 else 'unavailable', legacy_menus='unavailable'))
        with OgConsole(info.port) as console:
            capabilities = console.probe_capabilities()
            return dict(
                port=info.port,
                firmware_kind=console.identity.firmware_kind,
                banner=console.identity.banner,
                capabilities=capabilities,
            )


def identify_ghostesp(via_og: bool, port: Optional[str] = None) -> dict:
    """Identify the Bottlenose GhostESP firmware, either through the OG
    bridge or its own direct USB port. Read-only.
    """
    if via_og:
        resolved = transport.find_og_main(port)
    else:
        resolved = transport.find_bottlenose_usb(port)
    with transport.PortLock(resolved.port):
        try:
            with GhostEspLink(via_og=via_og, port=resolved.port) as link:
                identity = link.identify()
                return dict(
                    port=resolved.port, via_og=via_og,
                    firmware=identity.firmware, model=identity.model,
                    matches_expected_build=identity.matches_expected,
                    chipinfo=identity.raw_chipinfo,
                )
        except UnsupportedFeature as exc:
            return dict(port=resolved.port, via_og=via_og, available=False, reason=str(exc))


def bridge_status(port: Optional[str] = None) -> dict:
    candidates = [p for p in transport.enumerate_ports()
                  if p.is_og_display and p.product.startswith('FWOG display bnbridge ')
                  and (port is None or p.port.lower() == port.lower())]
    if len(candidates) != 1:
        raise transport.DeviceNotFoundError('Select one bnbridge DISPLAY port (currently COM9) for counters.')
    info = candidates[0]
    with transport.PortLock(info.port), transport.SerialLink(info.port) as link:
        raw = link.read_for(2.2).decode('utf-8', errors='replace')
    lines = [line for line in raw.splitlines() if line.startswith('BNBRIDGE ')]
    if not lines:
        raise transport.DeviceCommunicationError('Bridge counters did not arrive.')
    counters = {key: int(value) for key, value in re.findall(r'(\w+)=(\d+)', lines[-1])}
    return dict(port=info.port, status='ok' if counters.get('ready') == 1 else 'error',
                counters=counters, raw_text=raw,
                note='Counters are cumulative since OG boot. Compare before/after differences; startup baud transitions can cause initial UART errors.')
