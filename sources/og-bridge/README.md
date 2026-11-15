# bnbridge 004

MAIN provides a raw USB CDC to expansion UART bridge at 460800 8N1, no RTS/CTS, with a 128 KiB interrupt receive ring and forwarding/error counters. DISPLAY serves the status UI and a separate radio/control USB console. The inter-CPU link is 6250000 baud.

MAIN preserves watchdog servicing; DISPLAY preserves six-second red-hold power-off. CC1101 receivers start idle and listening expires after at most 30 seconds. Raw radio bytes can be noise; no known-transmitter RF validation is claimed. Maestro and legacy OG menus are not integrated.

The DISPLAY application is embedded in MAIN. The separate DISPLAY UF2 is its bootloader. Never native-UF2 flash a DISPLAY application.

See `../../docs/BUILDING.md` and `../../docs/FLASHING.md`. This is the final v004 source; only build/dependency paths were made portable. BSP license/notices are supplied in `../../licenses/`.
