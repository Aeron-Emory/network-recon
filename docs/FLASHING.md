# Firmware provisioning

The demonstrated board already has these images. Do not reflash it just to run the software. Stop the MCP gateway, serial terminals and other hardware clients before provisioning a new board.

Run `python scripts/verify_package.py` from the bundle root first. `Firmware needed/manifest.json` identifies all images and flash addresses. Never flash an image to a different processor.

## OG MAIN and DISPLAY

Install the DISPLAY bootloader once, then MAIN. Both use an inter-CPU rate of 6250000 baud. The MAIN image carries the DISPLAY application and installs it through the bootloader protocol. **Do not native-UF2 flash a DISPLAY application.**

The vendor BSP's unmodified `scripts/fw.py` is included for BOOTSEL recovery and MAIN UF2 transfer. Its license is in `licenses/BSP-LICENSE`. It needs Python and pyserial; the MCP environment provides both. All commands below run from the bundle root with USB connected to the OG. COM port numbers vary; identify roles first using your MCP client or the OS USB device list. OG MAIN uses VID:PID 093C:2054, DISPLAY uses 093C:2055.

For a board still running legacy DISPLAY firmware:

```powershell
Agent/MCP/.venv/Scripts/python.exe scripts/fw.py bootsel --cpu display
```

Exactly one `RPI-RP2` drive should appear. Copy `Firmware needed/OG/DISPLAY/bnbridge-display-bootloader-v001.uf2` onto it. The drive disappears as it reboots. Do not put both processors into BOOTSEL at once. If DISPLAY cannot enter BOOTSEL or reappear, use the vendor recovery procedure rather than guessing which drive/processor to flash.

Then install MAIN (or update a board that already has the matching DISPLAY bootloader):

```powershell
Agent/MCP/.venv/Scripts/python.exe scripts/fw.py flash bnbridge --uf2 "Firmware needed/OG/MAIN/bnbridge-main-v004.uf2"
```

The board restarts and MAIN transfers the embedded DISPLAY application. Check identification, bridge status and both radio statuses afterward. This replaces the legacy OG applications/menus; it does not restore them or integrate Maestro.

## Bottlenose ESP32-C6, rev 1, 4 MiB

Provision through **direct Bottlenose USB-C**, with the board still attached to the powered OG. Return USB to the OG afterward. The bundled images are for the tested ESP32-C6, not another ESP family.

In a separate temporary environment install `esptool==5.6.0`. Replace `COM12` below with the direct C6 USB port (303A:1001), not either OG port. If automatic download entry fails, hold BOOT, tap/release RESET, then release BOOT while USB remains connected to Bottlenose.

Before changing another board, make a private backup outside the shareable folder:

```powershell
python -m esptool --chip esp32c6 --port COM12 read-flash 0x0 0x400000 C:/private-backups/bottlenose-before.bin
```

The destination directory must exist. Keep full flash backups private because they can contain NVS settings or other user data. Do not erase the whole chip merely to install these three images.

From the bundle root:

```powershell
python -m esptool --chip esp32c6 --port COM12 write-flash 0x0 "Firmware needed/Bottlenose/ESP32-C6 bootloader/bootloader.bin" 0x8000 "Firmware needed/Bottlenose/partition table/partitions.bin" 0x10000 "Firmware needed/Bottlenose/adjusted GhostESP v2.2.2 application/firmware.bin"
```

Esptool verifies written data. For explicit read-back comparison:

```powershell
python -m esptool --chip esp32c6 --port COM12 verify-flash 0x0 "Firmware needed/Bottlenose/ESP32-C6 bootloader/bootloader.bin" 0x8000 "Firmware needed/Bottlenose/partition table/partitions.bin" 0x10000 "Firmware needed/Bottlenose/adjusted GhostESP v2.2.2 application/firmware.bin"
```

Press RESET only if the C6 remains in download mode. Return USB to the OG and check identification, then short Wi-Fi/BLE scans. Do not change baud/flow-control settings: both sides are matched at 460800 8N1 with no RTS/CTS. No eFuse, secure-boot or flash-encryption changes are part of this process.

References: [Espressif flashing](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/esptool/flashing-firmware.html), [advanced verification](https://docs.espressif.com/projects/esptool/en/latest/esp32c6/esptool/advanced-commands.html), [FreeWili BSP](https://github.com/freewili/wiliOGbsp).
