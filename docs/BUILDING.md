# Firmware source and build inputs

Building firmware is optional. Use the supplied images to reproduce the demonstrated deployment. Python setup needs no compiler, CMake kit or SDK.

## OG bridge

`sources/og-bridge/` contains v004 application source with portable dependency parameters.

Pinned inputs:

- [FreeWili BSP](https://github.com/freewili/wiliOGbsp), commit `3426c46728361299ab2687a073579ac6fc1c253d`.
- [Pico SDK](https://github.com/raspberrypi/pico-sdk) 2.3.0, commit `98a542c1a62fb549ffb5d66a3e5892b06276b670`; initialize its pinned TinyUSB submodule.
- Arm GNU Toolchain 13.3.Rel1 (gcc 13.3.1), CMake 4.4.5, Ninja 1.13.2, Python, and picotool compatible with SDK 2.3.0. Install separately; executables/environments are not bundled.

From the bundle root:

```powershell
git clone https://github.com/freewili/wiliOGbsp .deps/wiliOGbsp
git -C .deps/wiliOGbsp checkout 3426c46728361299ab2687a073579ac6fc1c253d
git clone https://github.com/raspberrypi/pico-sdk .deps/pico-sdk
git -C .deps/pico-sdk checkout 98a542c1a62fb549ffb5d66a3e5892b06276b670
git -C .deps/pico-sdk submodule update --init lib/tinyusb
.\sources\og-bridge\build.ps1 -BspPath .deps/wiliOGbsp -PicoSdkPath .deps/pico-sdk -PicotoolPath C:/path/to/picotool.exe -ToolchainPath C:/path/to/arm-gnu-toolchain
```

The script uses `cmake`, `ninja`, and `python` on PATH. MAIN and DISPLAY bootloader must both use `FWOG_LINK_BAUD=6250000`; the script supplies it. Outputs are `sources/og-bridge/build/bnbridge_main.uf2` and `sources/og-bridge/build/bl/bl_display.uf2`. New builds may differ in hashes because of source paths, tools and metadata. No newly built image was flashed as part of packaging.

## Bottlenose: exact application reproduction

The installed image is a version-locked binary patch of GhostESP v2.2.2's generic ESP32-C6 release, not a source rebuild. The final patch sets UART to 460800 and USB capture-write timeout to ten RTOS ticks, updating image checksum/digest. `patch_ghostesp_uart.py` is an imported helper; its intermediate 921600-baud result is not the final firmware.

Download `esp32c6-generic.zip` from the [v2.2.2 release](https://github.com/GhostESP-Revival/GhostESP/releases/tag/v2.2.2). Its SHA-256 must be `ff4a7a480776870b4f17eb006832d09221d6bca2bf14354c0c32b94ab59a5423`. Extract the unmodified `firmware.bin` outside this bundle. The patch requires its exact SHA-256 `df56e655c2ac4a06e88b8eb335bdd534d288801dce9457eeb31a0ee87f577295`.

```powershell
python sources/bottlenose-patches/patch_ghostesp_capture_io.py --input C:/temp/esp32c6-generic/firmware.bin --output C:/temp/rebuilt/firmware.bin
```

The output SHA-256 must be `dc9d9ef713057bfc2cb7f07cd0d2f90e049b6b2b5e6ac875dfe2eacfcc3225c1`, identical to the bundled application. Existing outputs are refused; a byte-change report is saved beside the new output. The patch does not alter bootloader or partition table. Original release ZIP/ELF files are not duplicated here.

## GhostESP upstream build source

`sources/upstream/GhostESP-v2.2.2-build-source.tar.xz` contains matching commit `98d92efb8202cb4139e995600e4357ae50bbaab6`, including build configurations, vendored components and notices. `GhostESP-source.json` records provenance, digest and exclusions. Extract into a new working directory using `tar -xf` or an archive tool.

The release image descriptor confirms app version `98d92ef`, ESP32-C6, flash 4 MiB, DIO/80 MHz, and ESP-IDF `v6.1-dirty`. The exact customized upstream IDF checkout was not obtained, so a byte-identical source rebuild is not promised. Follow the included `.github/workflows/compile_all.yml` generic-C6 target and `configs/sdkconfig.default.esp32c6`; managed dependencies are in `main/idf_component.yml`. Required generated assets remain because they are upstream build inputs, not local caches.

Website history, optional external plugin examples, a separate host OTA updater and prebuilt host executables are omitted. Source builds require Espressif's build environment and dependency resolution. The deterministic binary-patch reproduction above is independently verified.
