# Component licenses and notices

No single license is applied to this bundle. Original copyright notices remain with their respective sources. This packaging step does not choose a new blanket license for the original agent/MCP/bridge code.

| Component | License / supplied notices |
| --- | --- |
| FreeWili OG BSP, commit `3426c46728361299ab2687a073579ac6fc1c253d` | `BSP-LICENSE`, `BSP-NOTICE`, `BSP-THIRD-PARTY-NOTICES.md`. FreeWili Hardware License for FreeWili-targeted use; field-of-use restriction means this is not ordinary MIT or OSI open source. |
| GhostESP v2.2.2, commit `98d92efb8202cb4139e995600e4357ae50bbaab6` | `GhostESP-GPL-3.0.txt`. Build source/components/notices are in `sources/upstream/`; local modifications are in `sources/bottlenose-patches/`. |
| Raspberry Pi Pico SDK 2.3.0 | `pico-sdk-LICENSE.TXT`; dependency notices also accompany the upstream checkout specified in the build guide. |
| TinyUSB | `tinyusb-LICENSE`; revision pinned by the selected Pico SDK. |

GhostESP vendored components retain their license files inside its build-source archive. BSP notices identify its other bundled components. Installed Python packages and build tools retain upstream licenses; their environments/executables are not redistributed here.

## GhostESP reproduction limits

The source archive includes the pinned application's build inputs: vendored components, source assets, CMake files, configuration and build scripts. Website history, optional external plugin examples, a separate desktop OTA updater and prebuilt host executables are omitted; `sources/upstream/GhostESP-source.json` records the exclusions.

The release image reports ESP-IDF `v6.1-dirty`. The exact customized upstream ESP-IDF checkout and CI environment were not obtained, so a byte-identical source rebuild is not claimed. The local patch scripts reproduce the adjusted application exactly from the hash-verified upstream release application. See `docs/BUILDING.md`. Patch scripts alone are not a substitute for upstream corresponding source.
