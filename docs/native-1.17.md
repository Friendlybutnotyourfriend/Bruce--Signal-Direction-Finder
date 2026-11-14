# Native Bruce 1.17 custom tools

Base: official Bruce tag `1.17`, commit `2b6ba4d490bfcf94ce2574c6154537dbd5838c3d`.

Three separate **application-only** binaries are built, in this order:

1. CBD 2.8 inch: LCDWiki ES3C28P, ESP32-S3, capacitive touch. Not a classic ESP32 CYD or E32R28T.
2. Cardputer ADV: upstream `m5stack-cardputer` target, including upstream ADV detection and audio support.
3. LilyGO T-Embed CC1101: upstream `lilygo-t-embed-cc1101` target, including its antenna switch handling.

## Install using Launcher

Copy the matching `*-Launcher.bin` onto the device's SD card. In Launcher, select that file and install/run it as an application. Keep your existing Launcher installed. These files are not merged flash dumps and must not be written to address zero.

Launcher must offer an application slot at least as large as the binary. The manifest records exact size, source revision and SHA256. The build checks its standalone app partition too; it cannot inspect the partition table on your physical device. Do not accept a truncated image if Launcher reports insufficient space.

Open Config / device information after boot and check `1.17-native1` and the source revision. Existing radio-pin settings are retained by Bruce: check them after upgrading, especially if this card/config came from another device.

The 16 MB standalone build layout reserves 5 MiB for the application because the full custom 1.17 image exceeds the former 0x470000-byte slot. This layout is a build/standalone-flash setting: an app-only Launcher install does not replace your device's partition table.

## Included custom work

| Feature | Source carried forward | Native menu |
|---|---|---|
| BLE Hunter / Sniffer v3, FE9F/FCF1 analysis, continuity and active-scan bursts | Field Evolution and latest HUGINN fixes | DF and BLE |
| BLE session recording, review, desktop replay and VNA profile import | Field Evolution | DF / BLE Sessions; `tools/recon_session.py` |
| Proximity audio, alerts and deliberate five-second voice notes | HUGINN audio fixes, adapted to 1.17 speaker/mic APIs | Hunter / Sniffer actions |
| Backlight-off monitoring and touch wake | HUGINN CBD | CBD Hunter / Sniffer actions |
| Sub-GHz and 2.4 GHz surveys; A/B/A antenna comparison | Antenna ID / Field Evolution | RF |
| Opt-in CC1101 and nRF24 profiles | Radio Control Centre v1 | RF / NRF24 |
| RF Black Box and Receive Profile Finder | RF Lab plus stability corrections | RF |
| WiFi / BLE Sentinel | Latest Sentinel plus stability corrections | WiFi and BLE |
| Pin-conflict checks, capture clipping, register readback, source metadata and exposure-aware scoring | CBD stable1 | Integrated |

The feature source is the latest combined stability revision `753a1bdfd167b92e77a0bcad075f52a7765a0199`, checked against the HUGINN audio-fix, Field Evolution, radio-control and RF Lab branch heads. Earlier standalone nRF52840/direct-CDC experiments are separate firmware, not ESP32 Bruce apps. Fenrir/E32R28T board profiles are outside this three-target build.

Upstream 1.17 board configuration, HAL, menus, RF decoding and audio fixes are retained. Short background cues do not consume foreground key input. Small-screen antenna results fit the Cardputer; Hunter's graph appears only where screen height permits.

## Hardware requirements and limits

Internal WiFi/BLE tools work without an external RF module. CC1101 tools require a connected and configured CC1101; nRF24 tools require an nRF24. Only the T-Embed CC1101 target has its CC1101 wired onboard.

On the CBD, SPI defaults are SCK14 / MISO2 / MOSI3 / CS21. GDO0 and CE intentionally start unassigned: their old defaults collided with MISO/MOSI. Wire and configure a separate control pin. IO43 is only a proposed option when UART/GPS is unused; it is not assigned automatically or bench verified. Existing overlapping saved pin maps are rejected.

Ambient surveys measure received activity, not antenna match, resonance or calibrated gain. Finder ranks receive profiles; it does not identify a protocol or decrypt traffic. Sentinel findings are traffic patterns, not proof of malicious intent. WiFi/BLE share the ESP32 radio.

## Validation

CI builds CBD, then Cardputer ADV, then T-Embed, runs host scoring/parser/replay/capture tests, checks image chip ID, source identity and app size, and writes SHA256 manifests. Hardware testing remains outstanding: boot/Launcher return, touch/keyboard/encoder, audio/mic, SD logging, radio switching and repeated tool entry/exit on each actual board.

For a clean checkout: `pio run -e ENV`, then `python scripts/package_native.py --env ENV --output .pio/release`. `ENV` is one of the three names above. The packager rejects dirty or stale builds.
