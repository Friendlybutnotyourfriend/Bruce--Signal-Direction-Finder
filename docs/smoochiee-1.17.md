# Bruce 1.17 custom build for Smoochiee / Flux

Target: `smoochiee-board`, ESP32-S3 with 16 MB flash and 8 MB OPI PSRAM.
Base: official Bruce 1.17 (`2b6ba4d490bfcf94ce2574c6154537dbd5838c3d`).
Custom source carried forward from `92d127f0`, including the latest BLE lifecycle,
bounded session-memory and idle-workspace fixes. The Smoochie pinout and hardware
support remain upstream defaults. Fenrir's feature exclusions are not enabled.
The Smoochie build also isolates the two NFC libraries' BLE scan callback names
and corrects the Chameleon callback signature for the pinned NimBLE version.

## Included tools

- BLE Hunter, Sniffer, sessions/review and FE9F/FCF1 analysis.
- Antenna ID, sub-GHz/2.4 GHz surveys and A/B/A antenna comparison.
- Radio Control for CC1101 and nRF24.
- CC1101 RF Black Box and Receive Profile Finder.
- nRF24 2.4 GHz Black Box.
- Wi-Fi/BLE Sentinel and the standard Bruce 1.17 features, including IR and Config.

## Install

If Launcher is already installed, copy `Bruce-1.17-native1-Smoochiee-Flux-Launcher.bin`
to the SD card and install it through Launcher. This is an application-only image;
do not flash it at address zero. Launcher must provide an application slot at least
as large as the image; the manifest records the exact required size.

For a complete USB installation, use `Bruce-1.17-native1-Smoochiee-Flux-Full-USB.bin`
at offset `0x0` with an ESP32-S3 flasher. This replaces the bootloader and partition
table, including an existing Launcher. The original Smoochie layout is retained:
app at `0x10000`, app size `0x470000`, filesystem at `0x480000`. Back up important
internal files before a full USB installation and do not select erase-all unless
you intend to reset all internal data. The SD card is not part of this image.

In Config/device information, check version `1.17-native1` and the source revision
listed in the manifest. Settings loaded from an old Bruce config can override board
defaults; do not reuse another board's pin configuration.

## Board defaults

| Device | Pins |
|---|---|
| Radio SPI | SCK 13, MISO 11, MOSI 12 |
| CC1101 | CS 46, GDO0 9, GDO2 10 |
| nRF24 | CS 14, CE 21 |
| SD | SCK 18, MISO 8, MOSI 17, CS 3 |
| IR | TX 5, RX 4 |

CC1101 and nRF24 share SPI. GPIO 10 is also the microphone data pin; do not use
the microphone and CC1101 concurrently. Antenna surveys measure received activity,
not calibrated antenna resonance or gain. Receive Profile Finder ranks receive
settings; it does not identify or decrypt a protocol. nRF Black Box records channel
activity, not decoded packets or device identity.

## Verification and build

The release manifest records source identity, chip ID, image size and SHA256.
Compilation and image checks do not establish hardware operation: boot, display,
buttons, SD logging, both radios and repeated BLE entry/exit still require testing
on the physical board.

Build: `pio run -e smoochiee-board`.
Package: `python scripts/package_native.py --env smoochiee-board --output .pio/release`.
