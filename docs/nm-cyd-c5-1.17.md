# Bruce 1.17 native tools for NM-CYD-C5

Target: `nm-cyd-c5`, ESP32-C5, 8 MB flash, ST7789 display and XPT2046 resistive touch.
Base: official Bruce 1.17 (`2b6ba4d490bfcf94ce2574c6154537dbd5838c3d`),
with custom tools and shared stability fixes through `89be7e700e8c6bbdeb56291fec0aea136bc20af1`.
The manifest records the exact build commit and SHA256.

## Install with Launcher

1. Copy `Bruce-1.17-native1-NM-CYD-C5-Launcher.bin` to the SD card.
2. In Launcher, open SD, select the file, then Install.
3. Start Bruce. If needed, run touch calibration from Config.

This is an application-only image. Keep Launcher installed; do not flash this file
at USB address zero. Launcher needs an application slot at least as large as the
file. The build checks the 0x4E0000-byte (5,111,808-byte) standalone app limit;
the installed Launcher's partition layout must also fit it.

## Included

- BLE Hunter/Sniffer v3, FE9F/FCF1 analysis, BLE session recording and review.
- Wi-Fi/BLE Sentinel, with receive-only detection and logging.
- Sub-GHz and 2.4 GHz Antenna ID surveys and antenna comparison.
- Radio Control, CC1101 RF Black Box and Receive Profile Finder.
- Passive nRF24 2.4 GHz Black Box.
- Shared BLE lifecycle, lazy allocation and radio-workspace cleanup fixes.
- C5 BLE compatibility: the pinned NimBLE dispatch table matches the bundled
  SDK; the two NFC BLE adapters have distinct callback classes and the
  Chameleon adapter uses NimBLE 2's const callback signature.

Upstream C5 functions, screen/touch support and default pins are retained.
The Fenrir-only feature exclusions and E07 frequency restriction do not apply.
Audio and voice recording depend on supported audio hardware; this target does
not declare a speaker or microphone. These controls remain hardware-gated.

The C5 display, touch, SD and external radios share SPI (SCK6/MISO2/MOSI7).
Default external radio CS is GPIO9 and GDO0/CE is GPIO8. CC1101 and nRF24
cannot both use those same control pins simultaneously. Existing saved radio
settings are retained; check Config if using a custom wired RF board.

Sentinel's custom Wi-Fi sweep remains 2.4 GHz, even though the C5 supports
dual-band Wi-Fi. Antenna surveys and Black Boxes measure received activity;
they do not measure antenna matching or record IQ. Finder ranks receive settings.

## Build and validation

From a clean checkout:

```
pio run -e nm-cyd-c5
python scripts/package_native.py --env nm-cyd-c5 --output .pio/release
```

Packaging rejects stale or dirty builds, wrong-chip images, missing source
identity and images exceeding the configured app partition. Hardware acceptance
still requires boot, touch, SD logging and repeated radio-tool entry/exit on the
physical board; a successful build does not establish these checks.
