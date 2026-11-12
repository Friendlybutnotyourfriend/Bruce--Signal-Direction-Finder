# Sentinel

Sentinel is a 2.4 GHz listener for awareness and training. It records patterns. It does not send deauthentication frames, advertisement spam, jamming, exploits, or other attacks, and a finding is not an identification of a person.

Open it from **Wi-Fi → Sentinel** or **BLE → Sentinel**. Channel Analyzer (airtime) and Jam Detect (the short-dwell deauth alarm from Bruce 1.16.1, called Rogue Detect in the release notes) stay available. Sentinel adds the patterns below and links those two tools from its own menu.

This build is based on the official Bruce release tag **1.16.1**. It is not built from later `main`. The same image also carries the fork's earlier lab functions: **DF** (BLE Hunter, BLE Sniffer, BLE Sessions), **RF → Antenna ID**, **RF → Radio Control**, **RF → RF Black Box / Finder**, and **NRF24 → Radio Control**. Sentinel itself stays listen-only. Those other menus are the existing lab tools, including their previous transmit profiles and jammer entries.

## What it watches

Wi-Fi, only if the radio accepts monitor mode. The radio hears one channel at a time. The default hops channels 1–11. UP/DOWN locks a channel; SEL returns to hopping. Channels 12–13 are not swept. While hopping, a count is a lower bound.

ESP32-C5 (NM-CYD-C5) can put the radio in monitor mode on 5 GHz, and Bruce's existing sniffer already lists those channels. Sentinel does not sweep them in this build. On that board the watch says so. A quiet 2.4 GHz Sentinel screen does not mean the 5 GHz band was checked.

- **Deauth / disassoc rate** per BSSID, over a one-second window of frames actually received.
- **Beacon flood pattern:** many network names heard once in that second. Names that keep repeating are labelled busy air, not a flood.
- **Same name, different access point** or a different security class. A normal multi-AP network often uses one name on several radios. Open plus encrypted is a sharper pattern and is still not a claim about who is transmitting.
- **Karma-style probe responses:** one access point answering for several network names. The names themselves are not stored. A hidden network answering for its own name is not treated as this pattern.

BLE uses a passive scan (no scan requests, no connection). The NimBLE callback only copies the address, RSSI, and the first 31 advertisement bytes into a queue. A worker scores them. Popup families are evidence of a family, not of a device identity:

- Apple continuity (proximity pair, nearby action, nearby info)
- Fast Pair model-id advertisements
- Swift Pair
- Samsung EasySetup popup shape (Galaxy Buds / Watch style manufacturer data)

Also:

- **New HID-over-GATT** advertisements (service `0x1812`) after a 20 second baseline of BLE listening. Keyboards and BadBLE-style devices look the same. Sentinel does not connect.
- **Unknown tracker behaviour** for Apple Find My (`0x004C` / type `0x12`), Samsung SmartTag (`0xFD5A`), Tile (`0xFEED`), and Google Find My Device Network service data (`0xFE2C`, frame type `0x40`). SEL marks a checkpoint (8 maximum). A tracker-family address heard at two or more checkpoints, or heard continuously for 10 minutes, is the pattern. It may be your own tag. Rotating addresses are often missed.

Wi-Fi and BLE share the radio. **Alternate radios** runs about 8 seconds of Wi-Fi, a gap while the stack changes, then about 6 seconds of BLE. Nothing is heard during the gap. If a mode is refused, Sentinel says so and does not pretend that band is covered.

## On-screen severity

`LISTEN`, `INFO`, `LOW`, `MEDIUM`, `HIGH`. The line under the banner is an explanation of the pattern and the limit. `LISTEN` means nothing is over the threshold. That is not a clean bill of health.

## SD log

When a card is mounted and **SD log** is ON, a session file is created at:

`/Bruce/Sentinel/sentinel_<device-clock>_<millis>.jsonl`

If the clock is not set, the name uses the boot millisecond counter. The file begins with `#` comment lines: schema version, the claim, board (`DEVICE_NAME`), firmware (`BRUCE_VERSION`), git hash, and the field list. Each later line is one JSON object:

| Field | Meaning |
| --- | --- |
| `t_ms` | `millis()` when the pattern was scored |
| `wall` | Clock time when the line was written, or empty |
| `kind` | `deauth`, `beacon_flood`, `evil_twin`, `karma_probe`, `ble_spam`, `hid_gatt`, `tracker`, `note` |
| `severity` | `info`, `low`, `medium`, `high` |
| `summary` | Short pattern name |
| `detail` | Bounded text. No advertisement payload and no probe names |
| `drops` | Frames the queue could not accept. Those frames were not scored |

Caps, also written into the file header: 128 SSID hashes per second, 24 BSSIDs, 8 probe-name hashes per BSSID, 24 BLE addresses per second, 24 HID baseline addresses, 16 trackers, 8 checkpoints, 262144 bytes. At the cap the count stops and the detail or a final note says so. The same pattern is not logged again for 10 seconds (60 seconds at low, 30 seconds at info) unless the severity rises.

## Thresholds

Host-tested in `src/modules/sentinel/sentinel_score.cpp`:

- Deauth frames in one second, channel locked: low 8, medium 25, high 60. While hopping: low 3, medium 8, high 20.
- Beacon names in one second, and at least 70% of them seen once: low 30, medium 60, high 120. Many repeating names are info, not a flood.
- Same SSID on 2+ fresh BSSIDs: low. Known security classes differ: medium. One open and one encrypted: high.
- Karma extras (names that are not the beacon name): low 2, medium 4, high 8. A hidden beacon's own probe name does not count. With no beacon at all, fewer than 3 probe names does not count.
- BLE popup family: info if the rate is high but fewer than 3 addresses. Low/medium/high need both a rate and several addresses.
- New HID addresses in the window: low at 1, medium at 4, after the baseline.
- Tracker checkpoints you marked: medium at 2, high at 3. One checkpoint that stays audible for 10 minutes is low.

## Try it

1. Build and flash a 1.16.1 board image that is not `LITE_VERSION` (the Cardputer target is one).
2. Wi-Fi → Sentinel → What Sentinel claims, and read the limits.
3. Wi-Fi patterns, or BLE patterns. ESC leaves the watch and returns to the Sentinel menu.
4. Optional: put the card in, leave SD log ON, then read `/Bruce/Sentinel/` on a computer.

Jam Detect still extrapolates a short dwell and is the fast alarm. Sentinel's deauth number is the count in a one-second window on the channel the radio was actually tuned to.

## Tests

The scoring, frame classification, and log lines do not need the ESP32 SDK:

```sh
g++ -std=c++11 -Wall -Wextra -Werror -I src/modules/sentinel \
  test/sentinel/test_sentinel_score.cpp src/modules/sentinel/sentinel_score.cpp \
  -o /tmp/sentinel_score_test && /tmp/sentinel_score_test
```

Verified firmware targets, both official 1.16.1 envs and not lite builds:

- `pio run -e m5stack-cardputer` — M5Stack Cardputer. This env is what the Cardputer ADV uses. There is no separate ADV env. At boot it probes the TCA8418 keyboard on Wire1 SDA 8 / SCL 9 and, when that controller is present, uses the ADV keyboard and ES8311 path. The original Cardputer is not a separate target here.
- `pio run -e nm-cyd-c5` — NM-CYD-C5 (ESP32-C5).

Sentinel is omitted from `LITE_VERSION` builds, same as Channel Analyzer and Jam Detect.

Flash the merged images the build writes at the project root, at offset `0x0`:

```sh
pio run -e m5stack-cardputer -t upload
pio run -e nm-cyd-c5 -t upload
```

Or, with the image already built: `esptool --chip esp32s3 write-flash 0x0 Bruce-m5stack-cardputer.bin` and `esptool --chip esp32c5 write-flash 0x0 Bruce-nm-cyd-c5.bin`. The C5 bootloader sits at `0x2000` inside that merged file.

`fastled/FastLED` is pinned to 3.10.3 in `platformio.ini`. The original `^3.10.3` range now installs 3.10.9, and 3.10.5 and later use the name `FP`, which Bruce's `-DFP` font-size macro rewrites, so those releases do not compile. 3.10.3 is the newest published version in the original range that does not do that. No Bruce source commit after tag 1.16.1 is included.
