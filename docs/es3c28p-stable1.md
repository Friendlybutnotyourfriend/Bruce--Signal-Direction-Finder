# ES3C28P stabilisation 1 — bench candidate

Target: LCDWiki ES3C28P capacitive 2.8-inch ESP32-S3 display.
Based on Sentinel branch f33d1cccd097785f93fa105cd12debce592236d1 / Bruce 1.16.1.
This release has NOT been tested on a physical board. No flash was performed remotely.

## Install through Launcher

1. Keep your previous working image on the SD card for rollback.
2. Copy `Bruce-ES3C28P-stable1-Launcher.bin` onto the SD card.
3. In bmorcelli Launcher, select this file and install it.
4. Config > About shows version `1.16.1-cbd-stable1`, board and source commit.

The supplied binary is app-only. Do not flash it at address 0x0 with esptool.
The size check uses Bruce's 4,653,056-byte factory app slot. Launcher's actual
destination slot must also be large enough; this package does not change its partitions.

## Changes

- Embed source revision in About and Sentinel/BLE recon/RF Lab logs.
- Show minimum free heap, largest allocation and task stack headroom in About.
- Reject CBD radio configurations with overlapping/unassigned SPI/control pins.
- RMT capture uses a 3 us input glitch filter and matching 128-symbol hardware
  and software capacity. Full captures are excluded and counted as clipped.
  Pulse histogram still excludes durations below 20 us; this is separate from
  the hardware filter. Classic ESP32 consumes two 64-symbol memory blocks.
- RF Lab verifies frequency register readback, records nominal programmed base
  frequency, and saves modem register bytes with Finder candidates.
- Finder candidate detail shows the two passes' segment counts and clipping.
- Antenna comparison checks the board's supported band and frequency readback.
- Ambient survey wording describes RF activity, not antenna resonance or gain.
- Sentinel deauth rates use receiver-enabled time on each channel. A window
  below 100 ms is informational only. Normalized rates use locked-channel
  thresholds, not the former reduced hopping thresholds.
- Sentinel shows channel/BLE enabled time and writes a final coverage record;
  stack-switch time is excluded. These are receiver-enabled times, not a claim
  of continuous packet reception. BLE scan gaps and queue losses still apply.
- Same-SSID APs with matching security are informational; differing security
  remains a pattern alert, not proof of an evil twin.
- Repeated-address popup traffic is explicitly ambiguous, not declared benign.
- SD short writes stop Sentinel logging and display an error. Its 256 KiB cap
  is also visible. Wi-Fi tag parsing no longer cuts management frames at 512 bytes.

## External radio wiring: extra control pin required

The former defaults put CC1101 GDO0 on MISO and NRF24 CE on MOSI.
Both now default to unassigned. Existing saved conflicting configurations are
also rejected. Internal Wi-Fi/BLE and ordinary display operation need no change.

Proposed pin map for ONE SPI radio (bench verification still required):

| Radio signal | CBD header GPIO |
|---|---|
| SCK | Expand IO14 |
| MISO | Expand IO2 |
| MOSI | Expand IO3 |
| CS / CSN | Expand IO21 |
| CC1101 GDO0 OR NRF24 CE | UART TX / IO43, only when UART/GPS is unused |

Configure that control pin in Bruce's SPI pin settings after wiring it.
GPIO43 is a proposed spare digital pin, not an automatically applied remap.
Do not share it with a connected UART accessory. These checks validate distinct
pins within a radio; they cannot detect external wiring or every cross-peripheral conflict.
Expand contains no power. Supply voltage must match the exact radio module:
do NOT put the UART 5V rail directly onto a 3.3V-only CC1101/nRF24 module.
Default IR pins also overlap this SPI bus; disconnect that accessory before use.

## Acceptance checks on your board

1. Cold boot and Launcher return; verify version/source in About.
2. Touch each menu edge, back/escape and Config; check no text overlap.
3. Play a known sound through the speaker and confirm volume control.
4. Run BLE Hunter, Sentinel Wi-Fi, Sentinel BLE and antenna survey; switch
   between them at least 20 times. Compare About memory readings after warm-up.
   A continuing fall, crash or failed radio restart needs investigation.
5. Log to SD; confirm header identity, events and final coverage record. Test
   without a card and on a spare nearly full card; look for a clear error.
6. Leave Sentinel running for 30 minutes in ordinary home traffic. Confirm
   same-security mesh/AP names remain informational; save any unexpected alerts.
7. With an appropriately wired CC1101 and a repeatable known source, run Finder.
   Confirm both passes collect segments; deliberately long frames should show
   clipping, and no source should not produce an identification claim.
8. Test USB and battery power separately. Voltage rails, radio sensitivity,
   audio and actual antenna performance have not been measured by this build.

## Build and evidence

`pio run -e ES3C28P` then `python scripts/package_cbd.py --output /path/to/output`
requires a clean Git checkout. The packager checks chip ID, embedded commit and
actual app slot size, and records resolved library versions/commits and SHA256.
Keep the full PlatformIO build log alongside the manifest for toolchain versions.
Dependencies inherited from upstream still include floating references; the
manifest records what was used, not a guarantee of byte-identical future builds.

Host tests cover scoring/parsing, recon logic, RF Lab logic, pin conflicts,
capture boundaries, listening-time accounting and millis wrap. They do not
substitute for hardware timing, RF, audio, touchscreen or SD acceptance tests.
Sentinel remains listen-only. No transmit or attack functionality was added.
