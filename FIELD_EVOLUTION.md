# Bruce Field Evolution 1

Target: LilyGO T-Embed CC1101, installed through the existing bmorcelli Launcher.

## Using the features

- **Direction Finding > BLE Hunter**: select a target, then Select opens checkpoints, audio, bookmarks, address lock, undo, and recording controls. Audio also respects the global sound setting. The chart shows recent received signal levels; warmer/colder reflects filtered RSSI, not distance or bearing. A jitter warning suppresses audio.
- **Direction Finding > BLE Sniffer** and **Bluetooth > BLE Sniffer** use the same implementation and association engine. AD views include a decoded field-change count; RAW/MUTATION preserve byte offsets. The signature preview is bounded to 16 fields and the first 24 bytes of each field; desktop reports compare full captured fields.
- **BLE Sessions** replays saved observations with the current association engine, summarizes recordings, and compares two recorded target streams. Radios are stopped during review. Select steps; turning toggles autoplay. Replay starts at the first recorded report for the selected address; discoveries before recording are not reconstructed. Recorded and recomputed decisions can differ when earlier history is unavailable.
- **RF > Antenna ID > A/B/A CC1101** measures a fixed frequency using reference, candidate, then reference again. **A/B/A ESP32 BLE** uses one address-locked beacon on the ESP32 antenna path; it pools advertising channels, and cannot report per-channel gain. Keep the source, power, cable, position and orientation fixed. The profile reports median relative dB, reference drift and an empirical spread bound. Low levels, overload, drift over 3 dB, or sample spread over 4 dB produce an inconclusive result. These are controlled receive comparisons, not absolute antenna gain or resonance measurements.
- **Saved profiles / VNA** plots saved relative response by frequency, or imported S11 return loss and VSWR. Up to 128 points are shown; extra/invalid rows are visibly reported. BLE samples plot by measurement sequence. Profile filenames separate CC1101 and ESP32 BLE paths.

## Recording and offline review

Recording starts when entering Hunter or Sniffer if an SD card is available; the status line shows whether it is active. Files never overwrite an existing session. Captures go to `/BruceRecon/session-N.jsonl`. Antenna profiles go to `/AntennaProfiles/NAME-cc1101.csv` or `NAME-esp32-ble.csv`.

BLE callbacks enqueue records; only the UI task writes the SD card. The bounded queue holds 32 reports. Overflow, payload truncation and SD write errors are surfaced; a missing footer means the capture is incomplete. Main menus pause scanning and record pause/resume events, so those gaps are not treated as evidence of address rotation. Active scanning remains an explicit action and is recorded separately. Stored data includes nearby advertisements needed to explain competing hypotheses; captures contain device addresses and advertised payloads.

Timestamps are monotonic microseconds since boot, not UTC. Millisecond timestamps wrap at 49.7 days; engine age arithmetic handles that wrap. Raw capture is limited to 256 payload bytes/report. Scan response and advertising boundaries are recorded. This inspects advertising reports delivered by the BLE stack; it is not an over-the-air connection-channel sniffer.

Desktop review is bounded to 200,000 records and 5,000 detailed changes per invocation; limits are reported visibly. Split longer recordings for complete review.

Desktop commands (Python 3 standard library):

```text
python tools/recon_session.py report session-1.jsonl --html review.html
python tools/recon_session.py compare session-1.jsonl session-2.jsonl --left-address aa:bb:cc:dd:ee:ff --right-address 11:22:33:44:55:66
c++ -std=c++17 -O2 tools/recon_replay.cpp -o recon-replay
python tools/recon_session.py replay session-1.jsonl --engine ./recon-replay
python tools/recon_session.py vna antenna.s1p antenna-vna.csv --calibration-note "SOL calibrated at cable end; describe fixture and date"
```

The VNA importer accepts Touchstone 1.x S1P in RI/MA/DB formats, or CSV with `frequency_mhz`/`frequency_hz` and positive `return_loss_db` or `vswr`. If both columns exist they must agree within 2%. It rejects malformed, nonfinite and nonpassive measurements. Calibration provenance is saved in a companion metadata file; software cannot verify physical calibration. Copy the resulting CSV into `/AntennaProfiles`. Exact zero S11 produces infinite return loss, which the bounded on-device plot omits as a nonfinite point; it remains in the exported CSV.

## Association behavior

Decoded fields and UUIDs are normalized before comparison. Up to four observed layouts are retained, allowing alternating advertising formats. Byte positions that change in a layout stop contributing stable evidence. Empty payloads, UUID-only and name-only matches, malformed/truncated signatures and scan responses cannot elect a new target. Address type participates in matching.

The loss window adapts to packet cadence (3–45 seconds). Automatic changes remain disabled until a repeat report from the selected target establishes a cadence. A change needs at least three observations separated by 100 ms, at least 600 ms of evidence, a score of 85/100 and a 10-point lead over rivals. A crowded candidate table abstains. Scores express heuristic evidence, not identity probabilities. Identical broadcasts remain fundamentally indistinguishable. Automatically associated targets remain hypotheses, and the original model is preserved to prevent chained model drift. Undo restores the previous address and locks it until explicitly unlocked.

## Extended advertising milestone

The production configuration keeps the existing legacy BLE stack. The source has guarded metadata and 1M+Coded scan support. `lab/extended_scan` is a separate receive-only ESP32-S3 stack probe, compiled with `CONFIG_BT_NIMBLE_EXT_ADV=1` across all translation units. It reports scan-start failure and received SID, PHY, data status and length on USB serial. The CI artifact is an ELF for investigation, not a Launcher firmware release.

NimBLE-Arduino 2.5.1 removes the legacy `NimBLEAdvertising` API when extended advertising is enabled. Bruce has several existing users of that API, including the BLE keyboard and service stack. Enabling the flag in the main build before migrating those callers would break those features. The isolated probe establishes compile compatibility; controller acceptance, extended-only reception and Coded PHY reception still require physical tests. No AoA/AoD or channel-sounding capability is claimed.

Primary references: [NimBLE configuration](https://github.com/h2zero/NimBLE-Arduino/blob/2.5.1/src/nimconfig.h), [scan API](https://github.com/h2zero/NimBLE-Arduino/blob/2.5.1/src/NimBLEScan.h), [advertising API guard](https://github.com/h2zero/NimBLE-Arduino/blob/2.5.1/src/NimBLEAdvertising.h).

## Validation

The host C++ tests exercise field reordering, changing payloads, duplicate bursts, competing lookalikes, sparse cadence, address types, timer wrap, undo, scan pauses, malformed/truncated payloads and antenna drift. CI runs address/undefined-behavior sanitizers, including 20,000 deterministic malformed-payload trials. Python tests cover session loss/partial writes, decoded vs raw changes, HTML escaping, VNA formats, units and consistency.

Hardware acceptance remains necessary: boot through Launcher, verify controls and audio on the T-Embed display, run crowded/slow-beacon sessions and replay them, check SD removal/full-card behavior, and compare a known antenna fixture before relying on measurements. Test the isolated extended scanner with a known extended-only and Coded-PHY advertiser before undertaking main-stack migration.
