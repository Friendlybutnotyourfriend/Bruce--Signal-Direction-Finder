# HUGINN — ES3C28P audio field build (development)

Source: `agent/huginn-cbd-audio`, based on `agent/ble-field-evolution`.
Target: **ES3C28P / 2.8-inch Cheap Black Display** with its ES8311 codec,
FM8002E amplifier and compatible passive two-wire speaker.

## What is implemented

- **BLE Hunter > Actions > Audio on/off**: non-blocking, filtered RSSI
  pulses (stronger means faster and higher), lost/reacquired cues,
  address-handoff and uncertain-association warnings. Unstable, stale
  or unconfirmed observations cannot trigger proximity pulses.
- **BLE Sniffer > Audio alerts on/off**: selected-target loss,
  reacquisition and address handoff; rate-limited field-change chirps.
- **Hunter > Speaker test chirp**: verifies the existing I2S codec path
  independently of BLE signal quality (global Bruce sound must be on).
- **Hunter and Sniffer > Record 5s voice note** (ES8311 only):
  scanning is paused, the existing microphone recorder saves a WAV to
  `/BruceRecon/voice-<uptime-ms>.wav` and an SD session records a
  `voice_note` event containing the filename. Microphone and speaker
  do not operate at the same time.
- **Hunter/Sniffer > Backlight off (tap to wake)** (ES3C28P only):
  leaves BLE scanning and the low-priority audio worker running.
  Backlight is restored on a touch/button event or when exiting a mode.
  This does **not** suspend the TFT controller or create a new power
  management mode.
- A dedicated FreeRTOS audio worker keeps blocking I2S tone generation
  off the NimBLE callback and UI paths. Queues are bounded; proximity
  chirps can be dropped rather than delaying scan/capture tasks.

## Deliberate limitations

- Physical speaker playback, ES8311 register configuration, volume,
  the amplifier gate, microphone input, and screen wakeup **require
  on-device verification**. A successful compile does not verify sound.
- RSSI gives a **relative trend**, not range or bearing.
- Address handoff sounds reflect an evidence-backed *hypothesis*,
  **not** proof of device identity.
- Audio follows the global Bruce sound enable and volume controls;
  Hunter/Sniffer audio starts **off** for each session.
- Mic annotations are voluntary, capped at five seconds each, locally
  saved, and skipped on recording failure; voice recording pauses BLE
  scanning.
- There is **no separate Sentinel monitor mode**, speech recognition,
  location triangulation, or BLE connection-channel capture in this
  release. These are separate milestones.
- Existing BLE Sniffer, Hunter continuity logic, session storage,
  Antenna ID and unrelated features are intentionally unchanged.

## Hardware acceptance sequence

1. Power down CBD; connect the included passive speaker to its own
   marked 2-pin speaker connector, **not directly to an ESP32 GPIO**.
2. Boot the build through Launcher; enable sound and a low volume in
   Bruce settings; use **BLE Hunter > Speaker test chirp**. Listen for
   clicks, distortion, lack of sound and mute/volume behaviour.
3. Target a BLE peripheral. Confirm chirps track *filtered* RSSI, not
   packet-by-packet noise. Walk away, return, and verify loss/reacquisition.
4. Confirm audio OFF produces no tone; verify SD logging and scanning
   are uninterrupted by audio.
5. In Hunter/Sniffer toggle **Backlight off**, tap to wake and verify
   correct brightness restoration. Check that scan history continues.
6. Insert an SD card; record a voice note in Hunter. Confirm a WAV file
   and session `voice_note` event, and verify recording works with the
   speaker disabled.
7. Run at least 30 minutes of crowded BLE scanning plus audio. Check
   heap fragmentation, scan restarts, SD loss/full-card handling and
   battery consumption against the non-audio build.

## Firmware build

CI workflow: `.github/workflows/huginn_cbd_audio.yml`

Runs host regression tests and builds PlatformIO `ES3C28P`.
Successful CI uploads `HUGINN-ES3C28P-Audio-Launcher.bin`, containing
the partition table at `0x8000` and application at `0x10000`, **no
bootloader**. This is intended for an existing compatible Launcher
install, not a bare-device initial flash.

**Status:** Implementation committed; hardware acceptance outstanding.
Do not label the release stable before the tests above pass.
