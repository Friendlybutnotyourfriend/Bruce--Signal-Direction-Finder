# HUGINN

## Built on Bruce

**HUGINN is a development fork of [Bruce firmware](https://github.com/BruceDevices/firmware).** Bruce's developers and contributors deserve the credit for the firmware foundation, hardware support and existing toolset. This project adds focused BLE reconnaissance and field-review workflows to their work; it is independently maintained, not an official Bruce release.

Upstream credits remain intact. Distributed under [AGPLv3](./LICENSE).

## What is HUGINN?

Previously called Mako DF, HUGINN focuses on inspecting BLE advertisements, following changes in signal strength and reviewing the evidence afterwards.

The name comes from Huginn, one of Odin's two ravens, whose name means “thought.” A raven gathering information and returning with observations fits the reconnaissance role: collect, examine and report, without pretending every observation is a certainty.

## Modules and results

HUGINN brings together four practical tools:

- **BLE Hunter:** target selection, filtered RSSI history, checkpoints and warmer/colder feedback, with optional audio.
- **BLE Sniffer:** decoded advertisement fields and raw-byte changes, with cautious address-association hypotheses, address lock and undo.
- **BLE Sessions:** SD-card recording, visible capture-loss indicators, on-device review and desktop reporting, replay and comparison.
- **Antenna comparisons:** controlled reference–candidate–reference receive tests, saved profiles and imported VNA measurements.

Together, these tools turn live observations into records you can revisit and compare, rather than relying on a single signal-strength reading. HUGINN remains experimental; hardware acceptance testing is still outstanding.

RSSI does not establish exact bearing or distance, association does not prove device identity, and antenna comparisons measure relative response rather than absolute gain.

## Supported devices

- **LilyGO T-Embed CC1101 Plus:** current development build target.
- **NM-CYD-C5 and ES3C28P:** earlier BLE Recon builds only; the complete feature set above is not yet verified on these boards.

These are build targets, not hardware-validated support claims. Confirm your exact board revision; compatibility with other Bruce devices is not assumed.

## Installation — T-Embed CC1101 Plus

1. Back up existing data. If needed, install the correct device version of [bmorcelli Launcher](https://github.com/bmorcelli/Launcher#how-to-install).
2. From the [Field Evolution builds](https://github.com/Friendlybutnotyourfriend/Bruce--Signal-Direction-Finder/actions/workflows/field_evolution.yml), choose a successful run for `agent/ble-field-evolution`, download the `Field-Evolution-lilygo-t-embed-cc1101` artifact and extract `Launcher-T-Embed-CC1101-Plus.bin`. GitHub sign-in may be required. If the artifact has expired, obtain a fresh build using the [build workflow](https://github.com/Friendlybutnotyourfriend/Bruce--Signal-Direction-Finder/blob/agent/ble-field-evolution/.github/workflows/field_evolution.yml).
3. Copy the `.bin` to your SD card, start Launcher by pressing **Sel** on its startup screen, then select the file through **SD** and install it. Restart and check the display, controls and BLE tools before relying on them.

**This is a Launcher-only image, not a full USB-flash image: it contains no bootloader. Do not flash it directly at address zero.** Keep an SD card inserted for session recording.

## Where next

The priority is reliable field behaviour, backed by repeatable testing. **ODIN** is the working name for a future broader RF-security suite, with HUGINN as its reconnaissance component.

Use only for your own devices or authorised work, protect captured data and preserve the credit owed to Bruce and its contributors.
