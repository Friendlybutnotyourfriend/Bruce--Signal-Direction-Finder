<div align="center">

# 🦈 MAKO DF

### Every signal leaves a wake.

**A lean, purpose-built signal direction-finding fork of Bruce firmware.**

</div>

---

> [!NOTE]
> **Mako DF is under active development.** Features, hardware support and performance may change as field testing progresses.

## What is Mako DF?

**Mako DF** is a lean, purpose-built fork of Bruce firmware that transforms supported ESP32 devices into compact counter-surveillance and signal direction-finding tools.

Built to cut through crowded spectrum, Mako DF helps you detect, isolate and home in on Wi-Fi and BLE transmitters using live signal-strength intelligence and a directional antenna. From persistent access points to the faint, intermittent advertisements broadcast by AirTags and other tracking devices, Mako turns a drop of RF in an ocean of noise into a trail you can follow.

Named after one of the fastest and most efficient predators in the ocean, Mako DF follows the same philosophy: fast, agile and relentlessly focused. No unnecessary weight. No wasted movement. Just the tools required to acquire a signal, lock onto its direction and run it back to the source.

> **Detect the signal. Follow the wake. Find the source.**

---

## Current Capabilities

Mako DF is currently focused on practical, single-device direction finding using one external directional antenna.

Current development covers:

- Wi-Fi signal detection and targeting
- BLE advertiser detection and tracking
- Tracking of AirTags and similar BLE devices
- Live RSSI signal-strength monitoring
- Directional hot-and-cold feedback
- Target isolation within crowded RF environments
- Single-antenna, human-guided direction finding
- External directional antenna support

Mako DF does not perform phase-based Angle of Arrival, Time Difference of Arrival or other laboratory-grade direction-finding methods. It uses real-time signal-strength changes and directional antenna movement to guide the operator toward a signal source.

---

## Supported Hardware

Mako DF is currently optimised for:

- **LilyGO T-Embed CC1101**
- **LilyGO T-Embed CC1101 Plus**

Support for additional Bruce-compatible ESP32 devices is planned as development and hardware testing continue.

An external directional antenna is strongly recommended. The quality, gain and radiation pattern of the antenna will directly affect direction-finding performance.

---

## Development Direction

Mako DF is intentionally being developed as a lean, single-device tool before more complex systems are introduced.

Current priorities include:

- Reliable and responsive RSSI monitoring
- Improved signal filtering and smoothing
- Better target selection and isolation
- Clear visual and audible directional feedback
- Stable BLE advertiser tracking
- Reliable operation across supported hardware
- Reduced background noise and false directional changes

Planned development includes:

- Additional supported ESP32 devices
- Sub-GHz signal direction finding
- Improved tracking of intermittent transmitters
- Expanded visualisation and proximity feedback
- Field-tested antenna profiles
- Logging and export of direction-finding sessions

The future distributed multi-node tracking platform is being developed separately under the working name **Project Kraken**. Mako DF will remain focused on fast, portable and practical single-device direction finding.

---

## Installation

Detailed build, flashing and configuration instructions are currently being prepared.

Until official Mako DF binaries are released, the firmware must be compiled from source using PlatformIO and the correct build environment for the target device.

> [!CAUTION]
> Mako DF is a development fork. Do not assume that untested builds are stable or suitable for operational use.

---

## How Direction Finding Works

Mako DF does not magically calculate the exact location of a transmitter.

Instead, it measures changes in received signal strength while the operator moves or rotates a directional antenna. As the antenna points toward the target—or the operator moves closer—the received signal will generally become stronger.

Environmental factors can distort these readings, including:

- Walls and buildings
- Vehicles and machinery
- Metal structures
- Reflections and multipath interference
- Antenna orientation
- Transmitter power changes
- Human bodies and other obstructions

For the most reliable results, take multiple readings, approach from more than one direction and avoid treating a single RSSI spike as a confirmed bearing.

---

## Intended Use

Mako DF is intended for:

- Locating your own lost wireless devices
- Detecting unwanted tracking devices
- Authorised counter-surveillance work
- RF surveying and experimentation
- Educational research
- Legal and authorised security testing

Do not use Mako DF to track people, monitor devices without authority or interfere with communications.

You are responsible for complying with all applicable laws and regulations in your jurisdiction.

---

## Upstream Project and Licence

Mako DF is a modified fork of the open-source [Bruce firmware project](https://bruce.computer/).

The original Bruce firmware and its contributors retain copyright in the upstream work. Mako DF contains modifications developed beginning in 2026 to provide specialised signal direction-finding capabilities.

Mako DF is independently maintained and is **not an official Bruce firmware release**.

This project is distributed under the **GNU Affero General Public License Version 3 (AGPLv3)**. See the [`LICENSE`](./LICENSE) file for the complete licence terms.

Source-level copyright, attribution, warranty and licence notices from the upstream project must remain intact.

---

## Disclaimer

This software is provided without warranty.

Radio-frequency conditions are unpredictable, and RSSI-based direction finding cannot guarantee an exact bearing, distance or location. Results must be interpreted by the operator and confirmed through repeated observations.

The developers and contributors accept no liability for misuse, unlawful activity, equipment damage or decisions made using information produced by this software.

---

<div align="center">

### MAKO DF

**Every signal leaves a wake.**

</div>