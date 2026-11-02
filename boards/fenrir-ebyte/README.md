# Fenrir Ebyte RF - guarded Bruce board port

Target: **ESP32-2432S028R-PLUS-RF / ZLX-ESP32-4**, 4 MB classic ESP32,
Ebyte **E07-433M20S** CC1101 and **E01-2G4M27SX** nRF24 front ends.

Hardware maps from the board Development Interface Manual v1.0 (2026-08-29):

| Device | SPI SCK/MISO/MOSI | CS | Other |
| --- | --- | --- | --- |
| E07 CC1101 | 18/19/23 | 27 | GDO0 22, GDO2 35, RX_EN 0, TX_EN 4 |
| E01 nRF24 | 18/19/23 | 26 | CE 16 |
| microSD | 18/19/23 | 5 | |
| ST7789 240x320 BGR | 14/12/13 | 15 | DC 2, BL 21, no inversion |
| XPT2046 (software SPI) | 25/39/32 | 33 | IRQ 36 |

E07 operation is limited to 425-450.5 MHz. Normal TX/RX switching from
`agent/mako-alpha1-continuity` is retained, with a 50 us break between
RX_EN and TX_EN. Both controls are released on exit and deep sleep.
The RF menu includes Scan/copy, Record RAW, Custom SubGhz, Radio Control,
a dedicated in-band RSSI scanner, and Antenna ID. Jammer remains hidden.
Antenna ID uses an E07-only 425-450.5 MHz receive survey. It reports
ambient activity, not antenna resonance or a comparison against
315/868/915 MHz. The native ESP32 WiFi/BLE survey remains available.
The qualified ST7789_2 display driver uses SPI mode 0; PN532 CS17 is
held inactive alongside the other shared-bus chip selects.
BLE Hunter, Sniffer, Sessions, capture/review, replay and continuity
use `agent/ble-field-evolution` at 867f7fa3, with the radio branch's
NimBLE extended-advertising build guard retained. Build-time rewriting
of the BLE Hunter source is disabled, matching that BLE branch.
The nRF24 menu exposes spectrum and read-only diagnostics; TX-oriented
menu options are hidden.

The integrated RF settings and CS pins are restored after loading an old
Bruce pin configuration. GPIO0 is not treated as a wake/OK button; the
touch IRQ (GPIO36) is used as deep-sleep wake instead.

Do **not flash** based on CI alone: verify the PCB revision, 4 MB
partition layout, serial recovery, module/chip-select isolation, touch
orientation and E07 amplifier polarity on the bench. Build success
does not prove actual RF power, EIRP, or that all indirect scripting
transmit pathways are inhibited. Preserve working firmware/backups.
