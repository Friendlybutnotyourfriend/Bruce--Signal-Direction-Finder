# Fenrir Ebyte RF - Bruce board port

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
| Battery ADC | GPIO34 | | 100k/100k divider, voltage multiplier 2 |

E07 operation is limited to 425-450.5 MHz. Normal TX/RX switching from
`agent/mako-alpha1-continuity` is retained, with a 50 us break between
RX_EN and TX_EN. Both controls are released on exit and deep sleep.
The RF menu includes Scan/copy, Record RAW, Custom SubGhz, Radio Control,
a dedicated in-band RSSI scanner, Antenna ID, Bruteforce and Jammer.
Frequency selection and sweep endpoints stay within the E07 band;
retuning restores the previous TX or RX state after entering idle.
Antenna ID uses an E07-only 425-450.5 MHz receive survey. It reports
ambient activity, not antenna resonance or a comparison against
315/868/915 MHz. The native ESP32 WiFi/BLE survey remains available.
The qualified ST7789_2 display driver uses SPI mode 0; PN532 CS17 is
held inactive alongside the other shared-bus chip selects.
BLE Hunter, Sniffer, Sessions, capture/review, replay and continuity
use `agent/ble-field-evolution` at 867f7fa3, with the radio branch's
NimBLE extended-advertising build guard retained. Build-time rewriting
of the BLE Hunter source is disabled, matching that BLE branch.
The nRF24 menu exposes spectrum, diagnostics, MouseJack and NRF Jammer.
Radio Control enables adjustable nRF24 PA, rate and channel profiles.

Battery status uses 16 calibrated ADC samples on GPIO34 with 11 dB
attenuation and the manufacturer's 100k/100k divider. The displayed
percentage estimates 3.3-4.2 V cell voltage; it is not a fuel gauge or
charging-state indication. A depleted cell still displays 1% instead
of losing the icon. Confirm calibration against a meter if accuracy matters.
Hardware source: [manufacturer examples](https://github.com/qmaakdfq/ESP32-Multi-Protocol-Wireless-Development-Board).

The integrated RF settings and CS pins are restored after loading an old
Bruce pin configuration. GPIO0 is not treated as a wake/OK button; the
touch IRQ (GPIO36) is used as deep-sleep wake instead.

This target uses `custom_4Mb_full.csv`: app at 0x10000, size 0x3C0000;
NVS at 0x9000 and LittleFS at 0x3D0000. When this layout is already
installed, back up flash and write only `firmware.bin` at 0x10000 to
preserve settings and files. The merged `Bruce-fenrir-ebyte.bin` starts
at 0x0 and includes padding across the NVS region; it is for a full
installation, not a data-preserving app update. There is no second OTA slot.
Boot, touch, SD and Antenna ID have been checked on the connected unit.
Transmitter output power and battery calibration still require bench measurements.
