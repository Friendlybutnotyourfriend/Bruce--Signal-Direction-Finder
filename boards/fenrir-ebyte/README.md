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

This is a **compile-test and receive-only bring-up**. E07 is limited to
425–450.5 MHz. RX_EN and TX_EN are never asserted together. E07 TX is
blocked in the shared RF initialiser, the normal TX menus are hidden, and
no new PA/CW/noise/jammer modes are enabled. The Fenrir RF menu exposes a dedicated 425–450.5 MHz RSSI scanner,
rather than the incompatible 300/868 MHz sweep and Antenna ID tools.
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
