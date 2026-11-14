# Radio Control Centre v1 — supported board bring-up

This source branch adds **opt-in** CC1101 and nRF24 settings (PA register,
modulation/data rate/channel where applicable), restore-defaults and SPI
diagnostics. The default remains **OFF**, preserving Bruce's pre-existing
behaviour. PA register values are **not** calibrated radiated EIRP.

## PlatformIO / hardware matrix

| Board | Environment | CC1101 | nRF24 | Hardware caveat |
| --- | --- | --- | --- | --- |
| Smoochiee/Flux S3 | `smoochiee-board` | On-board | On-board | Shared SPI; different chip-select lines. |
| LilyGO T-Embed CC1101 Plus | `lilygo-t-embed-cc1101` | Native, CS12 / GDO0 3 | CE43 / CS44 as configured | Shares TFT/SD SPI. Verify specific Plus board revision and integrated nRF24 wiring before using TX. |
| M5Stack Cardputer ADV | `m5stack-cardputer` | **External** only | **External** only | SD/Grove SPI mapping; only connect/select one module per shared CS wiring arrangement. |
| NM-CYD-C5 + NM RF-HAT | `nm-cyd-c5` | External CS9 / GDO0 8 | External CS9 / CE8 | **Same CS and signal pin**. Physical module selector required; never treat them as simultaneously addressable. |
| Fenrir ZLX ESP32-2432S028R-PLUS-RF | `fenrir-ebyte` | Ebyte E07, dedicated CS27 / GDO0 22 | Ebyte E01, CS26 / CE16 | **RX-only bring-up**: 4 MB, no PSRAM; E07 PA and TX locked pending bench qualification. |

The Fenrir board is its own PlatformIO environment and keeps the
ST7789 240×320 BGR display without inversion, separate XPT2046 touch
software SPI, independent radio chip selects and gated E07 receive
amplifier. The E07 allowed tuning window is **425–450.5 MHz**; both
antenna front-end enable pins are kept mutually exclusive. It is **not**
interchangeable with standard ILI9341 CYD firmware. GPIO0 drives the
E07 receive amplifier after boot; it is not assigned to an OK button
or wake input.

## Verification before flashing any board

1. Obtain a successful **board-specific** CI build, not merely the
   successful Smoochiee reference build; inspect compiler output and
   partition/memory size.
2. Back up the current firmware, partitions, NVS and filesystem.
   Preserve bootloader, USB recovery route and existing Launcher layout.
3. On the physical board, verify TFT rotation/touch, exact board
   revision, chip-select isolation and radio detection at idle.
4. Run **receive-only** RF spectrum and SPI/register checks first;
   compare against a known local test signal. Confirm no unwanted
   transmit or current spikes with an appropriate RF test setup.
5. Only consider TX, PA and antenna measurements after verifying
   front-end enable polarity, supply current, antenna load, and local
   spectrum rules. The build does **not** qualify radiated power.

### Limits

A successful compile confirms source compatibility, **not**
hardware operation. Smoochiee, T-Embed, Cardputer and NM-CYD-C5 may
depend on firmware config files left by an earlier installation.
Do not copy chip selects between boards or confuse a CC1101 register
PA value with an RF amplifier's output.

Fenrir's guarded board build suppresses normal CC1101 TX and
nRF24 jammer/MouseJack menu entries, but is **not a proof** that
all indirect scripts or third-party libraries are TX-disabled.
Keep this target on the bench and RX-only until an end-to-end TX audit
and hardware qualification are completed.
