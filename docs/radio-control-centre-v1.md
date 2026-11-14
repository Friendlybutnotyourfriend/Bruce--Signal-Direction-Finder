# Bruce Radio Control Centre — Stage 1

## Scope

This patch adds opt-in, persistent CC1101 and nRF24 SPI hardware profiles, a menu
in each radio's existing Bruce menu, and read-only connection/register diagnostics.

It is the Radio Control Centre from the fork's earlier branches, rewired onto
Bruce tag 1.16.1. Profiles stay off until enabled, so existing Bruce radio
tools keep their previous defaults. GPIO definitions and partitions are unchanged.

### CC1101

- Enable/disable a CC1101 hardware override (OFF by default).
- PA chip setting: -30, -20, -10, or 0 dBm.
- Modulation: ASK/OOK, 2-FSK, GFSK.
- Data rate: 1.2 / 4.8 / 9.6 / 38.4 / 50 kBaud.
- SPI diagnostic (no TX command); retain existing frequency selection in RF Config.

The opt-in overrides apply from `initRfModule()`. Disabled mode retains the
current settings, including the existing TX PA setting.

### nRF24

- Enable/disable an SPI hardware override (OFF by default).
- Chip-level PA: MIN / LOW / HIGH / MAX.
- Data rate: 250 kbps / 1 Mbps / 2 Mbps.
- Channel presets: 2 / 20 / 40 / 60 / 76 / 80.
- Connection diagnostics with channel, PA and data rate registers.
- SPI profiles apply after `nrf_start()`; individual tools can override them
  later for protocol-specific operation.

### Safety / limitations

- Profiles are *opt-in*. A saved profile changes a later tool's radio init,
  not a currently running radio session.
- This version has no packet burst/noise generator, no live RSSI history,
  no bus arbitration mutex and no external PA/LNA detection.
- TX levels are chipset register settings, *not calibrated EIRP*. External
  amplifiers, antenna gain, frequency permissions and local regulatory limits
  must be validated separately.
- The hardware checks initialise each chip one at a time and do not call TX.
  Do not run simultaneous radio tasks on the Smoochiee shared SPI bus.
- RX/TX protocol tools may override these settings after radio start.
- Do not flash anything until the exact hardware revision is checked and a
  full backup of the installed working firmware has been taken.
- Firmware binaries must match the actual board. Existing Launcher bootloader,
  partition table, OTA metadata and app partition layout must remain intact.

## Manual smoke checks

1. Confirm both menus show `Radio Control` / `Hardware check`.
2. With profiles OFF, existing antenna ID / spectrum RX should behave as before.
3. Change a profile, reboot, and verify it persisted.
4. Turn on a profile; verify register values with hardware diagnostics.
5. Disable the profile and verify the original behaviour returns.
6. Confirm SD card and both radios still function on shared SPI.
7. Test only authorised packet transmissions into suitable test equipment.

A successful firmware compile does not establish hardware compatibility.
