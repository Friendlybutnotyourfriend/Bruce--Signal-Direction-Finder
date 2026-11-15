# Fenrir Black Box / Lean3 candidate

This is a full standalone 4 MB Fenrir build. Hardware qualification is pending.
Use `Bruce-1.17-Fenrir-BlackBox-Lean3-Full-USB.bin` at offset `0x0` for USB installation.

## Lean3 feature exclusions

LoRa, FM, Ethernet, IR and RFID/NFC are excluded for this Fenrir build,
including their menu instances, startup hooks, serial commands and dedicated libraries.
Wi-Fi network tools retain the shared network code. Other board profiles are unchanged.
The 48 KiB BLE startup guard remains unchanged; the build includes a static RAM
report, but only the physical device can establish the largest free DMA block.

## Idle RAM corrections

The protocol-decoder allocation tracker and GPIO receive buffer now allocate
only while used and release on exit. Allocation failures unwind cleanly.
GPIO capture storage stays in internal RAM and is released after the ISR stops.
MAC lookup tables are read-only flash data rather than writable pointer arrays
or statically reserved Arduino String objects. NetCut allocates its device table only on the first scan, retaining its original
process-long lifetime because the network input hook can reference it. No additional
menu feature is removed.
The BLE guard remains at 48 KiB; physical cold-boot and mode-switch tests are pending.

## nRF24 2.4 GHz Black Box

Open **NRF24 > 2.4 GHz Black Box**. It passively samples channel centres 2400–2483 MHz,
keeps 12 completed windows in RAM and records CSV to `/Bruce/NRFBlackBox` when SD is available.
SEL marks the current window; UP/DOWN selects recent history while recording continues; ESC exits.
The log stops at 16 MiB or a write failure and the display reports that recording has stopped.
Live measurement continues without SD. Hardware disconnection stops the session.

The detector reports sampled energy above the chip's nominal -64 dBm threshold, not RSSI,
packets, protocol, source identity, or antenna gain. Front-end gain affects the antenna-level
threshold. It samples channels sequentially, with gaps for display and SD writes. CSV includes
actual window duration and per-channel sample counts. A rise marker means at least one channel
changed from below 20% to at least 40% hits; it is not a threat classification.
Wi-Fi and BLE on this board are stopped during capture. Auto-ACK is disabled and no packets are sent.

## Hunter / Sniffer RAM correction in Stability2

The previous build allocated both modes' snapshots before starting BLE. This
could consume the radio's largest contiguous block before its 48 KiB startup
guard ran. The radio now starts first; only the selected mode's working state
is allocated, after the target list and menu callbacks have been destroyed.
The 48 KiB radio startup threshold is unchanged.

Classic ESP32 observation buffers now hold the complete legacy ADV + response
(62 bytes and a 31-byte response), instead of extended-advertising-sized arrays.
Other chips keep the larger buffers. Discovery retains up to 60 devices; menu
callbacks carry an index rather than copies of full observations.
The recording queue is released after the BLE host stops, including failed
recording attempts. An initialization failure retains its original error;
the screen shows the largest DMA block and required size if the guard refuses.

## Stability changes

- Common BLE startup handles insufficient RAM, initialization failure, and reuse of an already running stack.
- SDK-owned shutdown replaces the private initialization flag; background BLE API services stop before objects are freed.
- Sentinel uses callback-only scanning; discovery scans have explicit limits.
- Recon working memory is freed on exit. Sentinel frees working tables after a watch and retains findings only inside its menu.
- Channel Analyzer, Jam Detect and Wi-Fi Sniffer stop cleanly on startup failure.
- Direct Wi-Fi drivers are deinitialized during radio switching. Sentinel can fall back to Wi-Fi after BLE refuses to start.

Before hardware qualification: test BLE first after reset, then repeated Wi-Fi/BLE/Hunter/Sniffer/API switches,
Sentinel alternate mode, Black Box with and without SD, SD write failure/cap, nRF unplug/replug,
and return to existing RF/NRF tools. Automated host tests do not simulate ESP32 heap fragmentation or real radio timing.

---

# Fenrir — standalone Bruce 1.17 RAM Fix2

Target: ESP32-2432S028R-PLUS-RF, matching your board photo.
Classic ESP32, 4 MB flash, ST7789 display, E07/E01 radio daughterboard.
No Launcher is required or included.

## Files
Bruce-1.17-Fenrir-BlackBox-Lean3-Full-USB.bin
  Complete standalone image: bootloader, partition table and firmware.
  Flash at offset 0x0 using a compatible ESP32 USB flasher.
  Back up existing settings/internal files first: this writes across NVS and
  installs the standalone partition layout.

Bruce-1.17-Fenrir-BlackBox-Lean3-Full-App.bin
  Application-only update. Flash at 0x10000 ONLY if the existing partition
  table matches: factory app offset 0x10000, size 0x3C0000; filesystem offset
  0x3D0000, size 0x30000. This is the saved Fenrir standalone layout.
  The app-only file does not replace the bootloader, NVS or partition table.
  Do not flash this application-only file at 0x0.

## Features And Limits
The custom BLE Hunter/Sniffer, sessions/review, Sentinel, Antenna ID,
Radio Control and RF Black Box/Receive Profile Finder are retained.
The JavaScript interpreter is excluded to fit the existing 4 MB layout.
LoRa, FM, Ethernet, IR (including TV-B-Gone), and RFID/NFC are excluded.
No speaker/microphone is wired on this board.

## RAM Fix2
On Fenrir's classic ESP32, the BLE memory guard now reclaims the unused
Classic Bluetooth controller memory before measuring the available DMA block.
NimBLE 2.5.1 normally performs this release inside init(), after the old guard
could already have refused startup. The release is only attempted while the
controller is idle. BLE memory is retained, and the 48 KiB guard is unchanged.
An actual NimBLE initialization failure now stops scanning with an error.
Serial output records the release result and the DMA block before and after it.

This addresses a startup-order defect found after BLE patterns still showed a
low-RAM warning on a fresh boot. Whether it frees enough contiguous memory on
the physical Fenrir remains to be tested.

### Retained from RAM Fix1
Fenrir defers serial command registration until the first non-empty command.
Reading serial logs does not allocate that registry. Sending a command does;
reboot before comparing the fresh-boot Sentinel memory measurements.
Sentinel releases prior radio/WebUI state before allocating its tables/worker.
Wi-Fi initialization failures now stop immediately and clean up the driver.
Existing memory thresholds are retained. Added RAMLOG stages show memory before
and after cleanup, worker allocation and Wi-Fi initialization.

## Validation
The build manifest records the exact source commit, sizes and SHA-256 hashes.
Packaging checks source identity and the application partition limit.
This is a candidate fix; physical testing on Fenrir is still required.

## Update and reproduce
Close the serial monitor with Ctrl+] before flashing. For a complete standalone
install, save the Full-USB BIN directly in Downloads and run (overwrites settings):

```powershell
py -m esptool --chip esp32 --port COM12 --baud 460800 write_flash 0x0 "$env:USERPROFILE\Downloads\Bruce-1.17-Fenrir-BlackBox-Lean3-Full-USB.bin"
py -m serial.tools.miniterm --dtr 0 --rts 0 COM12 115200
```

Press RESET without holding BOOT. Open Sentinel > BLE patterns first.
Save the boot, sentinel-* RAMLOG, and Classic BT release lines plus any error.
Then test leaving and re-entering BLE patterns, Wi-Fi patterns, and alternating
modes. The App image remains an optional settings-preserving update only when
the existing standalone partition layout matches.

## First Boot
Complete touch calibration if prompted. Check touch/rotation, brightness,
battery reading, SD logging, E07 receive, nRF24 spectrum, settings persistence,
and sleep/wake. The E07 uses GPIO0 for RX enable; touch IRQ36 is the wake input.
