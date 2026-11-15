# Fenrir — standalone Bruce 1.17 RAM Fix1

Target: ESP32-2432S028R-PLUS-RF, matching your board photo.
Classic ESP32, 4 MB flash, ST7789 display, E07/E01 radio daughterboard.
No Launcher is required or included.

## Files
Bruce-1.17-Fenrir-RAM-Fix1-Full-USB.bin
  Complete standalone image: bootloader, partition table and firmware.
  Flash at offset 0x0 using a compatible ESP32 USB flasher.
  Back up existing settings/internal files first: this writes across NVS and
  installs the standalone partition layout.

Bruce-1.17-Fenrir-RAM-Fix1-Full-App.bin
  Application-only update. Flash at 0x10000 ONLY if the existing partition
  table matches: factory app offset 0x10000, size 0x3C0000; filesystem offset
  0x3D0000, size 0x30000. This is the saved Fenrir standalone layout.
  The app-only file does not replace the bootloader, NVS or partition table.
  Do not flash this application-only file at 0x0.

## Features And Limits
The custom BLE Hunter/Sniffer, sessions/review, Sentinel, Antenna ID,
Radio Control and RF Black Box/Receive Profile Finder are retained.
The JavaScript interpreter is excluded to fit the existing 4 MB layout.
This standalone image retains TV-B-Gone; the experimental Launcher reductions
are not applied. No speaker/microphone is wired on this board.

## RAM Fix1
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
Close the serial monitor with Ctrl+] before flashing. For the existing matching
Fenrir standalone layout, save the App BIN directly in Downloads and run:

```powershell
py -m esptool --chip esp32 --port COM12 --baud 460800 write_flash 0x10000 "$env:USERPROFILE\Downloads\Bruce-1.17-Fenrir-RAM-Fix1-Full-App.bin"
py -m serial.tools.miniterm --dtr 0 --rts 0 COM12 115200
```

Press RESET without holding BOOT. Open WiFi > Sentinel > Wi-Fi patterns.
Save the boot and sentinel-* RAMLOG lines plus any error. Then test leaving and
re-entering Sentinel, BLE-only and alternating modes. The App update preserves
settings. Use the USB image at 0x0 only for a full standalone installation.

## First Boot
Complete touch calibration if prompted. Check touch/rotation, brightness,
battery reading, SD logging, E07 receive, nRF24 spectrum, settings persistence,
and sleep/wake. The E07 uses GPIO0 for RX enable; touch IRQ36 is the wake input.
