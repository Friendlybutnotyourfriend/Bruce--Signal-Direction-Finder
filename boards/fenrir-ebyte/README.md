# Fenrir — native Bruce 1.17

Target: ESP32-2432S028R-PLUS-RF / ZLX-ESP32-4, classic ESP32-WROOM-32E/UE-N4,
4 MB flash, ST7789 240×320 BGR non-inverted display. Not the ILI9341 E32R28T.

Native 1.17 touch HAL and calibration, fixed integrated radio/SD pins,
GPIO36 touch wake (GPIO0 is E07 RX enable), battery ADC34 divider 2:1.
E07-433M20S: CS27, GDO0 22, GDO2 35, RX enable0, TX enable4;
E01-2G4M27SX: CS26, CE16; SD CS5; all share SCK18/MISO19/MOSI23.
Touch uses separate software SPI SCK25/MISO39/MOSI32/CS33/IRQ36.
PN532 CS17 stays deselected when unused. No speaker or microphone.
E07 tools are limited to 425–450.5 MHz.

## Images

- Launcher-App.bin: application-only, reduced upstream Lite build with the custom
  BLE Hunter/Sniffer/Sessions, Sentinel, Antenna ID, Radio Control and RF Black Box /
  Receive Profile Finder retained. Upstream Lite exclusions still apply to other
  features (including scripting, several NFC/network and advanced RF tools).
  TV-B-Gone is also omitted: this board has no wired IR transmitter.
  Install through compatible Launcher 3.0 from SD. Maximum app size 0x290000 bytes.
  The 4 MB budget reserves 0x160000 for Launcher/header and at least 0x10000 for
  settings. Back up existing internal files before resizing/replacing partitions;
  the installer must provide a sufficiently large app slot. Custom logs use SD.
  The compiler CSV describes a standalone layout; app-only installation uses
  Launcher's actual partition table, not the CSV's filesystem size.
- Full-USB.bin: standalone build with JavaScript interpreter excluded to fit 4 MB;
  custom tools retained. Merged bootloader/partition/app; USB flash at 0x0.
  This replaces Launcher and its partition layout. Back up files and settings first.
- Full-App.bin: full application only, intended for the standalone full partition
  at 0x10000, NOT the 4 MB Launcher layout.

Only files that pass size and embedded source identity checks are packaged.
Compile and host checks do not establish hardware compatibility: verify boot,
touch calibration/rotation, brightness, battery, SD logging, both radios, and
sleep/wake on the actual board. No physical Fenrir testing has been performed.
