#include "cli.h"
#include "badusb_commands.h"
#include "core/sd_functions.h"
#include "crypto_commands.h"
#include "gpio_commands.h"
#include "interpreter_commands.h"
#ifndef BRUCE_DISABLE_IR
#include "ir_commands.h"
#endif
#include "led_commands.h"
#include "power_commands.h"
#include "rf_commands.h"
#ifndef BRUCE_DISABLE_RFID
#include "rfid_commands.h"
#endif
#include "screen_commands.h"
#include "settings_commands.h"
#include "sound_commands.h"
#include "storage_commands.h"
#include "util_commands.h"
#include "wifi_commands.h"
#include "wire_commands.h"
#include <globals.h>

void cliErrorCallback(cmd_error *e) {
    CommandError cmdError(e); // Create wrapper object

    serialDevice->print("ERROR: ");
    serialDevice->println(cmdError.toString());

    if (cmdError.hasCommand()) {
        serialDevice->print("Did you mean \"");
        serialDevice->print(cmdError.getCommand().toString());
        serialDevice->println("\"?");
    }
}

SerialCli::SerialCli() {
#ifndef BRUCE_DEFER_SERIAL_CLI
    setup();
#endif
}

void SerialCli::setup() {
#ifdef BRUCE_DEFER_SERIAL_CLI
    // Registration owns many small heap allocations. Do it only for an actual
    // command, and once even if the serial task and a UI shortcut arrive together.
    std::call_once(_setupOnce, [this]() {
#endif
    _cli.setOnError(cliErrorCallback);

    createCryptoCommands(&_cli);
    createGpioCommands(&_cli);
#ifndef BRUCE_DISABLE_IR
    createIrCommands(&_cli);
#endif
    createPowerCommands(&_cli);
    createRfCommands(&_cli);
#ifndef BRUCE_DISABLE_RFID
    createRfidCommands(&_cli);
#endif
    createSettingsCommands(&_cli);
    createStorageCommands(&_cli);
    createUtilCommands(&_cli);
    createWifiCommands(&_cli);

#ifndef LITE_VERSION
    createWireCommands(&_cli);
#endif

#ifdef USB_as_HID
    createBadUsbCommands(&_cli);
#endif
#ifndef LITE_VERSION
    createInterpreterCommands(&_cli);
#endif
#ifndef USE_DUMMY_TFT
    createScreenCommands(&_cli);
#endif
#ifdef HAS_RGB_LED
    createLedCommands(&_cli);
#endif
    createSoundCommands(&_cli);
#ifdef BRUCE_DEFER_SERIAL_CLI
    });
#endif
}
