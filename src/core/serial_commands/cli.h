#ifndef __SERIAL_CLI_H__
#define __SERIAL_CLI_H__

#include <Arduino.h>
#include <SimpleCLI.h>
#ifdef BRUCE_DEFER_SERIAL_CLI
#include <mutex>
#endif

class SerialCli {
public:
    SerialCli();
    void setup(void);

    SimpleCLI getCli() {
#ifdef BRUCE_DEFER_SERIAL_CLI
        setup();
#endif
        return _cli;
    }
    bool parse(const String &input) {
#ifdef BRUCE_DEFER_SERIAL_CLI
        // Serial monitors may send an empty line; that must not allocate the registry.
        String command = input;
        command.trim();
        if (command.isEmpty()) return false;
        setup();
#endif
        return _cli.parse(input);
    }

private:
    SimpleCLI _cli;
#ifdef BRUCE_DEFER_SERIAL_CLI
    std::once_flag _setupOnce;
#endif
};

void cliErrorCallback(cmd_error *e);

#endif

//  TODO: more commands https://docs.flipper.net/development/cli#0Z9fs
