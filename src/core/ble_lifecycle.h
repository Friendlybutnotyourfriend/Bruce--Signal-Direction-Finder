#pragma once

#include <string>

// A failed start leaves callers responsible for returning without using BLE objects.
bool bruceBleInit(const std::string &name);
bool bruceBleDeinit(bool clearAll = true);
// A service with background tasks must detach them before SDK objects are destroyed.
void bruceBleShutdownHook(void (*hook)());
