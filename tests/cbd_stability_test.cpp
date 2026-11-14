#include "../src/core/radio_pin_validation.h"
#include "../src/modules/rf_lab/capture_limits.h"
#include "../src/modules/sentinel/sentinel_score.h"
#include <cassert>
#include <cstdio>

int main() {
    assert(!radioPins::distinct(14, 2, 3, 21, 2)); // old CC1101 map
    assert(!radioPins::distinct(14, 2, 3, 21, 3)); // old NRF24 map
    assert(!radioPins::distinct(14, 2, 3, 21, -1));
    assert(!radioPins::distinct(14, 2, 3, 14, 43));
    assert(radioPins::distinct(14, 2, 3, 21, 43));
    assert(!RfLab::captureClipped(127, 128));
    assert(RfLab::captureClipped(128, 128));
    assert(RfLab::captureClipped(129, 128));
    static_assert(RfLab::GlitchFilterNs <= 3187, "Classic ESP32 filter limit");
    sentinel::Exposure exposure;
    exposure.select(1, 100);
    exposure.select(6, 350);
    exposure.select(0, 600);
    exposure.select(15, 1100);
    exposure.update(1600);
    assert(exposure.window[1] == 250 && exposure.window[6] == 250);
    assert(exposure.window[15] == 500 && exposure.total[0] == 0);
    assert(sentinel::observedRate(10, exposure.window[1]) == 40);
    assert(sentinel::observedRate(10, 0) == 0);
    assert(sentinel::observedRate(1000000, 1) == 65535);
    exposure.resetWindow(1700);
    assert(exposure.window[15] == 0 && exposure.total[15] == 600);
    exposure.previous = 0xfffffff0u;
    exposure.update(0x10u);
    assert(exposure.window[15] == 32); // millis wrap
    puts("CBD pin validation and capture boundaries PASS");
}
