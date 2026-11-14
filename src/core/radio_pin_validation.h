#pragma once

namespace radioPins {
// SPI data and the asynchronous control line must remain independent.
inline bool distinct(int sck, int miso, int mosi, int cs, int control) {
    const int pins[] = {sck, miso, mosi, cs, control};
    for (unsigned i = 0; i < 5; ++i) {
        if (pins[i] < 0) return false;
        for (unsigned j = 0; j < i; ++j)
            if (pins[i] == pins[j]) return false;
    }
    return true;
}
}
