#include "../src/modules/rf_lab/core.h"
#include <cassert>
#include <iostream>
using namespace RfLab;
int main() {
    Ring<3> ring;
    for (unsigned i = 0; i < 5; ++i) ring.push({i, -90});
    assert(ring.count == 3 && ring.at(0).ms == 2 && ring.at(2).ms == 4);
    Detector d;
    for (unsigned i = 0; i < Detector::Learning; ++i) assert(!d.add({i * 20, -100}));
    assert(d.threshold == -90);
    assert(!d.add({3000, -80}));
    assert(d.add({3020, -80}));
    for (unsigned i = 3040; i < 4000; i += 20) assert(!d.add({i, -40}));
    assert(d.threshold == -90); // sustained signal cannot train itself away
    d.add({4000, -100}); d.add({4500, -100});
    assert(!d.add({4520, -80}) && d.add({4540, -80}));
    // Timer wrap during the quiet re-arm interval.
    d.add({0xffffff00u, -100}); d.add({0x100u, -100});
    assert(!d.add({0x120u, -80}) && d.add({0x140u, -80}));
    Evidence a, b;
    a.frames = b.frames = 3;
    for (int i = 0; i < 64; ++i) { a.pulse(400); b.pulse(400); }
    assert(similarity(a, b) == 100);
    b = Evidence{}; b.frames = 3;
    for (int i = 0; i < 64; ++i) b.pulse(4000);
    assert(similarity(a, b) == 0);
    b = a; b.clipped = 1; assert(similarity(a, b) == 0);
    b = a; b.frames = 1; assert(similarity(a, b) == 0);
    Evidence noise; noise.frames = 10; noise.pulses = 320;
    noise.bins.fill(10); assert(similarity(noise, noise) == 0);
    Evidence invalid; invalid.pulse(0); invalid.pulse(19); invalid.pulse(12000);
    assert(invalid.pulses == 0);
    std::cout << "RF Lab core tests passed\n";
}
