#include "../src/modules/df/recon_core.h"
#include <cassert>
#include <iostream>
#include <vector>
using namespace recon;
std::vector<uint8_t> payload(bool reorder = false, uint8_t counter = 1) {
    const std::vector<uint8_t> name{9, 9, 'M','y','B','e','a','c','o','n'};
    const std::vector<uint8_t> mfg{8,255,0x4c,0,0x10,0x23,0x45,0x67,counter};
    auto out = reorder ? mfg : name;
    const auto &other = reorder ? name : mfg;
    out.insert(out.end(), other.begin(), other.end());
    return out;
}
Packet packet(const char *addr, uint32_t time, const std::vector<uint8_t> &data, int rssi = -60, uint8_t type = 1) {
    Packet p; std::strncpy(p.address, addr, 17); p.ms = time; p.payload = data.data(); p.length = data.size(); p.rssi = rssi; p.addressType = type; return p;
}
int main() {
    const char *a = "aa:00:00:00:00:01", *b = "bb:00:00:00:00:02", *c = "cc:00:00:00:00:03";
    auto raw = payload(), reordered = payload(true), changing = payload(false, 2);
    assert(decode(raw.data(), raw.size()).schema == decode(reordered.data(), reordered.size()).schema);
    uint8_t bad[]{8,9,'a'};
    assert(decode(bad, sizeof(bad)).malformed);
    for (size_t i=1; i<9; ++i) assert(decode(raw.data(), i).malformed);
    Association e; e.reset(packet(a, 100, raw));
    assert(e.observe(packet(a, 500, changing)) == Decision::Current);
    assert(e.observe(packet(b, 600, reordered)) == Decision::Ignore);
    assert(e.observe(packet(b, 4000, reordered)) == Decision::Ambiguous);
    assert(e.observe(packet(b, 4001, reordered)) == Decision::Ambiguous);
    assert(e.status(4001).hits == 1); // duplicate burst is not independent evidence
    assert(e.observe(packet(b, 4300, reordered)) == Decision::Ambiguous);
    assert(e.observe(packet(b, 4600, reordered)) == Decision::Handoff);
    assert(e.status(4600).tentative);
    assert(e.undo(4700));
    assert(e.status(4700).locked && std::string(e.status(4700).address) == a);
    assert(e.observe(packet(b, 8000, reordered)) == Decision::Ignore);
    e.reset(packet(a, 100, raw));
    e.observe(packet(b, 4000, raw)); e.observe(packet(c, 4100, raw));
    for (uint32_t t=4400;t<10000;t+=400) {
        assert(e.observe(packet(b,t,raw)) != Decision::Handoff);
        assert(e.observe(packet(c,t+100,raw)) != Decision::Handoff);
    }
    assert(e.status(9900).ambiguous);
    // Sparse advertisements extend the loss window; wrap-around preserves age arithmetic.
    e.reset(packet(a, 100, raw));
    e.observe(packet(a, 8100, raw));
    assert(e.status(8100).timeout >= 32000);
    assert(e.observe(packet(b, 15000, raw)) == Decision::Ignore);
    e.reset(packet(a, 0xfffff000u, raw));
    assert(e.observe(packet(a, 0x100, raw)) == Decision::Current);
    assert(e.status(0x101).lastSeen == 0x100);
    // Empty payload and generic UUID-only advertisements cannot establish identity.
    std::vector<uint8_t> generic{3,3,0x0f,0x18};
    e.reset(packet(a,100,generic));
    for (uint32_t t=4000;t<9000;t+=500) assert(e.observe(packet(b,t,generic)) == Decision::Ignore);
    // Address type is part of the selected target; scan responses never elect candidates.
    e.reset(packet(a,100,raw));
    assert(e.observe(packet(a,500,raw,-60,0)) == Decision::Ignore);
    auto response = packet(b,4000,raw); response.response = true;
    assert(e.observe(response) == Decision::Ignore);
    response.response = false; response.truncated = true;
    assert(e.observe(response) == Decision::Ignore);
    const auto ok = compareAntenna(-60,-54,-60,1);
    assert(ok.reliable && ok.delta == 6 && ok.drift == 0);
    assert(!compareAntenna(-60,-54,-50,1).reliable);
    assert(!compareAntenna(-104,-100,-104,1).reliable);
    assert(!compareAntenna(-60,-54,-60,8).reliable);
    std::cout << "recon core: field ordering, mutation, duplicates, ambiguity, sparse cadence, wrap, undo, truncation, antenna checks passed\n";
}
