#include "../src/modules/df/recon_core.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
// stdin: ms address address_type RSSI response truncated hex_payload
// stdout: ms address decision score hits handoffs; exactly the firmware engine.
int main() {
    recon::Association engine;
    std::string line;
    bool initialized = false;
    while (std::getline(std::cin, line)) {
        std::istringstream row(line);
        recon::Packet p;
        std::string address, hex;
        unsigned type, response, truncated;
        if (!(row >> p.ms >> address >> type >> p.rssi >> response >> truncated >> hex)) return 2;
        if (address.size() != 17 || type > 3 || (hex != "-" && hex.size() % 2)) return 2;
        std::strncpy(p.address, address.c_str(), 17); p.addressType = type;
        p.response = response; p.truncated = truncated;
        std::vector<uint8_t> bytes;
        if (hex != "-") for (size_t i = 0; i < hex.size(); i += 2) {
            auto digit = [](char c) -> int { if (c >= '0' && c <= '9') return c-'0'; if (c >= 'a' && c <= 'f') return c-'a'+10; if (c >= 'A' && c <= 'F') return c-'A'+10; return -1; };
            const int a = digit(hex[i]), b = digit(hex[i+1]);
            if (a < 0 || b < 0 || bytes.size() >= 256) return 2;
            bytes.push_back(static_cast<uint8_t>((a << 4) | b));
        }
        p.payload = bytes.data(); p.length = bytes.size();
        if (!initialized) { engine.reset(p); initialized = true; }
        const auto d = engine.observe(p);
        const auto s = engine.status(p.ms);
        std::cout << p.ms << ' ' << p.address << ' ' << static_cast<int>(d) << ' ' << static_cast<int>(s.score) << ' ' << static_cast<int>(s.hits) << ' ' << s.handoffs << '\n';
    }
}
