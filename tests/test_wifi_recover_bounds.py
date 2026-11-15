"""Check the actual 32-byte PBKDF2 output and its adjacent memory."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest


class RecoveryBoundsTest(unittest.TestCase):
    def test_key_derivation_does_not_overwrite_adjacent_memory(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "src/modules/wifi/wifi_recover.cpp").read_text()
        core = source[source.index("struct Sha1Ctx {"):source.index("static size_t build_ptk_message(")]
        harness = r'''
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#define IRAM_ATTR
''' + core + r'''
int main() {
    for (unsigned iterations : {1u, 2u, 4096u}) {
        struct { uint8_t before[8], key[32], after[8]; } result;
        memset(&result, 0xa5, sizeof(result));
        HmacSha1Pre pre;
        hmac_sha1_precompute((const uint8_t *)"password", 8, pre);
        pbkdf2_precomp(pre, (const uint8_t *)"IEEE", 4, iterations, result.key, 32);
        for (unsigned i = 0; i < 8; ++i) {
            assert(result.before[i] == 0xa5);
            assert(result.after[i] == 0xa5);
        }
        for (uint8_t byte : result.key) printf("%02x", byte);
        puts("");
    }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            cpp, binary = Path(directory) / "bounds.cpp", Path(directory) / "bounds"
            cpp.write_text("#include <initializer_list>\n" + harness)
            subprocess.run(["g++", "-std=c++17", "-O2", str(cpp), "-o", str(binary)], check=True)
            actual = subprocess.check_output([str(binary)], text=True).splitlines()
        expected = [hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", n, 32).hex()
                    for n in (1, 2, 4096)]
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
