"""Keep the pinned NimBLE library compatible with the bundled C5 SDK."""
from pathlib import Path
import re
from SCons.Script import Import

Import("env")
libs = Path(env.subst("$PROJECT_LIBDEPS_DIR")) / env.subst("$PIOENV")
sdk = Path(env.PioPlatform().get_package_dir("framework-arduinoespressif32-libs"))
npl_path = Path("porting/npl/freertos/include/nimble/nimble_npl_os.h")
sdk_header = (sdk / "esp32c5/include/bt" / npl_path).read_text()
nimble_header = libs / "NimBLE-Arduino/src/nimble" / npl_path
text = nimble_header.read_text()
table = r"struct npl_funcs_t \{.*?\n\};"
sdk_table = re.search(table, sdk_header, re.S)
library_table = re.search(table, text, re.S)
if not sdk_table or not library_table:
    raise RuntimeError("Cannot verify the C5 NimBLE dispatch table")

# IDF's controller owns this table. Its new trailing event-queue slot must be
# declared consistently in every translation unit, including NimBLE 2.5.1.
updated = text[:library_table.start()] + sdk_table.group() + text[library_table.end():]
if updated != text:
    nimble_header.write_text(updated)
    print("Aligned NimBLE dispatch table with the C5 SDK")

for relative, name in (
    ("ESP Chameleon Ultra/src/chameleonUltra.cpp", "BruceC5ChameleonScanCallbacks"),
    ("ESP PN32BLE/src/pn532_ble.cpp", "BruceC5Pn532ScanCallbacks"),
):
    path = libs / relative
    text = path.read_text()
    if not re.search(r"\b(?:scanCallbacks|" + name + r")\b", text):
        raise RuntimeError(f"Cannot verify callback class in {relative}")
    updated = re.sub(r"\bscanCallbacks\b", name, text)
    if name == "BruceC5ChameleonScanCallbacks":
        # NimBLE 2 uses a const device pointer; the old overload never overrides
        # its callback. Both NFC libraries also used the same global class name.
        updated = updated.replace(
            "void onResult(NimBLEAdvertisedDevice* advertisedDevice)",
            "void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override",
        )
    if updated != text:
        path.write_text(updated)
        print(f"Isolated C5 BLE callbacks in {relative}")
