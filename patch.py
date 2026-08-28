import hashlib
from typing import TYPE_CHECKING, Any
import requests
import re

if TYPE_CHECKING:
    Import: Any = None
    env: Any = {}

import glob
import gzip
from os import makedirs, remove, rename
from os.path import basename, dirname, exists, isfile, join

Import("env")  # type: ignore

FRAMEWORK_DIR = env.PioPlatform().get_package_dir("framework-arduinoespressif32-libs")
board_mcu = env.BoardConfig()
mcu = board_mcu.get("build.mcu", "")
patchflag_path = join(FRAMEWORK_DIR,mcu, "lib", ".patched")

# patch file only if we didn't do it befored
if not isfile(join(FRAMEWORK_DIR,mcu, "lib", ".patched")):
    original_file = join(FRAMEWORK_DIR,mcu, "lib", "libnet80211.a")
    patched_file = join(
        FRAMEWORK_DIR, mcu, "lib", "libnet80211.a.patched"
    )

    if mcu=="esp32c5" or mcu=="esp32c6" :
        env.Execute(
            "pio pkg exec -p toolchain-riscv32-esp -- riscv32-esp-elf-objcopy  --weaken-symbol=ieee80211_raw_frame_sanity_check %s %s"
            % (original_file, patched_file)
        )
    elif mcu=="esp32p4":
        """Do nothing"""
    else:
        env.Execute(
            "pio pkg exec -p toolchain-xtensa-%s -- xtensa-%s-elf-objcopy  --weaken-symbol=ieee80211_raw_frame_sanity_check %s %s"
            % (mcu, mcu, original_file, patched_file)
        )

    if isfile("%s.old" % (original_file)):
        remove("%s.old" % (original_file))

    if isfile(original_file):
        rename(original_file, "%s.old" % (original_file))
    else:
        print("Patch: Original file not found")

    if isfile(patched_file):
        rename(patched_file, original_file)
    else:
        print("Patch: Patched file not found")


    def _touch(path):
        with open(path, "w") as fp:
            fp.write("")

    env.Execute(lambda *args, **kwargs: _touch(patchflag_path))


def patch_ble_hunter_ui():
    """Apply the target-first BLE Hunter UI without touching its DF/continuity engine."""
    project_dir = env.get("PROJECT_DIR")
    source_path = join(project_dir, "src", "modules", "df", "ble_solo_df.cpp")
    menu_path = join(project_dir, "src", "core", "menu_items", "DfMenu.cpp")

    if not exists(source_path):
        return

    with open(source_path, "r", encoding="utf-8") as f:
        source = f.read()

    if "BLE_HUNTER_TARGET_FIRST_UI" not in source:
        replacement = r'''// BLE_HUNTER_TARGET_FIRST_UI
void drawTrackerFrame() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.drawCentreString("BLE HUNTER", tftWidth / 2, 29, 1);

    const bool compact = tftHeight <= 150;
    const int barY = compact ? 84 : 111;
    const int barX = 14;
    const int barW = tftWidth - 28;
    const int barH = compact ? 12 : 15;
    tft.drawRect(barX, barY, barW, barH, bruceConfig.priColor);

    if (!compact) {
        const String footer = String(BTN_ALIAS) + " peak   Hold details   Esc back";
        tft.setTextSize(FP);
        tft.drawCentreString(footer, tftWidth / 2, tftHeight - 14, 1);
    }
    drawStatusBar();
}

void drawTrackerValues(const TrackerSnapshot &snapshot) {
    const TrackerState &state = snapshot.state;
    const bool compact = tftHeight <= 150;
    const int stable = state.initialized ? static_cast<int>(roundf(state.stableRssi)) : -127;
    const int best = state.initialized ? static_cast<int>(roundf(state.bestRssi)) : -127;
    const int confidence = confidenceScore(state);

    String identity = state.currentName[0] ? String(state.currentName) : String("Unknown BLE");
    const int maxNameChars = tftWidth >= 300 ? 28 : 20;
    if (identity.length() > maxNameChars) identity = identity.substring(0, maxNameChars - 3) + "...";

    String meta = "[" + String(identitySourceTag(state.identitySource)) + "] ";
    meta += state.currentAddress[0] ? String(state.currentAddress) : String("--:--:--:--:--:--");

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);

    // Target identity is the hero of the screen.
    tft.fillRect(8, 39, tftWidth - 16, compact ? 42 : 55, bruceConfig.bgColor);
    tft.setTextSize(compact ? FP : FM);
    tft.drawCentreString(identity, tftWidth / 2, compact ? 40 : 41, 1);

    tft.setTextSize(FP);
    tft.drawCentreString(meta, tftWidth / 2, compact ? 52 : 59, 1);

    // One useful, smoothed RSSI instead of three competing numbers.
    tft.setTextSize(compact ? FM : FG);
    const String rssiText = state.initialized ? String(stable) + " dBm" : String("-- dBm");
    tft.drawCentreString(rssiText, tftWidth / 2, compact ? 64 : 72, 1);

    if (!compact) {
        tft.setTextSize(FP);
        const String secondary = "PEAK " + String(best) + "   CONF " + String(confidence) + "%";
        tft.drawCentreString(secondary, tftWidth / 2, 96, 1);
    }

    const int barX = 16;
    const int barY = compact ? 86 : 113;
    const int barW = tftWidth - 32;
    const int barH = compact ? 8 : 11;
    tft.fillRect(barX, barY, barW, barH, bruceConfig.bgColor);
    if (state.initialized) {
        const int fillW = clampInt(signalBarPixels(state.stableRssi, barW), 0, barW);
        if (fillW > 0) tft.fillRect(barX, barY, fillW, barH, trackerStatusColor(state));
    }

    String direction = trackerStatusLabel(state);
    if (direction == "WARMER")
        direction = ">> WARMER";
    else if (direction == "COLDER")
        direction = "<< COLDER";
    else if (direction == "STEADY")
        direction = "-- STEADY --";

    tft.fillRect(8, compact ? 98 : 126, tftWidth - 16, compact ? 29 : 27, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(trackerStatusColor(state), bruceConfig.bgColor);
    tft.drawCentreString(direction, tftWidth / 2, compact ? 99 : 127, 1);

    if (!compact) {
        float displayedRate = state.packetsPerSecond;
        const uint32_t lastSeenAgeMs = state.lastSeenMs == 0 ? 0 : millis() - state.lastSeenMs;
        const bool targetLost = state.lastSeenMs != 0 && lastSeenAgeMs > LOST_TARGET_MS;
        if (state.lastSeenMs == 0 || lastSeenAgeMs > 1800) displayedRate = 0.0f;

        tft.setTextSize(FP);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        String stats;
        if (targetLost) {
            stats = "LAST " + formatAge(lastSeenAgeMs);
            if (state.candidateHits > 0) {
                stats += "   CAND " + String(state.candidateScore) + "%x" + String(state.candidateHits);
            }
        } else {
            stats = "RAW " + String(state.initialized ? state.rawRssi : -127) + "   " +
                    String(displayedRate, 1) + "/s   H" + String(state.handoffs) + " R" +
                    String(state.reacquisitions);
        }
        tft.drawCentreString(stats, tftWidth / 2, 146, 1);
    }
}

void drawFingerprintDetails'''

        pattern = re.compile(
            r"void drawTrackerFrame\(\) \{.*?\nvoid drawFingerprintDetails",
            re.DOTALL,
        )
        patched, count = pattern.subn(replacement, source, count=1)
        if count != 1:
            raise RuntimeError("BLE Hunter UI patch did not find the expected tracker display block")

        with open(source_path, "w", encoding="utf-8") as f:
            f.write(patched)
        print("[BLE Hunter] Applied target-first tracker UI")

    if exists(menu_path):
        with open(menu_path, "r", encoding="utf-8") as f:
            menu = f.read()
        updated_menu = menu.replace('"BLE Solo DF"', '"BLE Hunter"')
        if updated_menu != menu:
            with open(menu_path, "w", encoding="utf-8") as f:
                f.write(updated_menu)
            print("[BLE Hunter] Renamed native DF menu entry")


def hash_file(file_path):
    """Generate SHA-256 hash for a single file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks to avoid memory issues
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_files(file_paths):
    """Generate a combined hash for multiple files."""
    combined_hash = hashlib.sha256()

    for file_path in file_paths:
        file_hash = hash_file(file_path)
        combined_hash.update(file_hash.encode("utf-8"))  # Update with the file's hash

    return combined_hash.hexdigest()


def save_checksum_file(hash_value, output_file):
    """Save the hash value to a specified output file."""
    with open(output_file, "w") as f:
        f.write(hash_value)


def load_checksum_file(input_file):
    """Load the hash value from a specified input file."""
    with open(input_file, "r") as f:
        return f.readline().strip()


def minify_css(c):
    minify_req = requests.post(
        "https://www.toptal.com/developers/cssminifier/api/raw",
        {"input": c.read().decode('utf-8')},
    )
    return c if minify_req is False else minify_req.text.encode('utf-8')


def minify_js(js):
    minify_req = requests.post(
        'https://www.toptal.com/developers/javascript-minifier/api/raw',
        {'input': js.read().decode('utf-8')},
        timeout=10
    )
    return js if minify_req is False else minify_req.text.encode('utf-8')


def minify_html(html):
    minify_req = requests.post(
        'https://www.toptal.com/developers/html-minifier/api/raw',
        {'input': html.read().decode('utf-8')},
        timeout=10
    )
    return html if minify_req is False else minify_req.text.encode('utf-8')


# gzip web files
def prepare_www_files():
    HEADER_FILE = join(env.get("PROJECT_DIR"), "include", "webFiles.h")
    filetypes_to_gzip = ["html", "css", "js"]
    data_src_dir = join(env.get("PROJECT_DIR"), "embedded_resources/web_interface")
    checksum_file = join(data_src_dir, "checksum.sha256")
    checksum = ""

    if not exists(data_src_dir):
        print(f'Error: Source directory "{data_src_dir}" does not exist!')
        return

    if exists(checksum_file):
        checksum = load_checksum_file(checksum_file)

    files_to_gzip = []
    for extension in filetypes_to_gzip:
        files_to_gzip.extend(glob.glob(join(data_src_dir, "*." + extension)))

    files_checksum = hash_files(files_to_gzip)
    if files_checksum == checksum:
        print("[GZIP & EMBED INTO HEADER] - Nothing to process.")
        return

    print(f"[GZIP & EMBED INTO HEADER] - Processing {len(files_to_gzip)} files.")

    makedirs(dirname(HEADER_FILE), exist_ok=True)

    with open(HEADER_FILE, "w") as header:
        header.write(
            "#ifndef WEB_FILES_H\n#define WEB_FILES_H\n\n#include <Arduino.h>\n\n"
        )
        header.write(
            "// THIS FILE IS AUTOGENERATED DO NOT MODIFY IT. MODIFY FILES IN /embedded_resources/web_interface\n\n"
        )

        for file in files_to_gzip:
            gz_file = file + ".gz"
            with open(file, "rb") as src, gzip.open(gz_file, "wb") as dst:
                ext = basename(file).rsplit(".", 1)[-1].lower()
                if ext == 'html':
                    minified = minify_html(src)
                elif ext == 'css':
                    minified = minify_css(src)
                elif ext == 'js':
                    minified = minify_js(src)
                else:
                    raise ValueError(f"Unsupported file type: {ext}")

                # # Output minified file
                # min_file = file + ".min"
                # with open(min_file, "wb") as minf:
                #     minf.write(minified)

                dst.write(minified)

            with open(gz_file, "rb") as gz:
                compressed_data = gz.read()
                var_name = basename(file).replace(".", "_")

                header.write(f"const uint8_t {var_name}[] PROGMEM = {{\n")

                # Write hex values, inserting a newline every 15 bytes
                for i in range(0, len(compressed_data), 15):
                    hex_chunk = ", ".join(
                        f"0x{byte:02X}" for byte in compressed_data[i : i + 15]
                    )
                    header.write(f"  {hex_chunk},\n")

                header.write("};\n\n")
                header.write(
                    f"const uint32_t {var_name}_size = {len(compressed_data)};\n\n"
                )

            remove(gz_file)  # Clean up temporary gzip file

        header.write("#endif // WEB_FILES_H\n")

    save_checksum_file(files_checksum, checksum_file)

    print(f"[DONE] Gzipped files embedded into {HEADER_FILE}")


patch_ble_hunter_ui()
prepare_www_files()
