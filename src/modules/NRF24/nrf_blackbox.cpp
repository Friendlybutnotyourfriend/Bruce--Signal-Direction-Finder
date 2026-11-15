#include "nrf_blackbox.h"
#include "blackbox_core.h"
#include "nrf_common.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "modules/ble/ble_common.h"
#include <esp_random.h>
#include <memory>
#include <algorithm>
#include <cstring>

namespace {
using namespace NrfBlackBox;
class Log {
    File file;
    size_t bytes = 0;
public:
    const char *status = "Live only: no SD";
    String path;
    bool write(const char *line) {
        if (!file) return false;
        const size_t n = strlen(line);
        if (!fitsLog(bytes, n)) {
            status = "SD log reached 16 MiB cap";
            file.close();
            return false;
        }
        if (file.write(reinterpret_cast<const uint8_t *>(line), n) != n) {
            status = "SD write failed; live continues";
            file.close();
            return false;
        }
        bytes += n;
        return true;
    }
    void begin() {
        if (!setupSdCard()) return;
        if (!SD.exists("/Bruce")) SD.mkdir("/Bruce");
        if (!SD.exists("/Bruce/NRFBlackBox") && !SD.mkdir("/Bruce/NRFBlackBox")) {
            status = "SD folder failed";
            return;
        }
        // Never append a new boot to an existing capture with overlapping uptime.
        for (unsigned i = 0; i < 8; ++i) {
            char name[80];
            snprintf(name, sizeof(name), "/Bruce/NRFBlackBox/nrf_%08lx_%08lx.csv",
                     (unsigned long)millis(), (unsigned long)esp_random());
            if (SD.exists(name)) continue;
            path = name;
            file = SD.open(path, FILE_WRITE);
            break;
        }
        if (!file) { status = "SD open failed"; return; }
        status = "Recording to SD";
        write("# NRF Black Box v1; passive sequential RPD samples; nominal threshold -64 dBm at chip input\n");
        write("# 1 Mbps RX bandwidth; 200 us listen; scan gaps apply; hits are NOT packets or calibrated RSSI\n");
        write("# rise=channel moves from <20% to >=40% sampled hits; marker=user; uptime resets each boot\n");
        write("# firmware=" BRUCE_VERSION " git=" GIT_COMMIT_HASH " board=" BRUCE_BOARD_NAME "\n");
        write("frame,uptime_ms,span_ms,mhz,hits,samples,marker,rise,saturated\n");
    }
    void record(const Frame &f, uint32_t sequence) {
        if (!file) return;
        char line[120];
        for (size_t ch = 0; ch < Channels; ++ch) {
            const int n = snprintf(line, sizeof(line), "%lu,%lu,%lu,%u,%u,%u,%u,%u,%u\n",
                (unsigned long)sequence, (unsigned long)f.startMs, (unsigned long)f.spanMs,
                unsigned(2400 + ch), unsigned(f.hits[ch]), unsigned(f.samples[ch]),
                f.marker ? 1 : 0, f.rise ? 1 : 0, f.saturated ? 1 : 0);
            if (n <= 0 || size_t(n) >= sizeof(line) || !write(line)) break;
        }
        if (file) file.flush();
    }
    ~Log() { if (file) { file.flush(); file.close(); } }
};

class Receiver {
    bool started = false;
public:
    bool begin() {
        started = nrf_start(NRF_MODE_SPI);
        if (!started) return false;
        if (!NRFradio.isPVariant()) return false;
        NRFradio.stopListening();
        NRFradio.setAutoAck(false);
        NRFradio.disableAckPayload();
        NRFradio.disableDynamicPayloads();
        NRFradio.flush_tx();
        NRFradio.flush_rx();
        for (uint8_t pipe = 0; pipe < 6; ++pipe) NRFradio.closeReadingPipe(pipe);
        if (!NRFradio.setDataRate(RF24_1MBPS)) return false;
        NRFradio.disableCRC();
        return true;
    }
    bool sample(uint8_t channel) {
        NRFradio.setChannel(channel);
        NRFradio.startListening();
        delayMicroseconds(ListenUs);
        const bool hit = NRFradio.testRPD();
        NRFradio.stopListening();
        NRFradio.flush_rx();
        return hit;
    }
    ~Receiver() {
        if (started) {
            NRFradio.stopListening();
            NRFradio.flush_tx();
            NRFradio.powerDown();
        }
        digitalWrite(bruceConfigPins.NRF24_bus.io0, LOW);
        digitalWrite(bruceConfigPins.NRF24_bus.cs, HIGH);
    }
};

void draw(const Recorder &recorder, size_t age, const char *status) {
    const Frame *f = recorder.ago(age);
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(1);
    tft.drawString("NRF 2.4 GHz BLACK BOX / RX", 4, 4);
    if (!f) { tft.drawString("Sampling 2400-2483 MHz...", 4, 24); return; }
    const size_t peak = f->peak();
    tft.drawString(String(age ? "History " : "Live ") + String(f->startMs / 1000) + "s  " +
                   String(f->spanMs) + "ms window", 4, 23);
    tft.drawString(f->percent(peak) ? String("Peak ") + String(2400 + peak) + " MHz  " +
                   String(f->percent(peak)) + "% hits" : String("No above-threshold hits"), 4, 39);
    const int top = 61, bottom = tftHeight - 67, width = tftWidth - 8;
    for (size_t ch = 0; ch < Channels; ++ch) {
        const int x = 4 + ch * width / Channels;
        const int w = std::max(1, int((ch + 1) * width / Channels - ch * width / Channels));
        const int h = int(f->percent(ch)) * (bottom - top) / 100;
        tft.fillRect(x, bottom - h, w, h, ch == peak ? TFT_ORANGE : bruceConfig.priColor);
    }
    tft.drawFastHLine(4, bottom, width, TFT_DARKGREY);
    tft.drawString("2400                  2483 MHz", 4, bottom + 3);
    tft.drawString(f->saturated ? "Sample counter capped" : f->marker ? "USER MARKER" :
                   f->rise ? "ACTIVITY RISE (unclassified)" : "Sampled activity; scan gaps apply", 4, tftHeight - 48);
    tft.drawString(status, 4, tftHeight - 33);
    tft.drawString("SEL mark | UP/DN history | ESC exit", 4, tftHeight - 17);
}
} // namespace

void nrf_blackbox() {
    cleanlyStopWebUiForWiFiFeature();
    stopBLEStack();
    wifiDisconnect(); // Avoid measuring this board's own 2.4 GHz transmissions.
    std::unique_ptr<NrfBlackBox::Recorder> recorder(new (std::nothrow) NrfBlackBox::Recorder(millis()));
    if (!recorder) { displayError("Not enough RAM for recorder", true); return; }
    Log log;
    log.begin(); // SD and nRF share SPI; mount before starting the receiver.
    Receiver receiver;
    if (!receiver.begin()) { displayError("nRF24L01+ receiver unavailable", true); return; }
    uint32_t sequence = 0, lastDraw = 0, lastCheck = millis();
    size_t age = 0;
    bool exit = false;
    recorder->current.startMs = millis();
    while (!exit && !returnToMenu) {
        if (check(EscPress)) break;
        if (check(SelPress)) recorder->current.marker = true;
        if (check(UpPress) && age + 1 < recorder->count()) ++age;
        if (check(DownPress) && age) --age;
        for (size_t ch = 0; ch < NrfBlackBox::Channels; ++ch) {
            if (check(EscPress)) { exit = true; break; }
            recorder->current.sample(ch, receiver.sample(ch));
        }
        const uint32_t now = millis();
        if (uint32_t(now - lastCheck) >= 1000) {
            lastCheck = now;
            if (!NRFradio.isChipConnected()) { displayError("nRF disconnected; recording stopped", true); break; }
        }
        if (recorder->due(now)) log.record(recorder->finish(now), sequence++);
        if (uint32_t(now - lastDraw) >= 500) { draw(*recorder, age, log.status); lastDraw = now; }
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (recorder->current.hasSamples()) log.record(recorder->finish(millis()), sequence);
    Serial.printf("[NRF Black Box] %s: %s\n", log.status, log.path.c_str());
}
