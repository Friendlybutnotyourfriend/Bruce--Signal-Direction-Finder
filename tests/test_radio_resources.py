"""Fault-injection checks using the actual monitor/worker/receiver implementations."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_ble_lifecycle import function, ROOT


def run_cpp(source):
    with tempfile.TemporaryDirectory() as d:
        cpp = Path(d) / 'test.cpp'
        exe = Path(d) / 'test'
        cpp.write_text(source)
        subprocess.run(['g++', '-std=c++11', '-Wall', '-Wextra', '-Werror', str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


class ResourceTest(unittest.TestCase):
    def test_wifi_monitor_fails_closed(self):
        source = (ROOT/'src/core/wifi/wifi_common.cpp').read_text()
        run_cpp(r'''
#include <cassert>
#include <cstdio>
using esp_err_t=int; using uint32_t=unsigned; using wifi_promiscuous_cb_t=void(*)();
constexpr int ESP_OK=0,WIFI_STORAGE_RAM=0,WIFI_MODE_STA=0;
constexpr bool FORCE_RADIO_TEARDOWN_ON_SWITCH=true;
static int stage=0,failAt=0,stops=0; static bool budget=true,monitor=false;
struct SerialType { void printf(const char*,const char*){} } Serial;
struct wifi_init_config_t {}; struct wifi_promiscuous_filter_t {unsigned filter_mask;};
#define WIFI_INIT_CONFIG_DEFAULT() wifi_init_config_t{}
void displayError(const char*,bool){} void cleanlyStopWebUiForWiFiFeature(){} void stopBLEStack(){}
void ensureWifiPlatform(){} void esp_wifi_disconnect(){}
void wifiDisconnect(){++stops;monitor=false;} bool radioHasMemForWifi(){return budget;}
const char *esp_err_to_name(int){return "injected";}
int step(){return ++stage==failAt?1:0;}
int nvs_flash_init(){return step();} int esp_wifi_init(wifi_init_config_t*){return step();}
int esp_wifi_set_storage(int){return step();} int esp_wifi_set_mode(int){return step();}
int esp_wifi_start(){return step();} int esp_wifi_set_promiscuous_filter(wifi_promiscuous_filter_t*){return step();}
int esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb_t){return step();}
int esp_wifi_set_promiscuous(bool enabled){int e=step();monitor=!e&&enabled;return e;}
''' + function(source, 'bool startWifiMonitor(') + r'''
int main(){
 for(int failure=1;failure<=8;++failure){stage=0;failAt=failure;stops=0;
  assert(!startWifiMonitor(nullptr,1));assert(stage==failure && !monitor && stops==2);}
 stage=0;failAt=0;assert(startWifiMonitor(nullptr,1)&&monitor);
 budget=false;stage=0;assert(!startWifiMonitor(nullptr,1)&&stage==0&&!monitor);
 puts("Wi-Fi startup fault injection passed at every SDK stage");
}
''')

    def test_worker_timeout_retains_resources(self):
        source=(ROOT/'src/modules/sentinel/sentinel.cpp').read_text()
        run_cpp(r'''
#include <cassert>
#include <cstdio>
using TaskHandle_t=void*; using QueueHandle_t=void*;
static bool g_wifi_capture=true,g_ble_capture=true,g_worker_run=true;
static TaskHandle_t g_worker_handle=reinterpret_cast<void*>(1);
static QueueHandle_t g_wifi_q=reinterpret_cast<void*>(2),g_ble_q=reinterpret_cast<void*>(3);
static int deleted=0,waits=0,finishAfter=0;
#define pdMS_TO_TICKS(n) (n)
void vTaskDelay(int){if(++waits==finishAfter)g_worker_handle=nullptr;}
void vQueueDelete(void*){assert(!g_worker_handle);++deleted;}
struct SerialType { void println(const char*){} } Serial;
''' + function(source, 'bool stop_worker(') + r'''
int main(){
 assert(!stop_worker());assert(deleted==0&&g_wifi_q&&g_ble_q&&!g_worker_run);
 waits=0;finishAfter=2;assert(stop_worker());assert(deleted==2&&!g_wifi_q&&!g_ble_q);
 assert(stop_worker()&&deleted==2);
 puts("Worker shutdown timeout and repeated cleanup tests passed");
}
''')

    def test_receiver_never_transmits_and_settles(self):
        source=(ROOT/'src/modules/NRF24/nrf_blackbox.cpp').read_text()
        receiver=function(source,'class Receiver {')+';'
        run_cpp(r'''
#include <cassert>
#include <cstdio>
using uint8_t=unsigned char;
constexpr int NRF_MODE_SPI=1,RF24_1MBPS=1,LOW=0,HIGH=1;
constexpr unsigned ListenUs=200;
static bool failBegin=false,plus=true,rateOk=true;
static unsigned elapsed=0;static bool inRx=false,ack=false,powered=false;
struct Pins {int io0=16,cs=26;};struct Config {Pins NRF24_bus;} bruceConfigPins;
bool nrf_start(int){powered=!failBegin;return powered;}
void digitalWrite(int,int){}
void delayMicroseconds(unsigned us){elapsed+=us;}
struct Radio {
 bool isPVariant(){return plus;} void stopListening(){inRx=false;}
 void setAutoAck(bool enabled){ack=enabled;} void disableAckPayload(){}
 void disableDynamicPayloads(){} void flush_tx(){} void flush_rx(){}
 void closeReadingPipe(unsigned){} bool setDataRate(int){return rateOk;}
 void disableCRC(){} void setChannel(unsigned ch){assert(ch<84&&!inRx);}
 void startListening(){assert(!ack);inRx=true;elapsed=0;}
 bool testRPD(){assert(inRx&&elapsed>=170&&!ack);return true;}
 void powerDown(){inRx=false;powered=false;}
} NRFradio;
''' + receiver + r'''
int main(){
 {Receiver rx;assert(rx.begin());for(unsigned ch=0;ch<84;++ch)assert(rx.sample(ch));}
 assert(!inRx&&!powered);
 plus=false;{Receiver rx;assert(!rx.begin());}assert(!powered);
 plus=true;rateOk=false;{Receiver rx;assert(!rx.begin());}assert(!powered);
 failBegin=true;{Receiver rx;assert(!rx.begin());}
 puts("Passive receiver settling, channel bounds and cleanup tests passed");
}
''')

    def test_sd_log_failure_and_capacity(self):
        source=(ROOT/'src/modules/NRF24/nrf_blackbox.cpp').read_text()
        core=(ROOT/'src/modules/NRF24/blackbox_core.h').as_posix()
        stubs=r'''
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
using String=std::string; using uint8_t=unsigned char;
#define BRUCE_VERSION "test"
#define GIT_COMMIT_HASH "test"
#define BRUCE_BOARD_NAME "test"
constexpr int FILE_WRITE=0;
static bool mounted=true,shortWrite=false,open=false;
static size_t total=0;
unsigned millis(){return 1;} unsigned esp_random(){return 2;}
bool setupSdCard(){return mounted;}
struct File {
 explicit operator bool()const{return open;}
 void close(){open=false;} void flush(){}
 size_t write(const uint8_t*,size_t n){if(shortWrite)return n-1;total+=n;return n;}
};
struct Storage {
 bool exists(const char *p){return std::strstr(p,".csv")==nullptr;}
 bool mkdir(const char*){return true;}
 File open(const String&,int){::open=true;return {};}
} SD;
'''
        run_cpp('#include "'+core+'"\nusing namespace NrfBlackBox;\n'+stubs+
                function(source,'class Log {')+';'+r'''
int main(){
 {Log log;mounted=false;log.begin();assert(!open&&std::strstr(log.status,"no SD"));}
 mounted=true;
 {Log log;log.begin();assert(open);shortWrite=true;assert(!log.write("abc"));
  assert(!open&&std::strstr(log.status,"write failed"));}
 shortWrite=false;total=0;
 {Log log;log.begin();std::string block(1024*1024,'x');
  for(int i=0;i<17;++i)log.write(block.c_str());
  assert(!open&&total<=MaxLogBytes&&std::strstr(log.status,"cap"));}
 puts("SD missing, short-write and recording-cap tests passed");
}
''')


if __name__=='__main__':unittest.main()
