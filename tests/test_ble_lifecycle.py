"""Compile the production lifecycle functions against a deterministic SDK model."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    begin = source.index(signature)
    brace = source.index('{', begin)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[begin:end]


class LifecycleTest(unittest.TestCase):
    def test_real_helpers_with_sdk_failures(self):
        source = (ROOT / 'src/modules/ble/ble_common.cpp').read_text()
        stubs = r'''
#include <cassert>
#include <string>
#include <cstdio>
#define CONFIG_IDF_TARGET_ESP32 1
using std::string;
static bool budget=true, initOk=true, deinitOk=true;
static unsigned initCalls=0, guardCalls=0, wifiStops=0, hookCalls=0, resets=0;
static bool returnToMenu=false;
constexpr bool FORCE_RADIO_TEARDOWN_ON_SWITCH=true;
struct Scan { void stop(){assert(false);} void clearResults(){assert(false);} };
static Scan *pBLEScan=nullptr;
static void *pServer=nullptr,*pService=nullptr,*pTxCharacteristic=nullptr,*pRxCharacteristic=nullptr;
static bool deviceConnected=false,oldDeviceConnected=false,bleDataTransferEnabled=false,BLEConnected=false;
static unsigned hidDeletes=0;
struct Hid { void end(); ~Hid(); }; static Hid *hid_ble=nullptr; int activeBLEInstances=0;
struct SerialType { void println(const char*){} } Serial;
void displayError(const char*,bool){}
void cleanlyStopWebUiForWiFiFeature(){}
void wifiDisconnect(){++wifiStops;}
bool radioHasMemForBle(){++guardCalls;return budget;}
constexpr size_t RADIO_BLE_MIN_DMA_BLOCK=48*1024;
size_t radioLargestDmaBlock(){return budget?64*1024:32*1024;}
enum Status { ESP_BT_CONTROLLER_STATUS_IDLE, ESP_BT_CONTROLLER_STATUS_INITED, ESP_BT_CONTROLLER_STATUS_ENABLED };
static Status controller=ESP_BT_CONTROLLER_STATUS_IDLE;
Status esp_bt_controller_get_status(){return controller;}
void esp_bt_controller_disable(){controller=ESP_BT_CONTROLLER_STATUS_INITED;}
void esp_bt_controller_deinit(){controller=ESP_BT_CONTROLLER_STATUS_IDLE;}
struct BLEDevice {
 static bool active;
 static bool isInitialized(){return active;}
 static bool init(const std::string&){++initCalls;controller=ESP_BT_CONTROLLER_STATUS_ENABLED;active=initOk;return initOk;}
 static bool deinit(bool){if(!deinitOk)return false;active=false;controller=ESP_BT_CONTROLLER_STATUS_IDLE;return true;}
}; bool BLEDevice::active=false;
bool bruceBleDeinit(bool);
void Hid::end(){bruceBleDeinit(true);}
Hid::~Hid(){assert(!BLEDevice::active);++hidDeletes;}
using HIDInterface=Hid;
using BleKeyboard=Hid;
using NimBLEDevice=BLEDevice;
struct BLEStateManager {static void resetState(){++resets;}};
static void (*shutdownHook)()=nullptr;
void hook(){++hookCalls;assert(!BLEDevice::active);}
'''
        bodies = '\n'.join(function(source, x) for x in [
            'void bruceBleShutdownHook(', 'bool bruceBleDeinit(',
            'void stopBLEStack(', 'bool bruceBleInit('])
        bodies += function((ROOT / 'src/modules/badusb_ble/ducky_typer.cpp').read_text(),
                           'void cleanupDuckyBLE(')
        tests = r'''
int main(){
 budget=false;
 assert(!bruceBleInit("scan") && initCalls==0 && !returnToMenu);
 BLEDevice::active=true;
 assert(bruceBleInit("reuse") && guardCalls==1 && initCalls==0);
 bruceBleShutdownHook(hook);
 // A stale application scan pointer must never be dereferenced during shutdown.
 pBLEScan=reinterpret_cast<Scan*>(1);
 stopBLEStack();
 assert(!BLEDevice::active && pBLEScan==nullptr && hookCalls==1 && resets==1);
 budget=true;initOk=false;
 assert(!bruceBleInit("failure") && controller==ESP_BT_CONTROLLER_STATUS_IDLE);
 initOk=true;assert(bruceBleInit("restart"));
 deinitOk=false;
 pBLEScan=reinterpret_cast<Scan*>(1);
 assert(!bruceBleDeinit(true) && BLEDevice::active && pBLEScan!=nullptr);
 deinitOk=true;assert(bruceBleDeinit(true));
 assert(bruceBleInit("another restart"));
 hid_ble=new Hid;activeBLEInstances=1;deinitOk=false;
 stopBLEStack();
 assert(hid_ble && hidDeletes==0 && activeBLEInstances==1);
 deinitOk=true;stopBLEStack();
 assert(!hid_ble && hidDeletes==1 && activeBLEInstances==0);
 assert(bruceBleInit("HID cleanup"));
 hid_ble=new Hid;activeBLEInstances=1;deinitOk=false;
 cleanupDuckyBLE(hid_ble);
 assert(hid_ble && hidDeletes==1 && activeBLEInstances==1);
 deinitOk=true;cleanupDuckyBLE(hid_ble);
 assert(!hid_ble && hidDeletes==2 && activeBLEInstances==0);
 puts("BLE lifecycle failure, reuse, HID ownership and restart tests passed");
}
'''
        with tempfile.TemporaryDirectory() as d:
            cpp = Path(d) / 'test.cpp'
            cpp.write_text(stubs + bodies + tests)
            exe = Path(d) / 'test'
            subprocess.run(['g++', '-std=c++11', '-Wall', '-Wextra', '-Werror',
                            str(cpp), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    unittest.main()
