"""Exercise production recon allocation, startup and target-picker lifetimes."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_ble_lifecycle import ROOT, function

SOURCE = (ROOT / 'src/modules/df/ble_recon_v3.cpp').read_text()


def run_cpp(code, flags=()):
    with tempfile.TemporaryDirectory() as d:
        cpp = Path(d) / 'test.cpp'
        cpp.write_text(code)
        exe = Path(d) / 'test'
        subprocess.run(['g++', '-std=c++11', '-Wall', '-Wextra', '-Werror', *flags,
                        str(cpp), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)


class ReconRamTest(unittest.TestCase):
    def test_modes_allocate_only_owned_buffers_and_unwind(self):
        definitions = SOURCE[SOURCE.index('constexpr uint32_t DISCOVERY_MS'):SOURCE.index('struct GattResult')]
        allocations = SOURCE[SOURCE.index('static HunterState *memHunter'):SOURCE.index('#define hunterState')]
        stubs = r'''
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <new>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
static size_t liveBytes=0, peakBytes=0;
static int allocCalls=0, failAt=0, releases=0;
static bool radio=false, stopOk=true, discoveryOk=true;
static std::map<void*,size_t> blocks;
template<class T> T* lazyRam(T*&p){
 if(p)return p;
 if(++allocCalls==failAt)return nullptr;
 void* raw=std::malloc(sizeof(T));assert(raw);
 blocks[raw]=sizeof(T);liveBytes+=sizeof(T);peakBytes=std::max(peakBytes,liveBytes);
 return p=new(raw)T();
}
template<class T> void releaseLazyRam(T*&p){
 if(!p)return;
 liveBytes-=blocks.at(p);blocks.erase(p);p->~T();std::free(p);p=nullptr;
}
struct NimBLEDevice {static bool isInitialized(){return radio;}};
void stopBLEStack(){if(stopOk)radio=false;}
void displayError(const char*,bool){}
'''
        # Keep the capture stub inside recon alongside the real association engine.
        stubs += '#include "' + str(ROOT / 'src/modules/df/recon_core.h') + '"\n'
        stubs += 'namespace recon {struct Capture {void release(){assert(!radio);++releases;}} capture;}\n'
        operations = allocations + r'''
int starts=0;
bool chooseReconTarget(bool, BleObservation &target){
 assert(liveBytes==0); // Radio startup must precede all working buffers.
 if(!discoveryOk)return false;
 radio=true;target.rssi=-42;return true;
}
void huntTarget(const BleObservation &target){assert(radio&&target.rssi==-42);assert(ensureReconRam(true));++starts;}
void sniffTarget(const BleObservation &target){assert(radio&&target.rssi==-42);assert(ensureReconRam(false));++starts;}
'''
        operations += function(SOURCE, 'void runReconSession(')
        tests = r'''
int main(){
 const size_t hunterBytes=2*sizeof(HunterState)+sizeof(recon::Association);
 const size_t snifferBytes=3*sizeof(SnifferState)+sizeof(recon::Association);
 const size_t oldBytes=hunterBytes+snifferBytes-sizeof(recon::Association);
 for(int repeat=0;repeat<5;++repeat){
  assert(ensureReconRam(true));assert(liveBytes==hunterBytes);
  assert(!memSniffer&&!memUiSniffer&&!memUiFrozen);
  releaseReconRam();assert(liveBytes==0);
  assert(ensureReconRam(false));assert(liveBytes==snifferBytes);
  assert(!memHunter&&!memUiHunter);
  releaseReconRam();assert(liveBytes==0);
 }
 for(bool hunter : {true,false})for(int fail=1;fail<=(hunter?3:4);++fail){
  allocCalls=0;failAt=fail;assert(!ensureReconRam(hunter));
  releaseReconRam();assert(liveBytes==0&&blocks.empty());
 }
 failAt=0;
 runReconSession(true);runReconSession(false);
 assert(starts==2&&!radio&&liveBytes==0);
 discoveryOk=false;runReconSession(true);assert(starts==2&&liveBytes==0);
 // A failed shutdown must retain memory still reachable by callbacks.
 {ReconSession session;assert(ensureReconRam(false));radio=true;stopOk=false;}
 assert(liveBytes==snifferBytes);
 stopOk=true;discoveryOk=true;runReconSession(true);
 assert(starts==3&&liveBytes==0);
#ifdef CONFIG_IDF_TARGET_ESP32
 static_assert(MAX_PAYLOAD==62 && MAX_RESPONSE==31,"Legacy ADV and response remain complete");
 assert(hunterBytes<5000&&snifferBytes<8000);
#else
 static_assert(MAX_PAYLOAD==256 && MAX_RESPONSE==128,"Extended-capable targets keep their buffers");
#endif
 printf("Recon RAM: Hunter %zu, Sniffer %zu, both-mode baseline %zu bytes; failure/retry cleanup passed\n",
        hunterBytes,snifferBytes,oldBytes);
}
'''
        for flags in (('-DCONFIG_IDF_TARGET_ESP32=1',), ()):
            run_cpp(stubs + definitions + operations + tests, flags)

    def test_picker_frees_list_before_tracking_and_propagates_failure(self):
        stubs = r'''
#include <cassert>
#include <cstdlib>
#include <functional>
#include <new>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
static void *targetAllocation=nullptr;static bool targetFreed=false;
void *operator new(size_t n){if(void*p=std::malloc(n))return p;throw std::bad_alloc();}
void operator delete(void*p)noexcept{if(p&&p==targetAllocation)targetFreed=true;std::free(p);}
void operator delete(void*p,size_t)noexcept{::operator delete(p);}
struct String:std::string{
 using std::string::string;
 String(const std::string&s):std::string(s){}
 String(int n):std::string(std::to_string(n)){}
 String substring(size_t n)const{return substr(n);}
};
String operator+(const char*a,const String&b){return String(std::string(a)+b);}
struct BleObservation {char name[41]{},address[18]{};int rssi=0;};
static unsigned choicesAlive=0,warnings=0;static bool discoveryOk=true,empty=false,returnToMenu=false;
static int selection=37;
struct Option {
 String label;std::function<void()> operation;
 Option(const String&l,std::function<void()>f):label(l),operation(f){++choicesAlive;}
 Option(const Option&o):label(o.label),operation(o.operation){++choicesAlive;}
 ~Option(){--choicesAlive;}
};
constexpr int MENU_TYPE_REGULAR=0;
void displayWarning(const char*,bool){++warnings;}
bool discoverTargets(bool,std::vector<BleObservation>&out){
 if(!discoveryOk)return false;if(empty)return true;
 out.resize(60);targetAllocation=out.data();targetFreed=false;
 for(unsigned i=0;i<out.size();++i){out[i].rssi=-int(i);std::strcpy(out[i].address,"11:22:33:44:55:66");}
 return true;
}
int loopOptions(std::vector<Option>&options,int,const char*,int,bool){
 assert(options.size()==61);assert(!targetFreed);
 if(selection>=0)options[selection].operation();return selection;
}
'''
        tests = r'''
int main(){
 BleObservation selected;
 assert(chooseReconTarget(true,selected)&&selected.rssi==-37);
 assert(targetFreed&&choicesAlive==0&&warnings==0);
 selection=-1;assert(!chooseReconTarget(false,selected)&&targetFreed&&choicesAlive==0);
 selection=60;assert(!chooseReconTarget(false,selected)&&returnToMenu&&choicesAlive==0);
 discoveryOk=false;assert(!chooseReconTarget(true,selected)&&warnings==0);
 discoveryOk=true;empty=true;assert(!chooseReconTarget(true,selected)&&warnings==1);
 puts("Target picker preserves selection, frees snapshots and preserves startup errors");
}
'''
        run_cpp(stubs + function(SOURCE, 'bool chooseReconTarget(') + tests,
                ('-Wno-misleading-indentation',))

    def test_recording_queue_released_even_without_open_file(self):
        source = (ROOT / 'src/modules/df/recon_capture.cpp').read_text()
        run_cpp(r'''
#include <cassert>
#include <cstdio>
static unsigned ends=0,deletes=0;
void vQueueDelete(void*p){assert(p);++deletes;}
struct Capture {
 void*queue=reinterpret_cast<void*>(1);
 void end(){++ends;}void release();
};
''' + function(source, 'void Capture::release(') + r'''
int main(){Capture c;c.release();assert(!c.queue&&ends==1&&deletes==1);
c.release();assert(!c.queue&&ends==2&&deletes==1);puts("Recording queue cleanup is idempotent");}
''')


if __name__ == '__main__':
    unittest.main()
