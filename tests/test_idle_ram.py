"""Exercise on-demand RF workspaces, allocation failure and ISR teardown."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_ble_lifecycle import ROOT, function
from test_radio_resources import run_cpp


class IdleRamTest(unittest.TestCase):
    def test_protocol_tracker_failure_and_retry(self):
        source = r'''
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
static int calls, failAt, live;
static void *test_calloc(size_t n,size_t s) {
 if(++calls==failAt)return NULL;
 void *p=calloc(n,s);if(p)++live;return p;
}
static void test_free(void *p){if(p)--live;free(p);}
static void *test_realloc(void *p,size_t n){
 if(++calls==failAt)return NULL;
 void *q=realloc(p,n);if(q&&!p)++live;return q;
}
#define calloc test_calloc
#define free test_free
#define realloc test_realloc
#include "src/modules/rf/protocols/rf_stream_memory.c"
#undef calloc
#undef free
#undef realloc
int main(void){
 assert(!allocated && live==0);
 for(int failure=1;failure<=3;++failure){
  calls=0;failAt=failure;rf_stream_memory_begin();
  if(setjmp(*rf_stream_memory_jump())==0){
   rf_stream_malloc(12);rf_stream_malloc(20);assert(0);
  }
  rf_stream_memory_finish(NULL);assert(live==0&&!allocated&&!active);
 }
 for(int round=0;round<3;++round){
  calls=0;failAt=0;rf_stream_memory_begin();assert(!allocated);
  assert(setjmp(*rf_stream_memory_jump())==0);
  void *a=rf_stream_calloc(3,4),*b=rf_stream_malloc(20);
  assert(allocated&&used==2&&total==32&&live==3);
  a=rf_stream_realloc(a,40);assert(total==60);
  rf_stream_free(b);assert(total==40&&used==1);
  rf_stream_memory_finish(a);assert(live==1&&!allocated&&!active);
  rf_stream_free(a);assert(live==0);
  rf_stream_memory_finish(NULL);assert(live==0);
 }
 calls=0;failAt=0;rf_stream_memory_begin();
 if(setjmp(*rf_stream_memory_jump())==0){
  void *p=rf_stream_malloc(12);failAt=calls+1;rf_stream_realloc(p,40);assert(0);
 }
 rf_stream_memory_finish(NULL);assert(live==0&&!allocated);
 calls=0;failAt=0;rf_stream_memory_begin();
 if(setjmp(*rf_stream_memory_jump())==0){
  for(int i=0;i<513;++i)rf_stream_malloc(1);assert(0);
 }
 assert(used==512);rf_stream_memory_finish(NULL);assert(live==0&&!allocated);
 calls=0;failAt=0;rf_stream_memory_begin();
 if(setjmp(*rf_stream_memory_jump())==0){rf_stream_calloc((size_t)-1,2);assert(0);}
 rf_stream_memory_finish(NULL);assert(live==0&&!allocated);
 puts("RF tracker allocation faults, limits, retained output and repeated cleanup passed");
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'tracker.c';exe=Path(d)/'tracker'
            c.write_text(source)
            subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',
                            '-fsanitize=address,undefined','-I',str(ROOT),str(c),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)

    def test_gpio_capture_buffer_lifecycle(self):
        source=(ROOT/'src/modules/rf/protocols/rf_decoder.cpp').read_text()
        funcs='\n'.join(function(source,s) for s in (
            'static bool rf_m5_buffer_acquire(', 'static void rf_m5_buffer_release(',
            'static void IRAM_ATTR rf_m5_edge_isr('))
        run_cpp(r'''
#include <cassert>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#define IRAM_ATTR
static int locked=0,freed=0,reads=0;
static bool fail=false;
static constexpr int MALLOC_CAP_INTERNAL=1,MALLOC_CAP_8BIT=2;
void *heap_caps_malloc(size_t n,int caps){assert(caps==3);return fail?nullptr:malloc(n);}
void heap_caps_free(void*p){assert(!locked);if(p)++freed;free(p);}
void lock(int*){assert(!locked);++locked;} void unlock(int*){assert(locked);--locked;}
#define portENTER_CRITICAL(p) lock(p)
#define portEXIT_CRITICAL(p) unlock(p)
#define portENTER_CRITICAL_ISR(p) lock(p)
#define portEXIT_CRITICAL_ISR(p) unlock(p)
static int rf_m5_mux=0;
static constexpr int RF_M5_BUFFER_COUNT=524,RF_M5_RX_GLITCH_US=220;
static int *rf_m5_buf=nullptr;
static bool rf_m5_active=false,rf_m5_last_level=false;
static uint32_t rf_m5_last_edge_us=0,tick=0;
static int rf_m5_count=0,rf_m5_ready_count=0,rf_m5_pin=22;
uint32_t micros(){assert(locked);return tick;}
bool digitalRead(int pin){assert(locked&&pin==22);++reads;return true;}
''' + funcs + r'''
int main(){
 fail=true;assert(!rf_m5_buffer_acquire()&&!rf_m5_buf);
 fail=false;assert(rf_m5_buffer_acquire());int *first=rf_m5_buf;
 assert(rf_m5_buffer_acquire()&&first==rf_m5_buf);
 rf_m5_active=true;tick=100;rf_m5_edge_isr();assert(rf_m5_count==0&&!locked);
 tick=500;rf_m5_edge_isr();assert(rf_m5_count==1&&rf_m5_buf[0]==-500&&!locked);
 for(int i=1;i<=RF_M5_BUFFER_COUNT;++i){tick+=500;rf_m5_edge_isr();}
 assert(rf_m5_ready_count==RF_M5_BUFFER_COUNT&&!locked);
 rf_m5_buffer_release();assert(!rf_m5_buf&&!rf_m5_active&&freed==1);
 int before=reads;rf_m5_edge_isr();assert(reads==before&&!locked);
 rf_m5_buffer_release();assert(freed==1);
 assert(rf_m5_buffer_acquire());rf_m5_buffer_release();assert(freed==2);
 puts("GPIO capture OOM, retry, bounds and stopped-ISR cleanup passed");
}
''')
