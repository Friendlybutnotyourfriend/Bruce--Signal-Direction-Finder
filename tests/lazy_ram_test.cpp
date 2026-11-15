#include <cassert>
#include <cstdlib>
#include <cstdio>
#include "core/lazy_ram.h"
static int outstanding=0, constructed=0, destroyed=0;
void *heap_caps_malloc(size_t n, unsigned caps) {
    if (caps & MALLOC_CAP_SPIRAM) return nullptr;
    void *p=std::malloc(n); if(p) ++outstanding; return p;
}
void heap_caps_free(void *p){if(p){--outstanding;std::free(p);}}
struct Item { Item(){++constructed;} ~Item(){++destroyed;} };
int main(){
 Item *one=nullptr,*many=nullptr;
 assert(lazyRam(one)); assert(lazyRam(one));
 assert(constructed==1 && outstanding==1);
 assert(lazyRamArray(many,20));
 releaseLazyRam(one); releaseLazyRamArray(many,20);
 releaseLazyRam(one); releaseLazyRamArray(many,20);
 assert(!one && !many && outstanding==0 && constructed==destroyed);
 assert(!lazyRamArray(many,0));
 struct Large {char bytes[2];}; Large *overflow=nullptr;
 assert(!lazyRamArray(overflow,size_t(-1)));
 puts("Lazy RAM destruction, release, repeated cleanup and overflow tests passed");
}
