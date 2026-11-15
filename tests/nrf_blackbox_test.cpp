#include "../src/modules/NRF24/blackbox_core.h"
#include <cassert>
#include <cstdio>
using namespace NrfBlackBox;
int main() {
    Frame f;
    f.sample(Channels, true);
    assert(!f.hasSamples() && f.percent(Channels) == 0);
    f.sample(83, true); f.sample(83, false);
    assert(f.percent(83) == 50 && f.peak() == 83);
    f.samples[3] = 65535; f.hits[3] = 65535;
    f.sample(3, true);
    assert(f.saturated && f.samples[3] == 65535 && f.percent(3) == 100);
    Recorder r(0xfffffff0u);
    assert(!r.due(0x10u));
    assert(r.due(0x3e0u));
    for (int i=0;i<10;++i) r.current.sample(5,false);
    const auto &a=r.finish(0x3e0u);
    assert(a.spanMs==1008 && !a.rise);
    for (int i=0;i<10;++i) r.current.sample(5,i<4);
    r.current.marker=true;
    const auto &b=r.finish(0x7c8u);
    assert(b.rise && b.marker && b.percent(5)==40);
    assert(!r.current.marker && !r.current.hasSamples());
    for (unsigned i=0;i<HistoryFrames+4;++i) {
        r.current.sample(i%Channels,true);
        r.finish(3000+i*1000);
    }
    assert(r.count()==HistoryFrames && !r.ago(HistoryFrames));
    assert(r.ago(0)->startMs>r.ago(HistoryFrames-1)->startMs);
    assert(fitsLog(MaxLogBytes-1,1) && !fitsLog(MaxLogBytes,1));
    assert(!fitsLog(size_t(-1),1) && !fitsLog(1,size_t(-1)));
    static_assert(sizeof(Recorder)<6000,"Keep bounded working memory on classic ESP32");
    std::puts("nRF Black Box boundary, saturation, rollover, event and history tests passed");
}
