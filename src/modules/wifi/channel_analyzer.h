#pragma once

#if !defined(LITE_VERSION) || defined(FENRIR_RECON_LITE)

// Real-time 2.4GHz channel utilization analyzer.
// Hops channels 1-11 in promiscuous mode, estimates per-channel airtime load,
// and draws solid-threshold bars with load %, peak hold and a signal meter.
void channel_analyzer_setup();

#endif
