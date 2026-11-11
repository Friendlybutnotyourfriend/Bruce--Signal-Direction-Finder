# RF Lab v1

Entry: RF -> RF Black Box / Finder. Based on the combined E32R28T branch
437538ef81984bd8e3dc430b94cd40cb10522f5a.

## Operation

1. Select a frequency matching the connected CC1101 module and antenna.
2. Start Black Box with an SD card mounted. Keep the source quiet during baseline
   learning (128 samples, nominally 2.56 seconds).
3. The detector uses the baseline lower quartile + 10 dB, requires two consecutive
   above-threshold samples, and rearms after 500 ms below threshold minus 3 dB.
4. Each trigger saves up to 64 preceding samples and 32 samples beginning at the
   trigger. The threshold is frozen for that session. Stop with ESC. A partially
   collected event is saved with `partial:true`. The run stops at 100 events or a
   write failure. A separate activity-end record gives the observed above-threshold
   span and peak RSSI, including sustained activity; stopping marks unfinished spans
   partial. These are sampled spans, not calibrated airtime. Logs reside in `/RF-Lab` on SD; no continuous internal-flash writes.
5. Review events, select one, then run Profile Finder while the original source
   repeatedly transmits. This is live receiver experimentation, not offline
   re-demodulation of the saved RSSI log.
6. Finder tests OOK, 2-FSK and GFSK at 1.2/4.8/9.6 kBaud and requested
   58.0357/203.125 kHz bandwidths: 18 configurations, two 2-second passes in reverse
   order (~75 seconds). Adjust the Finder energy gate if needed.
7. Select a ranked candidate to use in Black Box or save its settings, both pulse
   histograms and one signed pulse example. Load the JSONL profile later to reuse
   it. Global Radio Control preferences and TX power remain unchanged.

## Meaning and limits

- CC1101 only. E07 targets retain their 425–450.5 MHz restriction. Other targets
  accept only the three documented CC1101 bands. This is fixed-frequency monitoring,
  not a simultaneous band survey, BLE scanner, SDR or protocol decoder.
- Black Box records sampled RSSI only, not raw pulses or IQ. Sample timestamps and
  maximum observed gaps expose display/storage pauses. Short bursts can be missed.
  A continuously occupied channel during learning may not produce an event.
- Uptime milliseconds wrap at 2^32; exports are not UTC timestamps. Separate files
  distinguish sessions. Session filenames include a random ID and collision handling.
- Finder uses hardware RMT (1 us resolution, 20 us glitch filter, 12 ms idle split).
  Segments are not proven protocol frames. Buffers are bounded at 128 RMT symbols;
  full-buffer captures are flagged and excluded from scoring. This v1 targets slow,
  repetitive bursts, not continuous or high-rate traffic.
- Energy is sampled every 5 ms and associated with a capture segment. It is not
  per-pulse RSSI and can miss very short bursts or include unrelated energy.
- A candidate needs at least two segments and 32 pulses in each pass. Score is pulse
  histogram overlap multiplied by concentration in the three dominant bins. Any
  clipping or diffuse distributions reject the candidate. Structured noise can still
  score well. Scores are NOT probabilities, device fingerprints or verified modulation.
  GFSK and 2-FSK can remain indistinguishable; ties are not broken into false certainty.
- Infrequent or changing transmissions require longer observation/a rerun. No evidence
  is reported explicitly rather than making up an identity. An observed pulse period
  is not automatically the symbol rate.
- Saved settings are requested driver inputs, not calibrated/independently measured
  bandwidth or data rate. Profiles never change persistent transmit settings.
- JSONL exports can be compared manually with protocol documentation/online sources.
  There is no automatic online matching service or built-in device identification.

## Verification

Host core test:

```
g++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined tests/rf_lab_core_test.cpp -o /tmp/rf_lab_core_test
ASAN_OPTIONS=detect_leaks=0 /tmp/rf_lab_core_test
```

Leak detection is disabled only because the execution host uses ptrace. Address and
undefined-behaviour checks remain enabled. Tests cover ring ordering, baseline,
trigger/rearm/hysteresis, timer wrap, insufficient evidence, clipping, diffuse noise
and similar/dissimilar pulse distributions.

Hardware acceptance still required: repeatable known OOK/FSK source, no-source noise,
ESC during capture, SD removal/full card, shared SPI display/SD, profile reload,
100-event limit, repeated entry/exit, and normal existing RF tool use after exit.
