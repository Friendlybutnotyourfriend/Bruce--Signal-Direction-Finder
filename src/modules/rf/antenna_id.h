#ifndef __ANTENNA_ID_H__
#define __ANTENNA_ID_H__

// Native antenna response surveys.
//
// These are receive-only ambient RF classifiers. They do not measure
// impedance, return loss, SWR, or antenna resonance.
void rf_antenna_id();
void rf_antenna_id_subghz();
void rf_antenna_id_24ghz();

#endif
