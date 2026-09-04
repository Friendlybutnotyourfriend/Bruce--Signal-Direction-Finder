# BLE Recon Phase 1/2 test sheet

This branch is stacked on `agent/ble-hunter-v2` and is intended for hardware validation before Phase 3.

## Hunter

- Passive discovery only on entry.
- Select a target and leave it stationary for baseline learning.
- Verify advertised name and address type are shown.
- Move the target and verify WARMER/COLDER/STEADY behaviour.
- Temporarily shield/remove the target from RF and verify TARGET LOST, then REACQUIRED.
- Force or wait for an RPA rotation and verify address history / handoff score.
- In a crowded BLE environment, verify the best candidate wins only with repeated hits and a score margin.
- Use details view to record stable/volatile bytes, service hash, shape hash and candidate scores.

## Sniffer

- Passive discovery only on entry.
- Plain view: identity, MAC/address type, RSSI, connectability, payload length.
- AD Fields: generic TLV decode, malformed-field rejection, UUID/service labels.
- Raw: advertisement and scan-response hex.
- Mutation: changed-byte offsets, stable/volatile count, counter-like detection.
- Google Service (FCF1): verify payload length, first/last seen, count, MAC changes, payload changes, correlated MAC+payload changes, MAC-only and payload-only changes.
- Active Scan: only after confirmation; verify scan-response capture.
- GATT: only after confirmation; verify structure/properties are mapped and no characteristic values are read/written/subscribed.
- Extended advertising: verify legacy/extended, SID, PHY, data status and periodic interval when a suitable advertiser is available.

## Deployment

CI targets exactly:

- NM-CYD-C5
- ES3C28P 2.8in Cheap Black Display
- LilyGO T-Embed CC1101 Plus

CI pins the displayed Bruce version to 1.12.4 and enables NimBLE extended advertising with `MYNEWT_VAL_BLE_EXT_ADV=1` while preserving the normal global build flags.

Artifacts are **Launcher-only** images: partition table at `0x8000` plus Bruce application at `0x10000`, with **no bootloader**. They are intended to be installed through bmorcelli's Launcher so the existing Launcher/bootloader/partition-table installation boundary is preserved.

CI also uploads a per-board build log so any compile failure can be corrected without guessing at the runner output.
