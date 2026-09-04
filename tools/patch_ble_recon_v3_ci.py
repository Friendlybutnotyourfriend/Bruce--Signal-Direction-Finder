from pathlib import Path

p = Path("src/modules/df/ble_recon_v3.cpp")
s = p.read_text()

old = 'o.legacy=device->isLegacyAdvertisement();if(!o.legacy){o.sid=device->getSetId();o.primaryPhy=device->getPrimaryPhy();o.secondaryPhy=device->getSecondaryPhy();o.periodicInterval=device->getPeriodicInterval();o.dataStatus=device->getDataStatus();}'
new = 'o.legacy=device->isLegacyAdvertisement();'
if old not in s:
    raise SystemExit("extended metadata block not found")
s = s.replace(old, new, 1)

old = 'tft.drawCentreString(lost?"TARGET QUIET":String(s.target.rssi)'
new = 'tft.drawCentreString(lost?String("TARGET QUIET"):String(s.target.rssi)'
if old not in s:
    raise SystemExit("TARGET QUIET ternary not found")
s = s.replace(old, new, 1)

p.write_text(s)
print("Applied CI compatibility patch to BLE Recon v3")
