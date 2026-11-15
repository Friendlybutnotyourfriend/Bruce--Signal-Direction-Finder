"""Check Fenrir's exclusions against the linked ELF and record static RAM use."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
build = root / '.pio/build/fenrir-ebyte'
packages = Path.home() / '.platformio/packages'
nm = next(packages.glob('toolchain-xtensa*/bin/xtensa*-nm'))
size = nm.with_name(nm.name[:-2] + 'size')
elf = build / 'firmware.elf'
symbols = subprocess.check_output([str(nm), '-S', '-C', '--size-sort', str(elf)], text=True)
sections = subprocess.check_output([str(size), '-A', str(elf)], text=True)
for forbidden in ('LoRaMenu::', 'FMMenu::', 'IRMenu::', 'RFIDMenu::', 'EthernetMenu::',
                  'EthernetHelper::', 'ESPNetifEthernetClient::'):
    if forbidden in symbols:
        raise SystemExit(f'Excluded feature still linked: {forbidden}')
for directory in ('lora', 'fm', 'ir', 'rfid'):
    if list((build / 'src/modules' / directory).rglob('*.o')):
        raise SystemExit(f'Excluded module still compiled: {directory}')
ram = []
for line in symbols.splitlines():
    fields = line.split(None, 3)
    if len(fields) == 4 and fields[2] in 'bBdD':
        ram.append((int(fields[1], 16), fields[3]))
ram.sort(reverse=True)
report = ('Fenrir Lean1: excluded feature symbols and source objects absent.\n'
          'Static sections; runtime largest DMA block requires hardware measurement.\n\n'
          + sections + '\nLargest RAM symbols (bytes):\n'
          + '\n'.join(f'{count:8d}  {name}' for count, name in ram[:100]) + '\n')
out = root / '.pio/release'
out.mkdir(parents=True, exist_ok=True)
(out / 'Fenrir-memory.txt').write_text(report)
print(report)
