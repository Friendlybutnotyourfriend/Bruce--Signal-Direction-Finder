"""Validate and package each native 1.17 app image for Launcher."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess

TARGETS = {
    'ES3C28P': ('CBD-2.8-ES3C28P', 'boards/ES3C28P/partitions_16Mb.csv'),
    'm5stack-cardputer': ('Cardputer-ADV', 'custom_8Mb.csv'),
    'lilygo-t-embed-cc1101': ('T-Embed-CC1101', 'custom_16Mb.csv'),
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--env', choices=TARGETS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = root / '.pio/build' / args.env
    identity = json.loads((build / 'source_identity.json').read_text())
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).strip()
    if identity['dirty'] or dirty or identity['commit'] != commit or identity['environment'] != args.env:
        raise SystemExit('Refusing dirty, stale or mismatched build')
    image = (build / 'firmware.bin').read_bytes()
    if len(image) < 256 or image[0] != 0xE9 or int.from_bytes(image[12:14], 'little') != 9:
        raise SystemExit('Not an ESP32-S3 app image')
    if identity['build_id'].encode() not in image or identity['version'].encode() not in image:
        raise SystemExit('Embedded identity mismatch')
    label, partitions = TARGETS[args.env]
    sizes = [int(row[4].strip(), 0) for row in csv.reader((root / partitions).read_text().splitlines())
             if row and not row[0].startswith('#') and len(row) >= 5 and row[1].strip() == 'app']
    size = min(sizes)
    if len(image) > size:
        raise SystemExit(f'App exceeds partition: {len(image)} > {size}')
    args.output.mkdir(parents=True, exist_ok=True)
    name = f'Bruce-1.17-native1-{label}-Launcher.bin'
    (args.output / name).write_bytes(image)
    digest = hashlib.sha256(image).hexdigest()
    identity.update(file=name, sha256=digest, bytes=len(image), app_partition_bytes=size,
                    headroom_bytes=size-len(image), hardware_tested=False, image_type='application-only')
    (args.output / f'{label}-manifest.json').write_text(json.dumps(identity, indent=2)+'\n')
    (args.output / f'{label}-SHA256.txt').write_text(f'{digest}  {name}\n')
    print(f'{name}: {len(image)} bytes; partition headroom {size-len(image)} bytes')

if __name__ == '__main__':
    main()
