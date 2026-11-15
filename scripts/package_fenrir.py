"""Package classic ESP32 Fenrir images, checking both identity and flash limits."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--env', choices=['fenrir-ebyte', 'LAUNCHER_fenrir-ebyte'], required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
build = root / '.pio/build' / args.env
identity = json.loads((build / 'source_identity.json').read_text())
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
if identity['dirty'] or identity['commit'] != commit or identity['environment'] != args.env or subprocess.check_output(['git', 'status', '--porcelain'], cwd=root).strip():
    raise SystemExit('Dirty, stale or mismatched build')
app = (build / 'firmware.bin').read_bytes()
if len(app) < 256 or app[0] != 0xe9 or int.from_bytes(app[12:14], 'little') != 0:
    raise SystemExit('Not a classic ESP32 image')
if identity['build_id'].encode() not in app or identity['version'].encode() not in app:
    raise SystemExit('Embedded identity mismatch')
launcher = args.env.startswith('LAUNCHER_')
limit = 0x290000 if launcher else 0x3c0000
if len(app) > limit:
    raise SystemExit(f'App exceeds partition: {len(app)} > {limit}')
if launcher and 0x160000 + ((len(app) + 0xffff) & ~0xffff) + 0x10000 > 0x400000:
    raise SystemExit('Launcher plus aligned app and minimum settings storage exceeds 4 MB')
out = root / '.pio/release'
out.mkdir(parents=True, exist_ok=True)
variant = 'Launcher' if launcher else 'Full'
images = {f'Bruce-1.17-Fenrir-BlackBox-Stability1-{variant}-App.bin': app}
if not launcher:
    images['Bruce-1.17-Fenrir-BlackBox-Stability1-Full-USB.bin'] = (root / f'Bruce-{args.env}.bin').read_bytes()
manifest = dict(identity, hardware_tested=False, app_partition_bytes=limit, headroom_bytes=limit-len(app), files=[])
for name, data in images.items():
    (out / name).write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    manifest['files'].append(dict(name=name, bytes=len(data), sha256=sha))
    (out / (name+'.sha256')).write_text(f'{sha}  {name}\n')
(out / f'Fenrir-{variant}-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
(out / 'Fenrir-README.md').write_text((root / 'boards/fenrir-ebyte/README.md').read_text())
print(f'{variant}: {len(app)} bytes, {limit-len(app)} bytes spare')
