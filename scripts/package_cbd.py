"""Package the app-only CBD image, checked against its factory app partition."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = root / ".pio/build/ES3C28P"
    identity = json.loads((build / "source_identity.json").read_text())
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True).strip()
    if identity["dirty"] or dirty or identity["commit"] != commit:
        raise SystemExit("Refusing release: source or build identity is dirty/stale")
    image = (build / "firmware.bin").read_bytes()
    if image[0] != 0xE9 or int.from_bytes(image[12:14], "little") != 9:
        raise SystemExit("Not an ESP32-S3 application image")
    if identity["build_id"].encode() not in image:
        raise SystemExit("Embedded source identity does not match manifest")
    partition_file = root / "boards/ES3C28P/partitions_16Mb.csv"
    for row in csv.reader(partition_file.read_text().splitlines()):
        if row and not row[0].startswith("#") and len(row) >= 5 and row[2].strip() == "factory":
            size = int(row[4].strip(), 0)
            break
    else:
        raise SystemExit("No factory partition")
    if len(image) > size:
        raise SystemExit("Image exceeds app partition")
    args.output.mkdir(parents=True, exist_ok=True)
    name = "Bruce-ES3C28P-stable1-Launcher.bin"
    (args.output / name).write_bytes(image)
    dependencies = []
    for library in sorted((root / ".pio/libdeps/ES3C28P").iterdir()):
        if not library.is_dir():
            continue
        entry = {"directory": library.name}
        metadata = library / ".piopm"
        if metadata.exists():
            entry["package"] = json.loads(metadata.read_text())
        if (library / ".git").exists():
            entry["git"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=library, text=True).strip()
        dependencies.append(entry)
    digest = hashlib.sha256(image).hexdigest()
    identity.update({"file": name, "sha256": digest, "bytes": len(image),
                     "app_partition_bytes": size, "headroom_bytes": size - len(image),
                     "hardware_tested": False, "dependencies": dependencies})
    (args.output / "build-manifest.json").write_text(json.dumps(identity, indent=2) + "\n")
    (args.output / "SHA256SUMS.txt").write_text(f"{digest}  {name}\n")
    shutil.copyfile(root / "docs/es3c28p-stable1.md", args.output / "READ-ME.md")
    print(f"Packaged {name}: {len(image)} bytes, {size-len(image)} bytes headroom")


if __name__ == "__main__":
    main()
