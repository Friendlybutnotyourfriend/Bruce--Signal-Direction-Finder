#!/usr/bin/env python3
"""Offline BLE session inspection, C++ engine replay, comparison and VNA import. Standard library only."""
import argparse
import csv
import html
import json
import math
import re
from pathlib import Path
import statistics
import subprocess


def read_session(path):
    rows, warnings = [], []
    with Path(path).open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if len(rows) >= 200000:
                warnings.append("Review limited to the first 200000 records; split the session for full analysis")
                break
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("record must be an object")
                if row.get("type") == "observation":
                    payload = bytes.fromhex(row["payload"])
                    if len(payload) > 256 or not -127 <= int(row["rssi"]) <= 20:
                        raise ValueError("invalid observation bounds")
                    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", row["address"]) or not 0 <= int(row["address_type"]) <= 3:
                        raise ValueError("invalid address")
                    if not 0 <= int(row["ms"]) <= 0xffffffff or not 0 <= int(row["us"]) <= 0xffffffffffffffff:
                        raise ValueError("invalid timestamp")
                    if not 0 <= int(row.get("adv_len", 0)) <= len(payload):
                        raise ValueError("invalid advertising boundary")
                rows.append(row)
            except (ValueError, KeyError, TypeError) as exc:
                warnings.append(f"line {line_no}: {exc}")
    if not rows or rows[0].get("type") != "header" or rows[0].get("schema") != 1:
        raise ValueError("missing/unsupported session header")
    footer = next((r for r in reversed(rows) if r.get("type") == "footer"), None)
    if not footer:
        warnings.append("Incomplete session: no footer (power loss or recording still active)")
    elif footer.get("dropped") or footer.get("truncated") or footer.get("write_error"):
        warnings.append(f"Capture limitations: {footer}")
    return rows, warnings


def decoded_fields(payload):
    """Canonical AD fields, complete raw values; repeated types retained and sorted."""
    fields, off = {}, 0
    while off < len(payload):
        size = payload[off]
        if not size:
            break
        if off + size + 1 > len(payload):
            fields.setdefault("malformed", []).append(payload[off:].hex())
            break
        kind = payload[off + 1]
        value = payload[off + 2: off + size + 1]
        off += size + 1
        if 2 <= kind <= 7:
            width = 2 if kind <= 3 else 4 if kind <= 5 else 16
            key = f"AD{kind | 1:02x}"
            fields.setdefault(key, []).extend(value[i:i+width].hex() for i in range(0, len(value), width))
        else:
            fields.setdefault(f"AD{kind:02x}", []).append(value.hex())
    return {key: sorted(values) for key, values in sorted(fields.items())}


def summarize(rows, address=None):
    observations = [r for r in rows if r.get("type") == "observation" and (not address or r["address"].lower() == address.lower())]
    devices, changes, omitted_changes = {}, [], 0
    for r in observations:
        key = f'{r["address"]}/{r["address_type"]}'
        data = bytes.fromhex(r["payload"])
        fields = decoded_fields(data)
        item = devices.setdefault(key, {"rssi": [], "packets": 0, "first_us": r["us"], "last_us": 0, "fields": {}, "raw": b""})
        if item["packets"]:
            keys = set(fields) | set(item["fields"])
            changed = sorted(k for k in keys if fields.get(k) != item["fields"].get(k))
            raw = item["raw"]
            offsets = [i for i in range(max(len(raw), len(data))) if raw[i:i+1] != data[i:i+1]]
            if offsets:
                if len(changes) < 5000:
                    changes.append({"us": r["us"], "device": key, "fields": changed, "raw_offsets": offsets})
                else:
                    omitted_changes += 1
        item["packets"] += 1
        item["rssi"].append(r["rssi"])
        item["last_us"] = r["us"]
        item["fields"], item["raw"] = fields, data
    for item in devices.values():
        item["median_rssi_dbm"] = statistics.median(item.pop("rssi"))
        del item["raw"]
    return {"devices": devices, "changes": changes, "omitted_changes": omitted_changes, "events": [r for r in rows if r.get("type") == "event"],
            "handoffs": [r for r in observations if r.get("decision") == 3]}


def render_html(summary, warnings, rows, destination):
    # Escape all captured strings. No network, imports or remote dependencies in the report.
    blocks = ["<!doctype html><meta charset=utf-8><title>Bruce session review</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;background:#101722;color:#e3eaf3}details{padding:12px;border:1px solid #435067;margin:12px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}svg{width:100%;height:160px;background:#1b2637}a{color:#69dcca}</style><h1>Bruce session review</h1>",
              "<p>RSSI trends and advertising evidence. Address associations are hypotheses; RSSI is not distance.</p>"]
    for warning in warnings:
        blocks.append(f"<p>{html.escape(warning)}</p>")
    if summary.get("omitted_changes"):
        blocks.append(f'<p>Detailed change list capped at 5000; {summary["omitted_changes"]} further changes omitted.</p>')
    for key, device in summary["devices"].items():
        selected = [r for r in rows if r.get("type") == "observation" and f'{r["address"]}/{r["address_type"]}' == key]
        start, end = device["first_us"], device["last_us"]
        stride = max(1, len(selected)//2000)
        points = " ".join(f'{10 + 980*(r["us"]-start)/max(1,end-start):.1f},{145-(max(-110,min(-20,r["rssi"]))+110)*1.4:.1f}' for r in selected[::stride])
        blocks.append(f'<details open><summary>{html.escape(key)} — {device["packets"]} reports, median {device["median_rssi_dbm"]} dBm</summary><svg viewBox="0 0 1000 160" role="img" aria-label="RSSI over elapsed time, minus 110 to minus 20 dBm"><polyline fill="none" stroke="#69dcca" stroke-width="2" points="{points}"/></svg><pre>{html.escape(json.dumps(device,indent=2))}</pre></details>')
    blocks.append(f'<details><summary>Field and raw-byte changes ({len(summary["changes"])})</summary><pre>{html.escape(json.dumps(summary["changes"], indent=2))}</pre></details>')
    blocks.append(f'<details><summary>Bookmarks and events</summary><pre>{html.escape(json.dumps(summary["events"],indent=2))}</pre></details>')
    Path(destination).write_text("\n".join(blocks), encoding="utf-8")


def vna_points(path):
    path = Path(path)
    points = []
    if path.suffix.lower() == ".s1p":
        unit, fmt, parameter = "GHZ", "MA", "S"
        for no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            line = raw.split("!", 1)[0].strip()
            if not line:
                continue
            if line.startswith("#"):
                tokens = line[1:].upper().split()
                if len(tokens) < 3:
                    raise ValueError(f"line {no}: invalid Touchstone option line")
                unit, parameter, fmt = tokens[:3]
                continue
            if line.startswith("["):
                raise ValueError("Touchstone 2.0 is not supported; export a Touchstone 1.x S1P")
            values = [float(x) for x in line.split()]
            if len(values) != 3 or not all(math.isfinite(x) for x in values):
                raise ValueError(f"line {no}: expected frequency and S11 pair")
            if parameter != "S" or unit not in {"HZ", "KHZ", "MHZ", "GHZ"} or fmt not in {"RI", "MA", "DB"}:
                raise ValueError("requires S parameters and RI, MA or DB format")
            freq, a, b = values
            if fmt == "DB" and a >= 0:
                raise ValueError(f"line {no}: passive S11 dB must be negative")
            freq *= {"HZ": 1e-6, "KHZ": 1e-3, "MHZ": 1, "GHZ": 1e3}[unit]
            rho = math.hypot(a, b) if fmt == "RI" else a if fmt == "MA" else 10 ** (a / 20)
            if freq <= 0 or not 0 <= rho < 1:
                raise ValueError(f"line {no}: passive S11 magnitude must be >=0 and <1")
            rl = -20 * math.log10(rho) if rho else float("inf")
            points.append((freq, rl, (1 + rho) / (1 - rho)))
    else:
        with path.open(newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                freq = float(row["frequency_mhz"]) if "frequency_mhz" in row else float(row["frequency_hz"]) / 1e6
                if "return_loss_db" in row:
                    rl = float(row["return_loss_db"])
                    if not math.isfinite(rl) or rl <= 0:
                        raise ValueError("return_loss_db must be positive and finite")
                    rho = 10 ** (-rl / 20)
                    if rho >= 1:
                        raise ValueError("return loss too close to zero to compute finite VSWR")
                    vswr = (1 + rho) / (1 - rho)
                    if row.get("vswr") and not math.isclose(float(row["vswr"]), vswr, rel_tol=.02):
                        raise ValueError("return loss and VSWR columns disagree")
                else:
                    vswr = float(row["vswr"])
                    if not math.isfinite(vswr) or vswr < 1:
                        raise ValueError("VSWR must be finite and >=1")
                    rho = (vswr - 1)/(vswr + 1)
                    rl = -20*math.log10(rho) if rho else float("inf")
                if not math.isfinite(freq) or freq <= 0:
                    raise ValueError("invalid frequency")
                points.append((freq, rl, vswr))
    if not points:
        raise ValueError("no VNA samples")
    return sorted(points)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser("report"); report.add_argument("session"); report.add_argument("--address"); report.add_argument("--html")
    compare = commands.add_parser("compare"); compare.add_argument("left"); compare.add_argument("right"); compare.add_argument("--left-address"); compare.add_argument("--right-address")
    replay = commands.add_parser("replay"); replay.add_argument("session"); replay.add_argument("--engine", required=True); replay.add_argument("--target")
    vna = commands.add_parser("vna"); vna.add_argument("input"); vna.add_argument("output"); vna.add_argument("--calibration-note", required=True)
    args = parser.parse_args()
    if args.command == "vna":
        points = vna_points(args.input)
        with Path(args.output).open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f); writer.writerow(["frequency_mhz", "return_loss_db", "vswr"]); writer.writerows(points)
        Path(args.output + ".meta.json").write_text(json.dumps({"source": str(args.input), "calibration_note": args.calibration_note, "calibration_verified_by_software": False}, indent=2), encoding="utf-8")
        print(f"Imported {len(points)} S11 points; place CSV in SD:/AntennaProfiles. Calibration is user supplied.")
        return
    if args.command == "compare":
        left, lw = read_session(args.left); right, rw = read_session(args.right)
        a, b = summarize(left, args.left_address), summarize(right, args.right_address)
        print(json.dumps({"left": a, "right": b, "warnings": lw + rw, "note": "Choose address filters for device comparison; different addresses are not assumed to be the same device."}, indent=2))
        return
    rows, warnings = read_session(args.session)
    if args.command == "report":
        summary = summarize(rows, args.address)
        if args.html:
            render_html(summary, warnings, rows, args.html)
        print(json.dumps({**summary, "warnings": warnings}, indent=2))
    else:
        target = args.target or rows[0]["target"]
        started, lines = False, []
        for row in rows:
            if started and row.get("type") == "event" and row.get("kind") in {"resume", "lock_toggle", "undo"}:
                lines.append(f'! {(row["us"] // 1000) & 0xffffffff} {row["kind"]}')
            if row.get("type") != "observation":
                continue
            if not started and row["address"].lower() != target.lower():
                continue
            started = True
            data = bytes.fromhex(row["payload"])
            length = row.get("adv_len", 0) or len(data)
            truncated = row.get("original_len", len(data)) > len(data) or row.get("data_status", 0) != 0
            lines.append(f'{row["ms"]} {row["address"]} {row["address_type"]} {row["rssi"]} {int(row["adv_type"] == 4)} {int(truncated)} {data[:length].hex() or "-"}')
        if not started:
            raise ValueError("selected target has no observations")
        result = subprocess.run([args.engine], input="\n".join(lines), text=True, capture_output=True, check=True)
        print(result.stdout, end="")
        for warning in warnings:
            print("WARNING:", warning, file=__import__("sys").stderr)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from exc
