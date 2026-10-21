import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recon_session", ROOT / "tools/recon_session.py")
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def file(self, name, text):
        p = self.root / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_reordered_fields_not_decoded_changes(self):
        a = bytes.fromhex("03030f180409616263")
        b = bytes.fromhex("040961626303030f18")
        self.assertEqual(session.decoded_fields(a), session.decoded_fields(b))
        rows = [dict(type="observation", address="aa:bb:cc:dd:ee:ff", address_type=1, rssi=-55, us=i, payload=p.hex()) for i, p in enumerate((a,b))]
        result = session.summarize(rows)
        self.assertEqual(result["changes"][0]["fields"], [])
        self.assertTrue(result["changes"][0]["raw_offsets"])

    def test_length_removal_is_a_change(self):
        rows = [dict(type="observation", address="aa:bb:cc:dd:ee:ff", address_type=1, rssi=-55, us=i, payload=p) for i,p in enumerate(("0409616263", ""))]
        result = session.summarize(rows)
        self.assertEqual(result["changes"][0]["fields"], ["AD09"])
        self.assertEqual(len(result["changes"][0]["raw_offsets"]), 5)

    def test_partial_capture_reports_error(self):
        p = self.file("partial.jsonl", '{"type":"header","schema":1}\n{"type":')
        rows, warnings = session.read_session(p)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(warnings), 2)

    def test_capture_loss_is_visible(self):
        p = self.file("lost.jsonl", '\n'.join(json.dumps(r) for r in [dict(type="header",schema=1),dict(type="footer",dropped=32,truncated=2)]))
        _, warnings = session.read_session(p)
        self.assertIn("32", warnings[0])

    def test_untrusted_text_escaped_in_html(self):
        p = self.root / "report.html"
        session.render_html({"devices": {}, "changes": [], "events": [{"detail":"<script>alert(1)</script>"}]}, [], [], p)
        self.assertNotIn("<script>", p.read_text())
        self.assertIn("&lt;script&gt;", p.read_text())

    def test_vna_units_and_formats(self):
        for fmt, pair in [("RI","0.1 0"),("MA","0.1 90"),("DB","-20 90")]:
            p = self.file("input.s1p", f"! calibrated fixture\n# GHZ S {fmt} R 50\n0.43392 {pair}\n")
            f, rl, vswr = session.vna_points(p)[0]
            self.assertAlmostEqual(f,433.92)
            self.assertAlmostEqual(rl,20)
            self.assertAlmostEqual(vswr,1.1/.9)

    def test_vna_invalid_measurements(self):
        for text in ["# MHZ S RI R 50\n433 1.1 0", "# MHZ S MA R 50\n433 -0.5 0", "# MHZ S RI R 50\n433 nan 0", "# MHZ Z RI R 50\n433 .5 0"]:
            with self.assertRaises(ValueError):
                session.vna_points(self.file("bad.s1p",text))

    def test_csv_vna_conventions_and_consistency(self):
        p = self.file("vna.csv", "frequency_hz,return_loss_db,vswr\n433920000,20,1.222222\n")
        self.assertAlmostEqual(session.vna_points(p)[0][0], 433.92)
        for text in ["frequency_mhz,return_loss_db\n433,-20\n", "frequency_mhz,vswr\n433,0.5\n", "frequency_mhz,return_loss_db,vswr\n433,20,5\n"]:
            with self.assertRaises(ValueError):
                session.vna_points(self.file("bad.csv",text))

    def replay(self, events):
        engine = os.environ.get("RECON_ENGINE")
        if not engine:
            self.skipTest("RECON_ENGINE not supplied; CI compiles the shared C++ engine first")
        a = "aa:00:00:00:00:01"
        payload = "09094d79426561636f6e08ff4c001023456701"
        rows = [dict(type="header", schema=1, target=a)]
        for time, address in events:
            if address in {"undo", "resume", "lock_toggle"}:
                rows.append(dict(type="event", us=time*1000, kind=address))
            else:
                rows.append(dict(type="observation", us=time*1000, ms=time, address=address, address_type=1, rssi=-60, mode=0, adv_type=0, adv_len=len(bytes.fromhex(payload)), original_len=len(bytes.fromhex(payload)), decision=0, payload=payload))
        rows.append(dict(type="footer", dropped=0, truncated=0))
        source = self.file("replay.jsonl", "\n".join(json.dumps(r) for r in rows))
        result = subprocess.run([sys.executable, str(ROOT / "tools/recon_session.py"), "replay", str(source), "--engine", engine], text=True, capture_output=True, check=True)
        return [int(line.split()[2]) for line in result.stdout.splitlines()]

    def test_recorded_handoff_and_undo_replay(self):
        a,b = "aa:00:00:00:00:01", "bb:00:00:00:00:02"
        decisions = self.replay([(100,a),(500,a),(4000,b),(4300,b),(4600,b),(4700,"undo"),(8000,b)])
        self.assertEqual(decisions, [1,1,2,2,3,0])

    def test_recorded_crowd_replay_abstains(self):
        a,b,c = "aa:00:00:00:00:01", "bb:00:00:00:00:02", "cc:00:00:00:00:03"
        decisions = self.replay([(100,a),(500,a),(4000,b),(4100,c),(4400,b),(4500,c),(4800,b),(4900,c)])
        self.assertNotIn(3, decisions)

    def test_recorded_menu_pause_replay(self):
        a,b = "aa:00:00:00:00:01", "bb:00:00:00:00:02"
        decisions = self.replay([(100,a),(20000,"resume"),(20100,b),(20400,b),(20700,b),(21000,a)])
        self.assertEqual(decisions, [1,0,0,0,1])


if __name__ == "__main__":
    unittest.main()
