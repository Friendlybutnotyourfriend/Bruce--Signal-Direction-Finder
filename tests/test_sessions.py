import importlib.util
import json
import math
from pathlib import Path
import tempfile
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


if __name__ == "__main__":
    unittest.main()
