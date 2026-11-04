"""security-gap-analysis: catalogs, row selection, evidence checks."""
import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

SKILL = Path(__file__).resolve().parents[1] / "skills/security-gap-analysis"
sys.path.insert(0, str(SKILL / "scripts"))
import gap


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = gap.main(list(argv))
    return code, out.getvalue()


class Catalogs(unittest.TestCase):
    def test_counts_and_levels(self):
        cats = {p.stem: json.loads(p.read_text()) for p in (SKILL / "catalogs").glob("*.json")}
        self.assertEqual({k: len(v["requirements"]) for k, v in cats.items()}, {"asvs": 345, "aisvs": 191, "aisvs-ac": 68, "masvs": 24})
        for doc in cats.values():
            self.assertRegex(doc["revision"], r"^[0-9a-f]{40}$")
            for r in doc["requirements"]:
                self.assertIn(r["level"], (1, 2, 3))
                self.assertTrue(r["text"] and r["chapter"] and r["section"])


class Rows(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        (self.repo / "src").mkdir()
        (self.repo / "src/app.py").write_text("a\nb\nc\n")
        run("init", str(self.repo), "--select", "asvs:1")

    def rows(self):
        with (self.repo / "security/requirements.csv").open() as f:
            return {(r["standard"], r["id"]): r for r in csv.DictReader(f)}

    def test_init_selects_by_level_and_keeps_rows(self):
        self.assertEqual(len(self.rows()), 70)
        run("set", str(self.repo), "asvs:V1.2.1", "--status", "missing", "--notes", "No encoding.")
        code, out = run("init", str(self.repo), "--select", "asvs:2", "--select", "masvs")
        self.assertEqual(len(self.rows()), 70 + 183 + 24)
        self.assertEqual(self.rows()[("asvs", "V1.2.1")]["status"], "missing")

    def test_prefix_is_whole_segments(self):
        run("init", str(self.repo), "--select", "asvs:3")
        run("set", str(self.repo), "asvs:V1", "--status", "not-applicable", "--notes", "x")
        rows = self.rows()
        self.assertTrue(all(r["status"] == "not-applicable" for k, r in rows.items() if k[1].startswith("V1.")))
        self.assertTrue(all(r["status"] == "unassessed" for k, r in rows.items() if k[1].startswith("V10.")))

    def test_evidence_must_resolve(self):
        code, out = run("set", str(self.repo), "asvs:V1.2.1", "--status", "met", "--evidence", "src/app.py:2-3")
        self.assertEqual(code, 0, out)
        for bad in ("src/app.py:9", "src/nope.py:1", "../outside:1", "src/app.py"):
            code, out = run("set", str(self.repo), "asvs:V1.2.1", "--status", "met", "--evidence", bad)
            self.assertEqual(code, 1, bad)
        code, out = run("check", str(self.repo))
        self.assertEqual(code, 1)

    def test_statuses_need_their_reasons(self):
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "met")[0], 1)
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "missing")[0], 1)
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "risk-accepted", "--notes", "ok")[0], 1)
        (self.repo / "security/accepted-risks.md").write_text("- asvs:V1.2.1 accepted 2026-11-04\n")
        self.assertEqual(run("set", str(self.repo), "asvs:V1.2.1", "--status", "risk-accepted", "--notes", "ok")[0], 0)

    def test_check_needs_the_coverage_ledgers(self):
        code, out = run("check", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("files.csv or inventory.csv is missing", out)
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo))
        code, out = run("check", str(self.repo))
        self.assertEqual(code, 0, out)
        self.assertIn("unassessed 70", out)


class Coverage(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        (self.repo / "src").mkdir()
        (self.repo / "src/server.rs").write_text('fn main() {\n    let l = TcpListener::bind("0.0.0.0:80");\n'
                                                  '    std::thread::spawn(|| {});\n}\n')
        (self.repo / "src/util.rs").write_text("pub fn add(a: u8) -> u8 { a }\n")
        (self.repo / "logo.png").write_bytes(b"\x89PNG\0\0")
        run("init", str(self.repo), "--select", "masvs")
        run("set", str(self.repo), "masvs", "--status", "not-applicable", "--notes", "Not a mobile app.")

    def check(self):
        return run("check", str(self.repo))

    def test_every_file_and_signal_must_be_accounted_for(self):
        code, out = run("files", str(self.repo))
        self.assertIn("unread 2", out)
        self.assertIn("skipped 1", out)
        code, out = run("inventory", str(self.repo))
        self.assertIn("listen", out)
        self.assertNotIn("thread::spawn", out)
        code, out = self.check()
        self.assertIn("2 files are unread", out)
        self.assertIn("1 inventory lines are unreviewed", out)
        run("files", str(self.repo), "--mark", "src", "--status", "read")
        run("inventory", str(self.repo), "--mark", "--kind", "listen", "--status", "boundary")
        code, out = self.check()
        self.assertIn("profile.md does not name src/server.rs", out)
        (self.repo / "security/profile.md").write_text("Port 80 is served by src/server.rs.\n")
        self.assertEqual(self.check()[0], 0, self.check()[1])

    def test_a_change_reopens_the_file_and_the_rows_citing_it(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("inventory", str(self.repo), "--mark", "--path", "src", "--status", "internal", "--notes", "test fixture")
        run("set", str(self.repo), "masvs:MASVS-CODE-1", "--status", "met", "--evidence", "src/util.rs:1")
        self.assertEqual(self.check()[0], 0, self.check()[1])
        (self.repo / "src/util.rs").write_text("pub fn add(a: u8) -> u8 { a + 1 }\n")
        code, out = self.check()
        self.assertIn("src/util.rs changed since it was marked; reread it, mark it again and reassess masvs:MASVS-CODE-1", out)
        (self.repo / "src/new.rs").write_text("let x = eval(input);\n")
        code, out = self.check()
        self.assertIn("files.csv does not list the current files", out)
        self.assertIn("inventory.csv does not match the code", out)

    def test_evidence_must_be_in_a_read_file(self):
        run("files", str(self.repo), "--mark", ".", "--status", "read")
        run("files", str(self.repo), "--mark", "src/util.rs", "--status", "skipped", "--notes", "trivial")
        run("inventory", str(self.repo), "--mark", "--path", "src", "--status", "internal", "--notes", "fixture")
        run("set", str(self.repo), "masvs:MASVS-CODE-1", "--status", "met", "--evidence", "src/util.rs:1")
        code, out = self.check()
        self.assertIn("evidence src/util.rs is skipped, not read", out)


if __name__ == "__main__":
    unittest.main()
