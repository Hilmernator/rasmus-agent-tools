"""security-gap-analysis: catalogs, row selection, evidence checks."""
import contextlib
import csv
import io
import json
from pathlib import Path
import subprocess
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
        code, out = run("check", str(self.repo), "--complete")
        self.assertEqual(code, 1)
        self.assertIn("70 requirements are unassessed", out)

    def test_the_folder_holds_only_its_own_files(self):
        (self.repo / "security/notes-2026.md").write_text("x\n")
        (self.repo / "security/findings.csv").write_text("id,status\n")
        out = run("check", str(self.repo))[1]
        self.assertIn("security/notes-2026.md: not a file of this folder", out)
        self.assertIn("security/findings.csv: header must be fingerprint,skill,", out)
        self.assertNotIn("requirements.csv: not a file", out)

    def test_the_folder_is_ignored_by_git_unless_it_is_tracked(self):
        def git(repo, *args):
            return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
        git(self.repo, "init", "-q")
        self.assertIn("ignored: added security/", run("init", str(self.repo), "--select", "asvs:1")[1])
        self.assertEqual(git(self.repo, "status", "--porcelain", "--", "security").stdout, "")
        self.assertNotIn("ignored:", run("files", str(self.repo))[1])
        tracked = Path(tempfile.mkdtemp())
        git(tracked, "init", "-q")
        run("init", str(tracked), "--select", "asvs:1")
        (tracked / ".git/info/exclude").write_text("")
        git(tracked, "add", "security")
        run("files", str(tracked))
        self.assertEqual((tracked / ".git/info/exclude").read_text(), "")


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


class Signals(unittest.TestCase):
    def kinds(self, name, text):
        repo = Path(tempfile.mkdtemp())
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
        return {h["kind"] for h in gap.scan(repo)}

    def test_entry_points_beyond_http_servers_are_found(self):
        for name, line, kind in [
            ("fn/app.py", "def lambda_handler(event, context):", "route"),
            ("template.yaml", "      Type: Api", "route"),
            ("app/api/items/route.ts", "export async function POST(req: Request) {", "route"),
            ("src/main.rs", "let args: Vec<String> = std::env::args().collect();", "cli"),
            ("tool.py", "import argparse", "cli"),
            ("api.py", "async def put(file: UploadFile):", "upload"),
            ("unpack.py", "tarfile.open(path).extractall(dest)", "upload"),
            ("web/app.js", "localStorage.setItem('token', t)", "store"),
            (".github/workflows/ci.yml", "      - uses: actions/checkout@v4", "pipeline"),
            (".github/workflows/ci.yml", "        run: curl -sSf https://sh.example.com | sh", "pipeline"),
            ("package.json", '    "postinstall": "node setup.js"', "pipeline"),
            ("src/lib.rs", "unsafe { ptr.read() }", "ffi"),
            ("client.py", "requests.get(url, verify=False)", "weak-crypto"),
            ("AndroidManifest.xml", '<activity android:exported="true">', "ipc"),
        ]:
            self.assertIn(kind, self.kinds(name, line + "\n"), line)

    def test_lookalikes_are_left_out(self):
        for name, line, kind in [
            (".github/workflows/ci.yml", "      - uses: actions/checkout@" + "a" * 40, "pipeline"),
            ("web/app.ts", "await uploadFile(blob)", "upload"),
            ("template.yaml", '        - "s3:CreateMultipartUpload"', "upload"),
            ("template.yaml", '        - "dynamodb:GetItem"', "store"),
            ("pyproject.toml", 'argparse = "^1.4.0"', "cli"),
            ("src/lib.rs", "let unsafe_name = 1;", "ffi"),
        ]:
            self.assertNotIn(kind, self.kinds(name, line + "\n"), line)


if __name__ == "__main__":
    unittest.main()
