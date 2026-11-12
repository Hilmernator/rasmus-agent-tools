# /// script
# requires-python = ">=3.10"
# dependencies = ["pyyaml==6.0.2"]
# ///
"""Maintainer tool: download the pinned standards and write catalogs/*.json.

Run with `uv run scripts/build_catalogs.py`. The skill itself never downloads anything;
it reads the catalogs this script wrote. To update a standard, change its pin below,
rerun, review the diff, and update SOURCES.md.
"""
import json
import re
import urllib.request
from pathlib import Path

import yaml

OUT = Path(__file__).resolve().parents[1] / "catalogs"
ASVS = ("5.0.0", "5cf9b032440be53ce345ab3c130fda46ba1ce7a2",
        "https://github.com/OWASP/ASVS/releases/download/v5.0.0_release/"
        "OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json")
AISVS = ("1.01", "3ae3af45c363467b8ad823ef79219236e67ca22f")
AISVS_FILES = [
    "0x10-C01-Training-Data-Integrity-and-Traceability.md", "0x10-C02-Input-Validation.md",
    "0x10-C03-Model-Lifecycle-Management.md", "0x10-C04-Infrastructure.md",
    "0x10-C05-Access-Control-and-Identity.md", "0x10-C06-Supply-Chain.md", "0x10-C07-Model-Behavior.md",
    "0x10-C08-Memory-Embeddings-and-Vector-Database.md", "0x10-C09-Orchestration-and-Agentic-Action.md",
    "0x10-C10-MCP-Security.md", "0x10-C11-Adversarial-Robustness.md", "0x10-C12-Monitoring-and-Logging.md",
    "0x92-Appendix-C_AI_for_Code_Generation.md",
]
MASVS = ("2.1.0", "1de2913fe799137ac4695eabaae633da693070cd",
         "https://github.com/OWASP/masvs/releases/download/v2.1.0/OWASP_MASVS.yaml")
ROW = re.compile(r"^\| \*\*(?P<id>[A-Z0-9.]+)\*\* \| (?P<text>.*) \| (?P<level>[123]) \|$")


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read().decode()


def write(key, name, version, revision, source, requirements):
    ids = [r["id"] for r in requirements]
    assert len(ids) == len(set(ids)), f"{key}: duplicate ids"
    doc = {"standard": key, "name": name, "version": version, "revision": revision, "source": source,
           "license": "CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/), OWASP Foundation; "
                      "reformatted to JSON, text unchanged", "requirements": requirements}
    (OUT / f"{key}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"{key} {version}: {len(requirements)} requirements")


def asvs():
    version, rev, url = ASVS
    rows = json.loads(get(url))["requirements"]
    write("asvs", "OWASP Application Security Verification Standard", version, rev, url, [
        {"id": r["req_id"], "chapter": f'{r["chapter_id"]} {r["chapter_name"]}',
         "section": f'{r["section_id"]} {r["section_name"]}', "level": int(r["L"]), "text": r["req_description"]}
        for r in rows])


def aisvs():
    version, rev = AISVS
    base = f"https://raw.githubusercontent.com/OWASP/AISVS/{rev}/1.0/en/"
    out = []
    for name in AISVS_FILES:
        chapter = section = None
        for line in get(base + name).splitlines():
            if line.startswith("# "):
                chapter = line[2:].strip()
            elif re.match(r"## (C\d+|AC)\.\d+ ", line):
                section = line[3:].strip()
            elif m := ROW.match(line):
                out.append({"id": m["id"], "chapter": chapter, "section": section, "level": int(m["level"]),
                            "text": m["text"].replace("**", "").strip()})
            else:
                assert not line.startswith("| **"), f"{name}: unparsed row: {line[:80]}"
    name = "OWASP Artificial Intelligence Security Verification Standard"
    # Appendix C is about building software with AI tools, not about an AI product, so it is selected on its own.
    write("aisvs", name, version, rev, base, [r for r in out if not r["id"].startswith("AC.")])
    write("aisvs-ac", name + ", Appendix C", version, rev, base, [r for r in out if r["id"].startswith("AC.")])


def masvs():
    version, rev, url = MASVS
    doc = yaml.safe_load(get(url))
    # MASVS v2 controls carry no level; profiles live in MASTG. Level 1 keeps them in every selection.
    write("masvs", "OWASP Mobile Application Security Verification Standard", version, rev, url, [
        {"id": c["id"], "chapter": f'{g["id"]} {g["title"]}', "section": f'{g["id"]} {g["title"]}', "level": 1,
         "text": c["statement"]}
        for g in doc["groups"] for c in g["controls"]])


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    asvs()
    aisvs()
    masvs()
