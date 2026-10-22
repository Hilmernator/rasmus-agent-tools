#!/usr/bin/env python3
"""Explicitly install the locked local SAST tools; scans never install packages."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from scan import RULES_DIR
import iac


ASSETS = Path(__file__).resolve().parents[1] / "assets/toolchain"
LOCKS = ("package.json", "package-lock.json", "requirements.txt")
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
              "0BSD", "PSF-2.0", "Python-2.0", "CC0-1.0", "BlueOak-1.0.0"}
RULE_POLICY = ASSETS.parent / "semgrep-policy.json"
MAX_RULE_BYTES = 8 * 1024 * 1024


def lock_digest():
    digest = hashlib.sha256()
    for name in LOCKS:
        digest.update(name.encode())
        digest.update((ASSETS / name).read_bytes())
    return digest.hexdigest()


def toolchain():
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache.expanduser().resolve() / "rasmus-security/toolchains" / lock_digest()


def license_allowed(expression):
    # Only these exact reviewed expressions are accepted, not arbitrary SPDX parsing.
    return expression in PERMISSIVE or expression in {
        "(MIT OR CC0-1.0)", "(MIT AND BSD-3-Clause)",
        "PSF-2.0 AND BSD-3-Clause",
    }


def inventory(root):
    packages = []
    lock = json.loads((root / "package-lock.json").read_text())
    for name, metadata in lock["packages"].items():
        if not name:
            continue
        installed = root / name
        actual = json.loads((installed / "package.json").read_text())
        if actual["version"] != metadata["version"]:
            raise ValueError("Installed npm package does not match lockfile")
        license_id = actual.get("license", "UNKNOWN")
        if not isinstance(license_id, str) or not license_allowed(license_id):
            raise ValueError(f"License needs manual approval: {actual['name']} {license_id}")
        notices = [p for p in installed.iterdir() if p.is_file() and
                   p.name.lower().startswith(("license", "licence", "notice", "copyright"))]
        packages.append({"ecosystem": "npm", "name": actual["name"], "version": actual["version"],
                         "license": license_id, "source": metadata.get("resolved"),
                         "integrity": metadata.get("integrity"),
                         "notices": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in notices}})
    code = """
import importlib.metadata as m, json, hashlib
rows = []
for dist in m.distributions():
    metadata = dist.metadata
    notices = {}
    for file in dist.files or []:
        if file.name.lower().startswith(('license', 'licence', 'notice', 'copyright')):
            notices[str(file)] = hashlib.sha256(dist.locate_file(file).read_bytes()).hexdigest()
    rows.append({'ecosystem': 'pypi', 'name': metadata['Name'], 'version': dist.version,
                 'license': metadata.get('License-Expression') or metadata.get('License', 'UNKNOWN'),
                 'classifiers': metadata.get_all('Classifier') or [], 'notices': notices})
print(json.dumps(rows))
"""
    result = subprocess.run([str(root / "venv/bin/python"), "-I", "-c", code],
                            check=True, capture_output=True, text=True, timeout=30)
    for package in json.loads(result.stdout):
        # Older wheel metadata uses a classifier rather than an SPDX expression.
        if package["license"] == "Apache License, Version 2.0":
            package["license"] = "Apache-2.0"
        if package["license"] == "UNKNOWN" and "License :: OSI Approved :: MIT License" in package["classifiers"]:
            package["license"] = "MIT"
        if not license_allowed(package["license"]):
            raise ValueError(f"License needs manual approval: {package['name']} {package['license'][:100]}")
        packages.append(package)
    return packages


def verified_receipt():
    root = toolchain()
    receipt = json.loads((root / "license-inventory.json").read_text())
    if receipt["lock_sha256"] != lock_digest():
        raise ValueError("Toolchain license inventory does not match bundled locks")
    for name in LOCKS:
        if (root / name).read_bytes() != (ASSETS / name).read_bytes():
            raise ValueError("Installed toolchain lockfiles were changed; repeat reviewed setup")
    if inventory(root) != receipt["packages"]:
        raise ValueError("Installed package versions or license evidence changed; repeat reviewed setup")
    return root, receipt


def node_supported(version):
    # Matches the Node engine range in the pinned ESLint release, not all semver.
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version.strip())
    if not match:
        return False
    major, minor, patch = map(int, match.groups())
    return major >= 24 or (major == 22 and (minor, patch) >= (13, 0)) or (major == 20 and (minor, patch) >= (19, 0))


def rules_status():
    """Installed packs must match the policy list and the hashes recorded at download."""
    policy = json.loads(RULE_POLICY.read_text())
    manifest = json.loads((RULES_DIR / "manifest.json").read_text())
    missing = [pack for pack in policy["packs"] if pack not in manifest.get("packs", {})]
    if missing:
        return {"status": "missing", "missing_packs": missing, "path": str(RULES_DIR)}
    for pack in policy["packs"]:
        path = RULES_DIR / f"{pack}.yaml"
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != manifest["packs"][pack]["sha256"]:
            return {"status": "changed", "error": f"Rule pack {pack} differs from its download record; rerun --fetch-rules",
                    "path": str(RULES_DIR)}
    return {"status": "available", "path": str(RULES_DIR), "fetched_at": manifest["fetched_at"],
            "packs": policy["packs"]}


def check():
    """No downloads or installation. Available executables are not smoke-tested."""
    checks = {"platform": {"status": "available" if os.name == "posix" else "unsupported"},
              "python": {"status": "available" if sys.version_info >= (3, 10) else "incompatible",
                         "version": ".".join(map(str, sys.version_info[:3]))}}
    for tool in ("git", "semgrep", "node"):
        executable = shutil.which(tool)
        checks[tool] = {"status": "available" if executable else "missing", "path": executable}
    if checks["node"]["path"]:
        try:
            env = {k: v for k, v in os.environ.items() if k not in ("NODE_OPTIONS", "NODE_PATH")}
            node = subprocess.run([checks["node"]["path"], "--version"], env=env,
                                  capture_output=True, text=True, check=True, timeout=15)
            checks["node"].update(version=node.stdout.strip(), status="available" if node_supported(node.stdout) else "incompatible")
        except (OSError, subprocess.SubprocessError):
            checks["node"]["status"] = "error"
    for name in ("toolchain", "rules"):
        try:
            if name == "toolchain":
                root, receipt = verified_receipt()
                checks[name] = {"status": "available", "path": str(root),
                                "license_inventory": str(root / "license-inventory.json"),
                                "versions": {p["name"]: p["version"] for p in receipt["packages"]
                                             if p["name"] in ("bandit", "eslint", "eslint-plugin-security", "@typescript-eslint/parser")}}
            else:
                checks[name] = rules_status()
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            checks[name] = {"status": "missing" if isinstance(error, FileNotFoundError) else "error",
                            "error": str(error) if type(error) is ValueError else type(error).__name__}
    checks["iac"] = iac.check()
    checks["iac"]["status"] = "available" if checks["iac"]["status"] == "prerequisites-ready" else "missing"
    ready = all(item["status"] == "available" for item in checks.values())
    return {"status": "prerequisites-ready" if ready else "needs-setup", "checks": checks,
            "installation_tools": {tool: shutil.which(tool) for tool in ("uv", "npm")},
            "next_step": "Ready to scan (--verify runs a functional self-test)" if ready else "Run security.py --setup (see references/setup.md)"}


def fetch_rules(refresh=False):
    """Explicit HTTPS download of the policy's packs; scans never download rules.

    The registry URLs are mutable, so content is recorded (sha256, time) at download
    rather than pinned in advance. Rerunning with refresh replaces the whole set.
    """
    try:
        if not refresh and rules_status()["status"] == "available":
            return {"status": "already-present", "path": str(RULES_DIR)}
    except (OSError, ValueError, KeyError):
        pass
    policy = json.loads(RULE_POLICY.read_text())
    if not policy["source"].startswith("https://"):
        raise ValueError("Rule source must use HTTPS")
    RULES_DIR.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staging = Path(tempfile.mkdtemp(dir=RULES_DIR.parent, prefix=".packs-"))
    try:
        manifest = {"source": policy["source"], "license": policy["license"], "packs": {},
                    "fetched_at": datetime.now(timezone.utc).isoformat()}
        for pack in policy["packs"]:
            with urllib.request.urlopen(policy["source"].format(pack=pack), timeout=120) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError("Rule download redirected outside HTTPS")
                data = response.read(MAX_RULE_BYTES + 1)
            if len(data) > MAX_RULE_BYTES or not data.startswith(b"rules:"):
                raise ValueError(f"Rule pack {pack} is oversized or not a Semgrep rule file; nothing replaced")
            (staging / f"{pack}.yaml").write_bytes(data)
            manifest["packs"][pack] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Swap complete sets only, so a failed download never leaves a mixed directory.
        previous = RULES_DIR.with_name(staging.name + "-previous")
        if RULES_DIR.exists():
            RULES_DIR.rename(previous)
        staging.rename(RULES_DIR)
        shutil.rmtree(previous, ignore_errors=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return {"status": "installed", "path": str(RULES_DIR), "packs": list(manifest["packs"]),
            "fetched_at": manifest["fetched_at"]}


def verify():
    """Exercise all four engines on synthetic files; never scan the user's repo."""
    preflight = check()
    if preflight["status"] != "prerequisites-ready":
        return preflight
    import sast

    with tempfile.TemporaryDirectory(prefix="rasmus-sast-setup-") as temporary:
        target = Path(temporary).resolve()
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        subprocess.run(["git", "init", "--quiet", "--template=", str(target)], env=env,
                       check=True, capture_output=True, timeout=30)
        (target / "unsafe.py").write_text("from urllib.request import urlopen\nurlopen(input())\neval(input())  # nosec\n")
        (target / "unsafe.ts").write_text("const value: string = process.argv[2]; eval(value);\n")
        (target / "unsafe.rs").write_text("fn main() { let p = std::env::args().nth(1).unwrap(); std::process::Command::new(p).spawn().unwrap(); }\n")
        (target / "safe.py").write_text("print('setup fixture')\n")
        (target / "Dockerfile").write_text("FROM alpine:3.20\nUSER root\n")
        (target / "template.yaml").write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n")
        args = argparse.Namespace(target=str(target), commit=None, diff=False, semgrep_config=None,
                                  custom_rules_license_reviewed=False, timeout=120, allow_network=False)
        path, report = sast.execute(args)
        try:
            engines = {item["tool"]: item for item in report["engines"]}
            detected = {item["engine"] for item in report["findings"]}
            ready = report["status"] == "findings" and detected == {"semgrep", "bandit", "eslint", "trivy"}
            return {"status": "ready" if ready else "verification-failed", "prerequisites": preflight,
                    "engines": engines, "detected_by": sorted(detected),
                    "error": report.get("error"), "scope": "synthetic temporary fixtures only"}
        finally:
            path.unlink()
            path.parent.rmdir()


def install():
    root = toolchain()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipt_path = root / "license-inventory.json"
    if receipt_path.exists():
        verified_receipt()
        print(f"Already installed: {root}")
        return
    for name in LOCKS:
        shutil.copy2(ASSETS / name, root / name)
    # Wheels only and disabled npm lifecycle scripts: installing tools must not
    # execute build hooks from packages or scripts from the target repository.
    if not (root / "venv/bin/python").exists():
        subprocess.run(["uv", "venv", "--python", "3.12", str(root / "venv")], check=True)
    subprocess.run(["uv", "pip", "sync", "--python", str(root / "venv/bin/python"),
                    "--require-hashes", "--only-binary=:all:", str(root / "requirements.txt")], check=True)
    subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=root, check=True)
    packages = inventory(root)
    receipt = {"lock_sha256": lock_digest(), "usage": "internal repository scanning",
               "legal_approval": "technical inventory, not company legal approval", "packages": packages}
    with receipt_path.open("x") as file:
        json.dump(receipt, file, indent=2)
        file.write("\n")
    print(f"Installed {len(packages)} license-inventoried packages: {root}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="inspect prerequisites without downloads (default)")
    mode.add_argument("--verify", action="store_true", help="run all engines on temporary synthetic fixtures, offline")
    mode.add_argument("--install", action="store_true", help="explicitly install locked Bandit/ESLint outside repositories")
    mode.add_argument("--install-iac", action="store_true", help="install checksum-pinned Trivy after separate tool license review")
    mode.add_argument("--fetch-rules", action="store_true", help="download the policy's Semgrep packs if missing")
    mode.add_argument("--refresh-rules", action="store_true", help="re-download every Semgrep pack (explicit update)")
    args = parser.parse_args()
    try:
        if args.install:
            install()
            return 0
        result = iac.install() if args.install_iac else fetch_rules(args.refresh_rules) if args.fetch_rules or args.refresh_rules else verify() if args.verify else check()
        print(json.dumps(result, indent=2))
        return 0 if result["status"] in ("prerequisites-ready", "ready", "already-present", "already-installed", "installed") else 2
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        detail = str(error) if type(error) is ValueError else type(error).__name__
        print(json.dumps({"status": "setup-failed", "error": detail}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
