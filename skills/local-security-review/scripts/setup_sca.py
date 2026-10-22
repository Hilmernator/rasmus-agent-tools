#!/usr/bin/env python3
"""Set up pinned OSV-Scanner and npm/PyPI/crates.io databases outside consumer repositories."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.request


VERSION = "2.6.0"
HASHES = {
    "darwin_arm64": "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4",
    "darwin_amd64": "60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca",
    "linux_arm64": "2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4",
    "linux_amd64": "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108",
}
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "rasmus-security/sca"
DB = CACHE / "databases"
ECOSYSTEMS = ("npm", "PyPI", "crates.io")


def artifact():
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
    key = f"{platform.system().lower()}_{arch}"
    if key not in HASHES:
        raise ValueError("SCA setup supports macOS/Linux arm64/amd64; use WSL on Windows")
    return key


def executable():
    return CACHE / VERSION / f"osv-scanner_{artifact()}"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def checked_executable():
    path = executable()
    if not path.is_file():
        raise ValueError("Pinned OSV-Scanner missing; run setup_sca.py --install")
    if digest(path) != HASHES[artifact()] or not os.access(path, os.X_OK):
        raise ValueError("Pinned OSV-Scanner integrity/permissions mismatch; preserve cache and inspect")
    return str(path)


def databases():
    result = []
    for ecosystem in ECOSYSTEMS:
        # v2.6 uses Scalibr's cache layout (older docs still say osv-scanner).
        path = DB / "osv-scalibr" / ecosystem / "all.zip"
        info = {"ecosystem": ecosystem, "path": str(path), "present": path.is_file()}
        if info["present"]:
            info.update(bytes=path.stat().st_size,
                        cache_mtime=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat())
        result.append(info)
    return result


def check():
    result = {"status": "needs-setup", "version": VERSION, "databases": databases(),
              "freshness_note": "Cache mtime is not proof of upstream advisory freshness; refresh explicitly.",
              "license": "Apache-2.0; advisory data has separate source-specific terms"}
    try:
        result["executable"] = checked_executable()
        if all(item["present"] and item["bytes"] for item in result["databases"]):
            result["status"] = "prerequisites-ready"
    except (OSError, ValueError) as error:
        result["error"] = str(error) if type(error) is ValueError else type(error).__name__
    return result


def install():
    path = executable()
    if path.exists() or path.is_symlink():
        checked_executable()
        return {"status": "already-installed", "executable": str(path), "version": VERSION}
    url = f"https://github.com/google/osv-scanner/releases/download/v{VERSION}/{path.name}"
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=path.parent) as temporary:
        downloaded = Path(temporary) / "binary"
        with urllib.request.urlopen(url, timeout=60) as response, downloaded.open("wb") as file:
            if not response.url.startswith("https://"):
                raise ValueError("Refusing non-HTTPS binary download")
            size = 0
            for block in iter(lambda: response.read(1024 * 1024), b""):
                size += len(block)
                if size > 256 * 1024 * 1024:
                    raise ValueError("OSV binary exceeds download limit")
                file.write(block)
        if digest(downloaded) != HASHES[artifact()]:
            raise ValueError("OSV release checksum mismatch; nothing installed")
        downloaded.chmod(0o755)
        os.link(downloaded, path)  # Atomic publication, never overwrite another installation.
    return {"status": "installed", "executable": checked_executable(), "version": VERSION,
            "sha256": HASHES[artifact()], "source": url,
            "license_source": f"https://github.com/google/osv-scanner/blob/v{VERSION}/LICENSE"}


def fixture(target):
    (target / "package-lock.json").write_text(json.dumps({
        "name": "rasmus-sca-smoke", "lockfileVersion": 3, "packages": {
            "": {"name": "rasmus-sca-smoke", "dependencies": {"lodash": "4.17.20"}},
            "node_modules/lodash": {"version": "4.17.20"}}}))
    (target / "requirements.txt").write_text("urllib3==1.26.4\n")
    (target / "Cargo.lock").write_text('version = 3\n\n[[package]]\nname = "smallvec"\nversion = "1.6.0"\n'
                                       'source = "registry+https://github.com/rust-lang/crates.io-index"\n')


def verify(update=False):
    # Only synthetic lockfiles; no packages are installed and no project code runs.
    import scan
    binary = checked_executable()
    with tempfile.TemporaryDirectory(prefix="rasmus-sca-verify-") as temporary:
        target = Path(temporary)
        fixture(target)
        raw = target / "raw.json"
        config = target / "trusted.toml"
        config.write_text("# No suppressions or package overrides.\n")
        argv = scan.sca_command(binary, target, raw, config, False)
        if update:
            argv.insert(3, "--download-offline-databases")
        env = {**os.environ, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(DB)}
        result = subprocess.run(argv, cwd=temporary, env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=900)
        if result.returncode != 1 or not raw.is_file() or raw.stat().st_size > scan.MAX_REPORT_BYTES:
            raise ValueError("OSV smoke scan failed; check binary compatibility and npm/PyPI databases")
        findings, coverage = scan.project("sca", json.loads(raw.read_text()))
        detected = {item["package"]["ecosystem"] for item in findings}
        if detected != set(ECOSYSTEMS):
            raise ValueError("Smoke scan must detect vulnerable dependencies in npm, PyPI and crates.io")
        if not all(item["present"] and item["bytes"] for item in databases()):
            raise ValueError("Smoke scan did not leave both offline databases available")
        return {"status": "ready", "version": VERSION, "detected_ecosystems": sorted(detected),
                "scanned_packages": coverage["scanned_packages"], "databases": databases(),
                "scope": "synthetic fixtures only", "network_allowed": update}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--install", action="store_true", help="download checksum-pinned official binary")
    mode.add_argument("--update-db", action="store_true", help="download/refresh npm and PyPI advisory databases")
    mode.add_argument("--verify", action="store_true", help="offline functional test of both ecosystems")
    args = parser.parse_args()
    try:
        result = install() if args.install else verify(args.update_db) if args.verify or args.update_db else check()
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        result = {"status": "failed", "error": str(error) if type(error) is ValueError else type(error).__name__}
    print(json.dumps(result, indent=2))
    return 2 if result["status"] in ("failed", "needs-setup") else 0


if __name__ == "__main__":
    raise SystemExit(main())
