#!/usr/bin/env python3
"""Install checksum-pinned Gitleaks outside repositories and verify redacted scanning."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import string
import tarfile
import tempfile
import urllib.request

VERSION = "8.30.1"
HASHES = {
    "darwin_arm64": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    "darwin_x64": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    "linux_arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    "linux_x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
}
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "rai-security/secrets"
LIMIT = 64 * 1024 * 1024


def artifact():
    arch = {"aarch64": "arm64", "x86_64": "x64"}.get(platform.machine(), platform.machine())
    key = f"{platform.system().lower()}_{arch}"
    if key not in HASHES:
        raise ValueError("Secrets setup supports macOS/Linux arm64/x64; use WSL on Windows")
    return key


def root():
    return CACHE / VERSION / artifact()


def archive_contents(path):
    if path.stat().st_size > LIMIT or hashlib.sha256(path.read_bytes()).hexdigest() != HASHES[artifact()]:
        raise ValueError("Gitleaks archive checksum mismatch; preserve cache and inspect")
    contents = {}
    with tarfile.open(path, "r:gz") as archive:
        for name in ("gitleaks", "LICENSE"):
            members = [member for member in archive.getmembers() if member.name == name]
            if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= LIMIT:
                raise ValueError("Unexpected Gitleaks archive member")
            # Read exact regular members; never extract paths, links or archive scripts.
            contents[name] = archive.extractfile(members[0]).read(LIMIT + 1)
            if len(contents[name]) != members[0].size:
                raise ValueError("Truncated Gitleaks archive member")
    return contents


def checked_executable():
    directory = root()
    if not directory.is_dir():
        raise ValueError("Pinned Gitleaks missing; run setup_secrets.py --install")
    contents = archive_contents(directory / "release.tar.gz")
    for name, expected in contents.items():
        path = directory / name
        if path.is_symlink() or path.stat().st_size != len(expected) or path.read_bytes() != expected:
            raise ValueError("Installed Gitleaks binary/license differs from the pinned archive")
    binary = directory / "gitleaks"
    if not os.access(binary, os.X_OK):
        raise ValueError("Installed Gitleaks is not executable")
    return str(binary)


def check():
    result = {"status": "needs-setup", "version": VERSION, "license": "MIT"}
    try:
        result.update(executable=checked_executable(), status="prerequisites-ready",
                      license_path=str(root() / "LICENSE"))
    except (OSError, ValueError, tarfile.TarError) as error:
        result["error"] = str(error) if type(error) is ValueError else type(error).__name__
    return result


def install():
    directory = root()
    if directory.exists() or directory.is_symlink():
        return {"status": "already-installed", "executable": checked_executable(), "version": VERSION}
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{artifact()}.tar.gz"
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent) as temporary:
        downloaded = Path(temporary) / "release.tar.gz"
        with urllib.request.urlopen(url, timeout=60) as response, downloaded.open("wb") as file:
            if not response.url.startswith("https://"):
                raise ValueError("Refusing non-HTTPS scanner download")
            size = 0
            for block in iter(lambda: response.read(1024 * 1024), b""):
                size += len(block)
                if size > LIMIT:
                    raise ValueError("Gitleaks archive exceeds download limit")
                file.write(block)
        for name, content in archive_contents(downloaded).items():
            (Path(temporary) / name).write_bytes(content)
        (Path(temporary) / "gitleaks").chmod(0o755)
        directory.mkdir(mode=0o700)  # Exclusive: existing or concurrent installations are preserved.
        for name in ("release.tar.gz", "gitleaks", "LICENSE"):
            os.link(Path(temporary) / name, directory / name)
    return {"status": "installed", "version": VERSION, "executable": checked_executable(),
            "archive_sha256": HASHES[artifact()], "source": url, "license_path": str(directory / "LICENSE")}


def fixture(target):
    # Random, synthetic and never issued by a provider. Never print this value.
    token = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (target / "candidate.env").write_text(f'github_token = "{token}" # gitleaks:allow\n')
    return token


def verify():
    import scan
    checked_executable()
    with tempfile.TemporaryDirectory(prefix="rai-secrets-verify-") as temporary:
        target = Path(temporary)
        token = fixture(target)
        args = argparse.Namespace(scanner="secrets", target=str(target), allow_network=False,
                                  history=False, semgrep_config=None, commit=None, diff=False, timeout=60)
        for expected in ("findings", "no-findings"):
            path, report = scan.execute(args)
            try:
                if token in path.read_text() or report["status"] != expected:
                    raise ValueError("Gitleaks smoke detection/redaction/negative control failed")
                if expected == "findings" and not any(item["rule"] == "github-pat" for item in report["findings"]):
                    raise ValueError("Gitleaks did not detect the seeded provider-token pattern")
            finally:
                shutil.rmtree(path.parent)
            (target / "candidate.env").write_text("# No credentials in this negative control.\n")
    return {"status": "ready", "version": VERSION, "scope": "synthetic fixtures only",
            "network_allowed": False, "detection": True, "redaction": True, "negative_control": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="inspect installation without network (default)")
    mode.add_argument("--install", action="store_true", help="download and verify the pinned MIT scanner")
    mode.add_argument("--verify", action="store_true", help="test actual detection, redaction and a safe control offline")
    args = parser.parse_args()
    try:
        result = install() if args.install else verify() if args.verify else check()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        result = {"status": "failed", "error": str(error) if type(error) is ValueError else type(error).__name__}
    print(json.dumps(result, indent=2))
    return 2 if result["status"] in ("needs-setup", "failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
