"""Bounded archive inspection: member names are metadata, never extraction paths."""

import bz2
import gzip
import io
import lzma
from pathlib import PurePosixPath
import stat
import tarfile
import time
import zipfile


MIB = 1024 * 1024


def archive_kind(name, prefix):
    lower = name.lower()
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or lower.endswith((".zip", ".jar", ".war", ".whl")):
        return "zip"
    if prefix.startswith(b"\x1f\x8b") or lower.endswith((".gz", ".tgz")):
        return "gzip"
    if prefix.startswith(b"BZh") or lower.endswith((".bz2", ".tbz2")):
        return "bzip2"
    if prefix.startswith(b"\xfd7zXZ\x00") or lower.endswith((".xz", ".txz")):
        return "xz"
    if prefix[257:262] == b"ustar" or lower.endswith(".tar"):
        return "tar"
    if prefix.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!")) or lower.endswith((".7z", ".rar", ".zst", ".zstd", ".br", ".lz4", ".gpg", ".enc")):
        return "unsupported"
    return None


class ArchiveReader:
    def __init__(self, output, coverage, deadline, *, max_bytes=256 * MIB, max_depth=5, max_members=10000):
        self.output, self.coverage, self.deadline = output, coverage, deadline
        self.max_bytes, self.max_depth, self.max_members = max_bytes, max_depth, max_members
        self.bytes = self.members = self.containers = 0
        self.locations = {}

    def gap(self, metadata, reason):
        self.coverage["gaps"].append({**metadata, "reason": reason})

    def check_time(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Deep scan time limit reached")

    def read(self, stream):
        self.check_time()
        if self.bytes >= self.max_bytes:
            raise ValueError("Archive expanded-byte limit reached")
        data = stream.read(min(32 * MIB, self.max_bytes - self.bytes) + 1)
        self.bytes += len(data)
        if len(data) > 32 * MIB or self.bytes > self.max_bytes:
            raise ValueError("Archive expanded-byte or member-size limit reached")
        return data

    def count_member(self):
        self.check_time()
        self.members += 1
        if self.members > self.max_members:
            raise ValueError("Archive member-count limit reached")

    def member(self, name, opener, metadata, depth):
        self.check_time()
        path = PurePosixPath(name.replace("\\", "/"))
        child = {**metadata, "path": metadata["path"] + "!" + name}
        if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
            self.gap(child, "Unsafe archive member name; not extracted")
            return
        with opener() as stream:
            data = self.read(stream)
        if archive_kind(name, data[:512]):
            self.inspect(data, child, depth + 1, name)
        else:
            self.save(data, child)

    def save(self, data, metadata):
        if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
            self.gap(metadata, "Git LFS pointer only; referenced content was not fetched")
        # Opaque filenames avoid applying path allowlists to untrusted member names.
        name = f"member-{len(self.locations):08d}.txt"
        (self.output / name).write_bytes(data)
        self.locations[name] = metadata

    def inspect(self, data, metadata, depth=1, name=None):
        self.check_time()
        kind = archive_kind(name or metadata["path"], data[:512])
        if not kind:
            return
        if depth > self.max_depth:
            self.gap(metadata, "Archive nesting-depth limit reached")
            return
        self.containers += 1
        try:
            if kind == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    if len(archive.infolist()) + self.members > self.max_members:
                        raise ValueError("Archive member-count limit reached")
                    for item in archive.infolist():
                        self.count_member()
                        if item.is_dir():
                            continue
                        mode = stat.S_IFMT(item.external_attr >> 16)
                        if (item.flag_bits & 1 or mode not in (0, stat.S_IFREG)
                                or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2)):
                            self.gap({**metadata, "path": metadata["path"] + "!" + item.filename},
                                     "Encrypted, unsupported-compression or special/link ZIP member was not read")
                            continue
                        self.member(item.filename, lambda: archive.open(item), metadata, depth)
            elif kind == "tar":
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                    for item in archive:
                        self.count_member()
                        if item.isdir():
                            continue
                        if not item.isfile():
                            self.gap({**metadata, "path": metadata["path"] + "!" + item.name},
                                     "Special/link TAR member was not read")
                            continue
                        self.member(item.name, lambda: archive.extractfile(item), metadata, depth)
            elif kind in ("gzip", "bzip2", "xz"):
                self.count_member()
                if kind == "gzip":
                    opener = lambda: gzip.GzipFile(fileobj=io.BytesIO(data))
                elif kind == "xz":
                    if self.bytes >= self.max_bytes:
                        raise ValueError("Archive expanded-byte limit reached")
                    decoder = lzma.LZMADecompressor(memlimit=64 * MIB)
                    expanded = decoder.decompress(data, max_length=min(32 * MIB, self.max_bytes - self.bytes) + 1)
                    if not decoder.eof or decoder.unused_data:
                        self.gap(metadata, "XZ truncated, limited or concatenated; full stream not covered")
                    opener = lambda: io.BytesIO(expanded)
                else:
                    opener = lambda: bz2.BZ2File(io.BytesIO(data))
                source_name = name or metadata["path"].rsplit("!", 1)[-1]
                payload_name = "payload.tar" if source_name.lower().endswith((".tgz", ".tbz2", ".txz")) else source_name.rsplit(".", 1)[0]
                self.member(payload_name if payload_name != source_name else "decompressed", opener, metadata, depth)
            else:
                self.gap(metadata, "Unsupported archive/encryption format")
        except (OSError, EOFError, ValueError, OverflowError, RuntimeError, NotImplementedError, tarfile.TarError, zipfile.BadZipFile, lzma.LZMAError):
            # Archive errors can contain member content/passwords: retain only a static reason.
            self.gap(metadata, "Archive unreadable, corrupt, encrypted or resource limit reached")
