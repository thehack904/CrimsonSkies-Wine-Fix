#!/usr/bin/env python3
"""Reversible NUL-guard patch for one verified Crimson Skies (2000) roffile.dll.

At RVA 0x231E, replaces INC ESI (0x46) with NOP (0x90).
No copyrighted DLL is distributed. Exit the game before applying or restoring.
"""

import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile

ORIGINAL_SHA256 = "1bc7b4b1adba1bf6a510e62f93473824c662acbf2a2176087b7b4b85338ba58a"
RVA = 0x231E
ORIGINAL_CONTEXT = bytes.fromhex("80 3e 20 7d 01 46 89 37")
PATCHED_CONTEXT = bytes.fromhex("80 3e 20 7d 01 90 89 37")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pe_file_offset(data, rva):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not a PE executable")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE header")
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    section_start = pe + 24 + optional_size
    for i in range(sections):
        s = section_start + 40 * i
        if s + 40 > len(data):
            raise ValueError("Invalid PE section table")
        virtual_size, va, raw_size, raw_offset = struct.unpack_from("<4I", data, s + 8)
        if va <= rva < va + min(virtual_size or raw_size, raw_size):
            offset = raw_offset + rva - va
            if offset >= len(data):
                break
            return offset
    raise ValueError("Target RVA not backed by DLL data")


def patch_copy(original):
    if sha256(original) != ORIGINAL_SHA256:
        raise ValueError("Unknown original DLL SHA-256; refusing to modify")
    offset = pe_file_offset(original, RVA)
    if original[offset - 5:offset + 3] != ORIGINAL_CONTEXT:
        raise ValueError("Original instruction bytes do not match expected build")
    updated = bytearray(original)
    updated[offset] = 0x90
    if updated[offset - 5:offset + 3] != PATCHED_CONTEXT:
        raise ValueError("Internal patch validation failed")
    return bytes(updated), offset


def write_atomic(path, data, mode):
    fd, name = tempfile.mkstemp(prefix=".roffile-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def make_backup_once(path, backup, original):
    """Create backup without replacing an existing file (even a broken one)."""
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(original)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(backup, stat.S_IMODE(path.stat().st_mode))
    except Exception:
        backup.unlink(missing_ok=True)
        raise
    if sha256(backup.read_bytes()) != ORIGINAL_SHA256:
        raise ValueError("Created backup failed SHA-256 verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "apply", "restore"))
    parser.add_argument("--dll", type=Path, required=True, help="Path to your own roffile.dll")
    args = parser.parse_args()
    path = args.dll.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.name.lower() != "roffile.dll":
        parser.error("Specify an existing regular roffile.dll, not a symlink")
    backup = path.with_name(path.name + ".before-nul-guard")
    if backup.is_symlink():
        raise ValueError("Backup location is a symlink; refusing")

    current = path.read_bytes()
    original = None
    if sha256(current) == ORIGINAL_SHA256:
        original = current
    elif backup.is_file() and sha256(backup.read_bytes()) == ORIGINAL_SHA256:
        original = backup.read_bytes()

    # Expected patched image is calculated from the *entire* verified original.
    expected_patched = None
    offset = None
    if original is not None:
        expected_patched, offset = patch_copy(original)

    if sha256(current) == ORIGINAL_SHA256:
        state = "original"
    elif expected_patched is not None and current == expected_patched:
        state = "patched"
    else:
        state = "unknown"

    backup_status = ("valid" if backup.is_file() and
                     sha256(backup.read_bytes()) == ORIGINAL_SHA256 else
                     "invalid" if backup.exists() else "absent")
    print(f"DLL: {path}\nSHA256: {sha256(current)}\nState: {state}\n"
          f"Backup: {backup} ({backup_status})")
    if offset is not None:
        print(f"RVA 0x{RVA:X} maps to file offset 0x{offset:X}")
    if args.action == "status":
        return
    if state == "unknown":
        raise ValueError("DLL does not match the validated original or complete patched image")
    print("Ensure the game and Wine processes using this DLL are fully stopped.")
    if args.action == "apply":
        if backup_status == "invalid":
            raise ValueError("Existing backup is invalid; refusing to overwrite it")
        if state == "patched":
            if backup_status != "valid":
                raise ValueError("Patched DLL requires a verified original backup")
            print("Already patched; full-file verification passed.")
            return
        if backup_status == "absent":
            make_backup_once(path, backup, original)
            print("Created and verified backup.")
        else:
            print("Reusing existing verified original backup.")
        write_atomic(path, expected_patched, stat.S_IMODE(path.stat().st_mode))
        if path.read_bytes() != expected_patched:
            raise ValueError("Post-patch verification failed; verified backup retained")
        print("Applied one-byte NUL guard. Full patched file verified.")
    else:
        if backup_status != "valid":
            raise ValueError("Restore requires a verified original backup")
        if state == "original":
            print("Already restored. Verified backup retained for reuse.")
            return
        write_atomic(path, original, stat.S_IMODE(path.stat().st_mode))
        if path.read_bytes() != original:
            raise ValueError("Post-restore verification failed; backup retained")
        print("Original DLL restored. Verified backup retained for future use.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        sys.exit(f"ERROR: {error}")
