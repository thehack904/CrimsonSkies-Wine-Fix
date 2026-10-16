#!/usr/bin/env python3
"""Crimson Skies (2000) ROF line-parser NUL guard for ONE verified DLL build.

Changes roffile.dll at RVA 0x231e: INC ESI (46) -> NOP (90).
No game binaries are included. Exit Crimson Skies before applying/restoring.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile

ORIGINAL_SHA256 = '1bc7b4b1adba1bf6a510e62f93473824c662acbf2a2176087b7b4b85338ba58a'
RVA = 0x231e
ORIGINAL = bytes.fromhex('80 3e 20 7d 01 46 89 37')
PATCHED = bytes.fromhex('80 3e 20 7d 01 90 89 37')

def sha(b):
    return hashlib.sha256(b).hexdigest()

def pe_file_offset(b, rva):
    if len(b) < 0x40 or b[:2] != b'MZ':
        raise ValueError('Not a PE DLL')
    pe = struct.unpack_from('<I', b, 0x3c)[0]
    if pe + 24 > len(b) or b[pe:pe+4] != b'PE\0\0':
        raise ValueError('Invalid PE header')
    n = struct.unpack_from('<H', b, pe+6)[0]
    optional_size = struct.unpack_from('<H', b, pe+20)[0]
    for i in range(n):
        s = pe + 24 + optional_size + 40*i
        if s+40 > len(b):
            raise ValueError('Invalid section headers')
        virtual_size, va, raw_size, raw_offset = struct.unpack_from('<4I', b, s+8)
        if va <= rva < va + raw_size and raw_offset + rva - va < len(b):
            return raw_offset + rva - va
    raise ValueError('RVA not backed by DLL data')

def write_atomic(path, data, mode):
    fd, tmp = tempfile.mkstemp(prefix='.roffile-', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=['status', 'apply', 'restore'])
    ap.add_argument('--dll', type=Path, required=True, help='Path to your own roffile.dll')
    args = ap.parse_args()
    path = args.dll.expanduser().absolute()
    if path.is_symlink() or not path.is_file() or path.name.lower() != 'roffile.dll':
        ap.error('Provide an existing, regular roffile.dll (not a symlink)')
    bak = path.with_name(path.name + '.before-nul-guard')
    b = path.read_bytes()
    off = pe_file_offset(b, RVA)
    context = b[off-5:off+3]
    state = 'original' if context == ORIGINAL else 'patched' if context == PATCHED else 'unknown'
    print(f'DLL: {path}\nRVA: 0x{RVA:x} / file offset: 0x{off:x}\nSHA256: {sha(b)}\nState: {state}\nBackup: {bak} ({"present" if bak.exists() else "absent"})')
    if args.action == 'status':
        return
    print('IMPORTANT: Ensure the game and Wine processes using this DLL have exited.')
    if args.action == 'apply':
        if state == 'patched':
            if bak.is_file() and sha(bak.read_bytes()) == ORIGINAL_SHA256:
                print('Already patched, with verified original backup.')
                return
            raise ValueError('Patched DLL has no verified original backup; refusing')
        if state != 'original' or sha(b) != ORIGINAL_SHA256:
            raise ValueError('This DLL build has NOT been validated. Refusing to patch.')
        if bak.exists():
            raise ValueError('Backup path already exists; refusing to overwrite')
        shutil.copy2(path, bak)
        if sha(bak.read_bytes()) != ORIGINAL_SHA256:
            raise ValueError('Backup verification failed; no patch applied')
        modified = bytearray(b)
        modified[off] = 0x90
        if modified[off-5:off+3] != PATCHED:
            raise ValueError('Internal patch verification failed')
        write_atomic(path, modified, path.stat().st_mode & 0o777)
        if path.read_bytes() != modified:
            raise ValueError('Post-write verification failed; original backup retained')
        print('Applied one-byte patch. Backup retained. New SHA256:', sha(modified))
    else:
        if not bak.is_file():
            raise ValueError('No backup available')
        original = bak.read_bytes()
        if sha(original) != ORIGINAL_SHA256:
            raise ValueError('Backup does not match validated original DLL')
        if state not in ('original', 'patched'):
            raise ValueError('Unexpected current DLL bytes; refusing restore')
        expected_patched = bytearray(original)
        expected_patched[off] = 0x90
        if b not in (original, bytes(expected_patched)):
            raise ValueError('Current DLL differs beyond the approved one-byte patch')
        write_atomic(path, original, path.stat().st_mode & 0o777)
        if path.read_bytes() != original:
            raise ValueError('Restoration verification failed; backup retained')
        print('Original restored. Backup retained at:', bak)

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as e:
        sys.exit(f'ERROR: {e}')
