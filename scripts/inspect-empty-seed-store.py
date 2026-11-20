#!/usr/bin/env python3
"""Read-only preflight for the upstream empty-seed SHNGDATA -> GPT converter.

This helper does not convert, mount, repair or write a disk. It is local review
code, not an upstream tool. It supports only a 32-byte DBRDISK1 empty seed.
"""
import argparse
import hashlib
import json
import stat
import struct
import zlib
from pathlib import Path

PAGE = 4096
MAX_LOGICAL = 1024**4


def require(ok, message):
    if not ok:
        raise ValueError(message)


def regular(path):
    require(not path.is_symlink(), f'symlink rejected: {path}')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), f'not a regular local file: {path}')
    return info


def fletcher64(data):
    lo = hi = 0
    for (word,) in struct.iter_unpack('<I', data):
        lo = (lo + word) % 0xffffffff
        hi = (hi + lo) % 0xffffffff
    c0 = 0xffffffff - ((lo + hi) % 0xffffffff)
    c1 = 0xffffffff - ((lo + c0) % 0xffffffff)
    return struct.pack('<II', c0, c1)


def inspect(seed_path, store_path, layout_path=None):
    seed_stat = regular(seed_path)
    before = regular(store_path)
    require(seed_stat.st_size == 32, 'requires exactly 32 bytes of empty DBRDISK1 seed')
    seed = seed_path.read_bytes()
    magic, version, page, logical, extents = struct.unpack('<8sIIQQ', seed)
    require((magic, version, page, extents) == (b'DBRDISK1', 1, PAGE, 0), 'nonempty or unsupported seed')
    require(0 < logical <= MAX_LOGICAL and logical % PAGE == 0, 'invalid seed logical size')
    pages = logical // PAGE
    bitmap_bytes = ((pages + PAGE * 8 - 1) // (PAGE * 8)) * PAGE
    window = 2 * PAGE + bitmap_bytes
    require(before.st_size == window + logical, 'store file length mismatch')
    if logical > 2 * 1024**3:
        identity = hashlib.sha256(b'SHNGSEED2' + struct.pack('<Q', logical)).digest()
    else:
        digest = hashlib.sha256()
        zero = bytes(1024**2)
        for offset in range(0, logical, len(zero)):
            digest.update(zero[:min(len(zero), logical - offset)])
        identity = digest.digest()
    with store_path.open('rb') as handle:
        label = handle.read(PAGE)
        header = handle.read(PAGE)
        require(label[:20] == b'DroidVMDataStore\x01\0\0\0', 'store label/version mismatch')
        require(header[:8] == b'SHNGDATA', 'missing SHNGDATA header')
        require(struct.unpack_from('<IIQ', header, 8) == (1, 64, pages), 'overlay header/geometry mismatch')
        require(zlib.crc32(header[:60]) == struct.unpack_from('<I', header, 60)[0], 'overlay header CRC32 mismatch')
        require(header[24:56] == identity, 'overlay/seed identity mismatch')
        bitmap = handle.read(bitmap_bytes)
        require(len(bitmap) == bitmap_bytes, 'short overlay bitmap')
        require(bitmap[0] & 1, 'APFS container page 0 not present in overlay')
        if pages % 8:
            require(bitmap[pages // 8] >> (pages % 8) == 0, 'bitmap bits past logical end')
        require(not any(bitmap[(pages + 7) // 8:]), 'bitmap padding is nonzero')
        handle.seek(window)
        nx = handle.read(PAGE)
    require(nx[32:36] == b'NXSB', 'APFS NXSB missing at logical offset 0')
    require(struct.unpack_from('<I', nx, 36)[0] == PAGE, 'unexpected APFS block size')
    require(struct.unpack_from('<Q', nx, 40)[0] * PAGE == logical, 'APFS size does not match seed/store')
    require(fletcher64(nx[8:]) == nx[:8], 'APFS block-0 Fletcher checksum mismatch')
    if layout_path:
        regular(layout_path)
        layout = json.loads(layout_path.read_text())
        require(layout['bytes'] == logical and layout['window_offset'] == window, 'disk.json geometry mismatch')
    after = store_path.stat()
    require((before.st_size, before.st_mtime_ns, before.st_ino) ==
            (after.st_size, after.st_mtime_ns, after.st_ino), 'source changed during preflight')
    return dict(passed=True, scope='read-only geometry/identity/block-0 preflight; not full APFS or boot verification',
                seed=str(seed_path), store=str(store_path), seed_sha256=hashlib.sha256(seed).hexdigest(),
                logical_bytes=logical, page_size=PAGE, pages=pages, bitmap_bytes=bitmap_bytes,
                window_offset=window, present_pages=sum(b.bit_count() for b in bitmap),
                seed_identity=identity.hex(), output_partition_offset=1024**2,
                expected_output_bytes=logical + 2 * 1024**2,
                expected_partition_type='69646961-6700-11AA-AA11-00306543ECAC',
                limitations=['No full APFS tree/volume UUID validation.',
                             'No claim that the source VM is stopped; caller must ensure it.',
                             'No conversion, guest boot, device operation or performance test.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('seed', type=Path)
    parser.add_argument('store', type=Path)
    parser.add_argument('--layout', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.seed, args.store, args.layout), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
