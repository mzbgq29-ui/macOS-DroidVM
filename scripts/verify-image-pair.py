#!/usr/bin/env python3
"""Read-only checks of an unpacked macOS-DroidVM image set; no guest boot implied."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while data := f.read(8 << 20):
            h.update(data)
    return h.hexdigest()


class Fat32:
    def __init__(self, path):
        self.handle = path.open('rb')
        self.data = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
        d = self.data
        assert d[510:512] == b'\x55\xaa', 'missing FAT boot signature'
        self.sector = struct.unpack_from('<H', d, 11)[0]
        self.cluster = d[13] * self.sector
        reserved = struct.unpack_from('<H', d, 14)[0]
        fats = d[16]
        sectors_per_fat = struct.unpack_from('<I', d, 36)[0]
        assert not struct.unpack_from('<H', d, 17)[0], 'not FAT32'
        assert self.cluster and sectors_per_fat, 'bad FAT32 BPB'
        self.fat = reserved * self.sector
        self.base = (reserved + fats * sectors_per_fat) * self.sector
        self.root = struct.unpack_from('<I', d, 44)[0]

    def chain(self, first):
        seen = set()
        cluster = first
        while 2 <= cluster < 0x0ffffff8:
            assert cluster not in seen, 'FAT cluster loop'
            seen.add(cluster)
            start = self.base + (cluster - 2) * self.cluster
            assert start + self.cluster <= len(self.data), 'cluster outside image'
            yield memoryview(self.data)[start:start + self.cluster]
            cluster = struct.unpack_from('<I', self.data, self.fat + cluster * 4)[0] & 0x0fffffff

    def directory(self, first):
        lfn = {}
        for block in self.chain(first):
            for off in range(0, len(block), 32):
                entry = bytes(block[off:off + 32])
                if entry[0] == 0:
                    return
                if entry[0] == 0xe5:
                    lfn = {}
                    continue
                attr = entry[11]
                if attr == 0x0f:
                    seq = entry[0] & 0x1f
                    lfn[seq] = entry[1:11] + entry[14:26] + entry[28:32]
                    continue
                short = entry[:8].decode('ascii').rstrip()
                ext = entry[8:11].decode('ascii').rstrip()
                name = short + ('.' + ext if ext else '')
                if lfn:
                    name = b''.join(lfn[k] for k in sorted(lfn)).decode('utf-16le').split('\0', 1)[0].rstrip('\uffff')
                lfn = {}
                if attr & 8:
                    continue
                cluster = struct.unpack_from('<H', entry, 26)[0] | struct.unpack_from('<H', entry, 20)[0] << 16
                size = struct.unpack_from('<I', entry, 28)[0]
                yield name, cluster, size, bool(attr & 16)

    def locate(self, path):
        cluster = self.root
        parts = Path(path).parts
        for i, part in enumerate(parts):
            found = [e for e in self.directory(cluster) if e[0].casefold() == part.casefold()]
            assert len(found) == 1, f'FAT path missing or ambiguous: {path} ({part})'
            name, cluster, size, is_dir = found[0]
            assert i == len(parts) - 1 or is_dir, f'not a directory: {part}'
        return cluster, size

    def read(self, path):
        cluster, size = self.locate(path)
        return b''.join(bytes(b) for b in self.chain(cluster))[:size]

    def hash(self, path):
        cluster, size = self.locate(path)
        h = hashlib.sha256()
        left = size
        for block in self.chain(cluster):
            h.update(block[:left])
            left -= min(left, len(block))
            if not left:
                break
        assert left == 0, f'truncated FAT file: {path}'
        return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    folder = args.directory
    manifest = json.loads((folder / 'manifest.json').read_text())
    layout = json.loads((folder / 'disk.json').read_text())
    report = {'scope': 'static integrity and pairing only; hardware boot not tested',
              'device_boot_tested': False, 'performance_tested': False, 'commit': manifest['commit'],
              'tag': manifest['tag'], 'dirty': manifest['dirty'], 'root_uuid': layout['system']['uuid'], 'checks': {}}
    checks = report['checks']
    checks['boot_sha256'] = sha256(folder / 'boot.img')
    assert checks['boot_sha256'] == manifest['boot_img'], 'boot.img/manifest mismatch'
    checks['trustcache_sha256'] = sha256(folder / 'kernel.macho.trustcache')
    assert checks['trustcache_sha256'] == manifest['trustcache'], 'trustcache/manifest mismatch'
    fat = Fat32(folder / 'boot.img')
    payload = 'EFI/UniXNU/Payloads/'
    checks['embedded_kc_sha256'] = fat.hash(payload + 'kernel.macho')
    assert checks['embedded_kc_sha256'] == manifest['kc'], 'embedded kernel collection mismatch'
    checks['embedded_trustcache_sha256'] = fat.hash(payload + 'kernel.macho.trustcache')
    assert checks['embedded_trustcache_sha256'] == checks['trustcache_sha256'], 'embedded trustcache mismatch'
    checks['seed_sha256'] = sha256(folder / layout['seed'])
    checks['embedded_seed_sha256'] = fat.hash(payload + 'scratch-data.img')
    assert checks['embedded_seed_sha256'] == checks['seed_sha256'], 'embedded seed mismatch'
    adt = fat.read(payload + 'kernel.macho.adt')
    assert layout['system']['uuid'].upper().encode() in adt.upper(), 'ADT root UUID/disk.json mismatch'
    checks['adt_root_uuid_match'] = True
    checks['adt_sha256'] = hashlib.sha256(adt).hexdigest()
    report['boot_menu'] = fat.read('EFI/UniXNU/unixnu.toml').decode()
    seed = (folder / layout['seed']).read_bytes()
    assert seed[:8] == b'DBRDISK1', 'seed header mismatch'
    seed_version, page, logical, extent_count = struct.unpack_from('<IIQQ', seed, 8)
    assert seed_version == 1 and page == 4096 and extent_count == 0 and len(seed) == 32 and logical == layout['bytes'], 'seed size/version mismatch'
    store = folder / layout['store']
    with store.open('rb') as f:
        header = f.read(8192)
    assert header[:16] == b'DroidVMDataStore', 'store label mismatch'
    assert header[4096:4104] == b'SHNGDATA', 'store overlay header mismatch'
    overlay_version, header_bytes, pages = struct.unpack_from('<IIQ', header, 4104)
    assert overlay_version == 1 and header_bytes == 64 and pages * page == logical, 'store overlay geometry mismatch'
    # DarwinBoot 85332b3 Test/packed_ramdisk.py: disks over 2 GiB use
    # SHA256(SHNGSEED2 + little-endian logical size + nonzero pages/indexes).
    assert logical > 2 * 1024**3, 'this verifier expects the k27 large empty seed'
    seed_identity = hashlib.sha256(b'SHNGSEED2' + struct.pack('<Q', logical)).digest()
    assert header[4120:4152] == seed_identity, 'store seed identity mismatch'
    checks['store_seed_identity_match'] = True
    window = (2 + (pages + page * 8 - 1) // (page * 8)) * page
    assert window == layout['window_offset'], 'store page-window mismatch'
    assert store.stat().st_size == window + logical, 'store file length mismatch'
    checks['store_geometry_match'] = True
    report['store_logical_bytes'] = store.stat().st_size
    report['store_allocated_bytes'] = store.stat().st_blocks * 512
    report['passed'] = True
    text = json.dumps(report, indent=2)
    print(text)
    if args.report:
        args.report.write_text(text + '\n')


if __name__ == '__main__':
    main()
