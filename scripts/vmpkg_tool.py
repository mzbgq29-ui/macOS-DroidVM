#!/usr/bin/env python3
"""Stream a portable DroidVM v1 .vmpkg or inspect it without extraction.

Format is matched to App 2554f0c8 / daemon ed9837be. No device or GitHub APIs.
GNU regular tar entries are used, never GNU/PAX sparse entries. Sparse input
files are read as their logical byte stream and compressed directly to output.
"""
import argparse
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import threading
import time

HEADER = struct.Struct('<6sHHHHHQ')
CODES = {'NONE': 0, 'GZIP': 1, 'XZ': 2, 'ZSTD': 3}
BLOCK = 4096
CHUNK = 1 << 20


def align(value):
    return (value + BLOCK - 1) // BLOCK * BLOCK


def strict_align(value):
    return value // BLOCK * BLOCK + BLOCK


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        while data := handle.read(CHUNK):
            digest.update(data)
    return digest.hexdigest()


def regular_name(name):
    return isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,98}', name) and name != 'manifest.json'


def forbid_credentials(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if child and re.search(r'password|passwd|token|secret|private.?key|credential', key, re.I):
                raise ValueError('Nonempty credential field is not allowed in the package manifest')
            forbid_credentials(child)
    elif isinstance(value, list):
        for child in value:
            forbid_credentials(child)


def validate_manifest(manifest, portable=False):
    if portable:
        forbid_credentials(manifest)
    if manifest.get('format') != 'vmpkg' or manifest.get('manifest_version') != 1:
        raise ValueError('This tool emits/validates the plain attached-disk v1 subset only')
    if not isinstance(manifest.get('app_version_code'), int) or not 0 <= manifest['app_version_code'] <= 65535:
        raise ValueError('app_version_code must fit the uint16 header')
    if manifest.get('compression') not in CODES:
        raise ValueError('Manifest compression must be NONE/GZIP/XZ/ZSTD')
    vm = manifest.get('vm')
    if not isinstance(vm, dict) or not isinstance(vm.get('name'), str) or not vm['name']:
        raise ValueError('Manifest needs a named vm object')
    for key in ('disks', 'boots', 'networks'):
        if not isinstance(manifest.get(key), list):
            raise ValueError('Manifest needs array: ' + key)
    declared = {}
    indices = []
    for kind in ('disks', 'boots'):
        for row in manifest[kind]:
            name = row.get('archive_path')
            if not regular_name(name) or name in declared:
                raise ValueError('Use unique, short, plain archive basenames')
            if not regular_name(row.get('name')) or type(row.get('size')) is not int or not 0 <= row['size'] <= (1 << 63) - 1:
                raise ValueError('Invalid declared filename or size')
            declared[name] = row
            if kind == 'disks':
                if row.get('attached', True) is not True or row.get('backing_archive', ''):
                    raise ValueError('Backing chains require manifest v2, outside this v1 packager')
                if row.get('format', '').lower() not in ('raw', 'qcow2') or row.get('bus', '').lower() != 'virtio':
                    raise ValueError('Portable target disks must explicitly use raw/qcow2 + virtio')
                indices.append(row.get('index'))
            elif row.get('kind') not in ('uefi', 'kernel', 'initrd'):
                raise ValueError('Boot kind must be one the importer remaps')
            if portable and row.get('path', ''):
                raise ValueError('Packaged source paths must be blank; importer assigns actual paths')
    if sorted(indices) != list(range(len(indices))):
        raise ValueError('Attached disk indices must be unique contiguous slots starting at zero')
    refs = set()
    for network in manifest['networks']:
        ref = network.get('pkg_network_ref', '')
        if network.get('schema') != 2 or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', ref) or ref in refs:
            raise ValueError('Packaged networks need schema 2 and a unique pkg_network_ref')
        refs.add(ref)
    for nic in vm.get('networks', []):
        if nic.get('pkg_network_ref') and nic['pkg_network_ref'] not in refs:
            raise ValueError('VM network ref does not match packaged networks')
        if portable and any(nic.get(key) for key in ('network_id', 'tap_name')):
            raise ValueError('Portable VM NICs must use pkg_network_ref instead of host network IDs')
    if portable:
        if vm.get('disks'):
            raise ValueError('Omit vm.disks or use []: importer reconstructs it from manifest disk slots')
        for option in vm.get('extra_options', []):
            if not isinstance(option, str) or '/' in option or option.partition('=')[0] in (
                    '--block', '--virtio-mmio-block', '--dump-device-tree-blob', '--bios', '--pflash', '--initrd'):
                raise ValueError('Portable package must not depend on extra_options file paths')
        boot = vm.get('boot', {})
        if boot.get('protocol', '').lower() == 'uefi':
            if boot.get('uefi', {}).get('firmware', '') or not any(row.get('kind') == 'uefi' for row in manifest['boots']):
                raise ValueError('UEFI package must have a blank firmware path and a kind=uefi boot file')
            if boot.get('uefi', {}).get('vars_enabled', False):
                raise ValueError('This portable subset leaves UEFI vars disabled; importer does not package/remap vars')
    return declared


class HashingReader:
    def __init__(self, handle):
        self.handle, self.hash = handle, hashlib.sha256()
    def read(self, count=-1):
        data = self.handle.read(count)
        self.hash.update(data)
        return data


@contextmanager
def encoder(output, compression):
    if compression == 'NONE':
        yield output
    elif compression == 'GZIP':
        with gzip.GzipFile(fileobj=output, mode='wb', compresslevel=6, mtime=0) as stream:
            yield stream
    elif compression == 'XZ':
        with lzma.LZMAFile(output, mode='wb', preset=6) as stream:
            yield stream
    else:
        output.flush()
        process = subprocess.Popen(['zstd', '-q', '-T0', '-3', '-c'], stdin=subprocess.PIPE, stdout=output)
        try:
            yield process.stdin
            process.stdin.close()
            if process.wait():
                raise ValueError('zstd encoder failed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if not process.stdin.closed:
                try:
                    process.stdin.close()
                except OSError:
                    pass


def pack(manifest, paths, output_path, compression):
    manifest = json.loads(json.dumps(manifest))
    manifest['compression'] = compression
    declared = validate_manifest(manifest, portable=True)
    if set(declared) != set(paths):
        raise ValueError('--file entries must exactly match declared disk and boot files')
    for name, path in paths.items():
        if Path(path).is_symlink() or not Path(path).is_file() or Path(path).stat().st_size != declared[name]['size']:
            raise ValueError('Input is not a regular file of the declared size: ' + name)
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=4).encode('utf-8')
    if not 0 < len(manifest_bytes) <= 65535:
        raise ValueError('UTF-8 manifest does not fit its 16-bit header field')
    output_path = Path(output_path)
    partial = output_path.with_name(output_path.name + '.partial')
    report_path = output_path.with_name(output_path.name + '.report.json')
    if any(path.exists() or path.is_symlink() for path in (output_path, partial, report_path)):
        raise ValueError('Refusing to replace existing output, partial package or report')
    payloads = {}
    try:
        with partial.open('x+b') as output:
            output.write(bytes(BLOCK))
            output.write(manifest_bytes)
            output.write(bytes(strict_align(output.tell()) - output.tell()))
            data_start = output.tell()
            with encoder(output, compression) as compressed:
                with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.GNU_FORMAT) as archive:
                    def info(name, size):
                        row = tarfile.TarInfo(name)
                        row.size, row.mode, row.uid, row.gid = size, 0o644, 0, 0
                        row.mtime = int(manifest.get('created_at', 0)) // 1000
                        return row
                    archive.addfile(info('manifest.json', len(manifest_bytes)), io.BytesIO(manifest_bytes))
                    for name, path in paths.items():
                        with Path(path).open('rb') as source:
                            hashed = HashingReader(source)
                            archive.addfile(info(name, declared[name]['size']), hashed)
                            if source.read(1):
                                raise ValueError('Source grew while packaging: ' + name)
                            actual_sha = hashed.hash.hexdigest()
                        if declared[name].get('sha256') and declared[name]['sha256'] != actual_sha:
                            raise ValueError('Input does not match declared SHA-256: ' + name)
                        payloads[name] = {'size': declared[name]['size'], 'sha256': actual_sha}
            data_end = output.tell()
            output.write(bytes(align(data_end) - data_end))
            output.seek(0)
            output.write(HEADER.pack(b'VMPKG\0', manifest['manifest_version'], manifest['app_version_code'],
                                     len(manifest_bytes), CODES[compression], 0, data_end - data_start))
            output.flush()
            os.fsync(output.fileno())
        os.link(partial, output_path)
        partial.unlink()
    except Exception:
        # Keep a failed partial for diagnosis, never present it as a finished package.
        raise
    report = {'status': 'package_written_not_device_tested', 'path': str(output_path),
              'package_bytes': output_path.stat().st_size, 'package_sha256': sha_file(output_path),
              'manifest_bytes': len(manifest_bytes), 'compression': compression,
              'compressed_data_bytes': data_end - data_start, 'logical_payload_bytes': sum(row['size'] for row in payloads.values()),
              'payloads': payloads}
    with report_path.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    return report


class LimitedReader:
    def __init__(self, handle, size):
        self.handle, self.remaining = handle, size
    def read(self, count=-1):
        count = self.remaining if count < 0 else min(count, self.remaining)
        data = self.handle.read(count)
        self.remaining -= len(data)
        if count and not data:
            raise ValueError('Truncated compressed data')
        return data


@contextmanager
def decoder(limited, compression):
    if compression == 'NONE':
        yield limited
    elif compression == 'GZIP':
        with gzip.GzipFile(fileobj=limited, mode='rb') as stream:
            yield stream
    elif compression == 'XZ':
        with lzma.LZMAFile(limited, mode='rb') as stream:
            yield stream
    else:
        process = subprocess.Popen(['zstd', '-q', '-d', '-c'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        errors = []
        def feed():
            try:
                while data := limited.read(CHUNK):
                    process.stdin.write(data)
                process.stdin.close()
            except Exception as error:
                errors.append(error)
                try:
                    process.stdin.close()
                except OSError:
                    pass
        thread = threading.Thread(target=feed, daemon=True)
        thread.start()
        try:
            yield process.stdout
            thread.join()
            if process.wait() or errors:
                raise ValueError('zstd decoder or bounded input failed')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            thread.join(timeout=5)
            process.stdout.close()


def zero_padding(handle, count):
    if handle.read(count) != bytes(count):
        raise ValueError('Nonzero or truncated package padding')


def read_exact(handle, count):
    chunks = []
    remaining = count
    while remaining:
        data = handle.read(remaining)
        if not data:
            raise ValueError('Truncated tar entry or header')
        chunks.append(data)
        remaining -= len(data)
    return b''.join(chunks)


def plain_tar_members(stream):
    """Inspect raw headers so Python cannot silently interpret a PAX override.

    The packager emits only short GNU regular headers. The native importer
    skips PAX/sparse metadata, so accepting Python's interpreted version of
    those entries would prove something different from native import.
    """
    while True:
        block = read_exact(stream, tarfile.BLOCKSIZE)
        if block == bytes(tarfile.BLOCKSIZE):
            zero_padding(stream, tarfile.BLOCKSIZE)
            tail_bytes = 0
            while tail := stream.read(CHUNK):
                if any(tail):
                    raise ValueError('Nonzero bytes after tar end marker')
                tail_bytes += len(tail)
            if tail_bytes % tarfile.BLOCKSIZE:
                raise ValueError('Tar trailer is not block aligned')
            return
        try:
            member = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
        except (tarfile.HeaderError, UnicodeError) as error:
            raise ValueError('Invalid tar header') from error
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.pax_headers or member.sparse:
            raise ValueError('Only plain regular tar files are supported; extensions, sparse/PAX/link entries are forbidden')
        if member.name != 'manifest.json' and not regular_name(member.name):
            raise ValueError('Tar entries must use the declared short basenames')
        if not 0 <= member.size <= (1 << 63) - 1:
            raise ValueError('Tar size exceeds native signed 64-bit range')
        source = LimitedReader(stream, member.size)
        yield member, source
        if source.remaining:
            raise ValueError('Tar member was not completely consumed')
        zero_padding(stream, (-member.size) % tarfile.BLOCKSIZE)


def inspect(path, verify=False, expected_report=None):
    path = Path(path)
    with path.open('rb') as handle:
        raw = handle.read(HEADER.size)
        if len(raw) != HEADER.size:
            raise ValueError('Truncated header')
        magic, version, app_code, manifest_size, compression_code, volume_count, data_size = HEADER.unpack(raw)
        if (magic != b'VMPKG\0' or version != 1 or not 0 < manifest_size <= 65535
                or compression_code not in CODES.values() or not 0 < data_size <= (1 << 63) - 1):
            raise ValueError('Unsupported package header')
        if volume_count:
            raise ValueError('This validator handles single-file packages only')
        compression = next(name for name, code in CODES.items() if code == compression_code)
        zero_padding(handle, BLOCK - HEADER.size)
        manifest_bytes = handle.read(manifest_size)
        manifest = json.loads(manifest_bytes.decode('utf-8'))
        declared = validate_manifest(manifest)
        if (manifest['manifest_version'], manifest['app_version_code'], manifest['compression']) != (version, app_code, compression):
            raise ValueError('Header and manifest metadata disagree')
        data_start = strict_align(BLOCK + manifest_size)
        zero_padding(handle, data_start - handle.tell())
        if path.stat().st_size != align(data_start + data_size):
            raise ValueError('Package file length does not match data_size/alignment')
        report = {'status': 'header_manifest_valid', 'path': str(path), 'manifest_version': version,
                  'app_version_code': app_code, 'compression': compression, 'volume_count': volume_count,
                  'data_start': data_start, 'compressed_data_bytes': data_size,
                  'package_bytes': path.stat().st_size, 'vm_name': manifest['vm']['name'], 'payloads': {}}
        if verify:
            limited = LimitedReader(handle, data_size)
            seen = set()
            expected = json.loads(Path(expected_report).read_text()) if expected_report else None
            with decoder(limited, compression) as stream:
                for index, (member, source) in enumerate(plain_tar_members(stream)):
                    if member.name in seen:
                        raise ValueError('Repeated tar entry')
                    seen.add(member.name)
                    if index == 0:
                        if member.name != 'manifest.json' or member.size != len(manifest_bytes) or read_exact(source, member.size) != manifest_bytes:
                            raise ValueError('First tar entry must exactly mirror manifest.json')
                        continue
                    if member.name not in declared or member.size != declared[member.name]['size']:
                        raise ValueError('Unexpected tar entry or declared size mismatch')
                    digest = hashlib.sha256()
                    while data := source.read(CHUNK):
                        digest.update(data)
                    actual_sha = digest.hexdigest()
                    wanted = declared[member.name].get('sha256')
                    if expected:
                        wanted = expected['payloads'][member.name]['sha256']
                    if wanted and wanted != actual_sha:
                        raise ValueError('Payload SHA-256 mismatch: ' + member.name)
                    report['payloads'][member.name] = {'size': member.size, 'sha256': actual_sha,
                                                     'sha256_expected_matched': bool(wanted)}
            if limited.remaining or seen != {'manifest.json', *declared}:
                raise ValueError('Compressed stream incomplete or a declared file is missing')
            zero_padding(handle, align(data_start + data_size) - (data_start + data_size))
            if handle.read(1):
                raise ValueError('Trailing data after package')
            report['package_sha256'] = sha_file(path)
            if expected and expected['package_sha256'] != report['package_sha256']:
                raise ValueError('Whole-package SHA-256 mismatch')
            report['status'] = 'payloads_verified_not_device_tested'
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('pack')
    build.add_argument('--manifest', type=Path, required=True)
    build.add_argument('--file', action='append', default=[], metavar='ENTRY=PATH')
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--compression', choices=('none', 'gzip', 'xz', 'zstd'), default='zstd')
    check = sub.add_parser('inspect')
    check.add_argument('package', type=Path)
    check.add_argument('--verify-payloads', action='store_true')
    check.add_argument('--expected-report', type=Path)
    args = parser.parse_args()
    if args.command == 'pack':
        paths = {}
        for item in args.file:
            entry, separator, filename = item.partition('=')
            if not separator or entry in paths:
                parser.error('--file must use unique ENTRY=PATH names')
            paths[entry] = Path(filename)
        result = pack(json.loads(args.manifest.read_text()), paths, args.output, args.compression.upper())
    else:
        result = inspect(args.package, args.verify_payloads, args.expected_report)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
