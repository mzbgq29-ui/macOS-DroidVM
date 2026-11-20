#!/usr/bin/env python3
"""Controlled CI plumbing for an encrypted transport of a real DroidVM package.

Never executes guest code. No key or account credential is read by this helper.
All decrypted images and raw packager reports remain in the private work tree;
only allowlisted encrypted parts and sanitized summaries enter dist/.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
from urllib.parse import unquote, urlparse
import uuid
import zlib

MIB, GIB = 1024**2, 1024**3
NAME = 'macOS-27.2-DroidVM.vmpkg'
SOURCE_SHA = '524d27bf57ae92375aa39e3a81e11727c08973ff'
SOURCE_RUN = 44723953351
CANDIDATE_BRANCH = 'redmi-native-recovery'
FIRMWARE_TAG = 'image-27.2-1'
FIRMWARE_SHA = 'ab69e017d2965d73ed2057bed8922a3908639021984bf250ec530cb6cb60cc4d'
SOURCE_PART_SHAS = (
    '89883242882374d5169c18029f972b14be93027d72f161e1e66acd3e156d591e',
    '88917653872161cdc0b73ff9d03790cbec9ed2ed99861d10cdfd8ec9e4bfe915',
    'cb67fb6db0024974237df2ff1c089e8f366b755ae3d99bf912a088a57e2c337e',
    'c9858bcfaf0c598887357749d09d93cc66db742655ec6657c724b6e357a08d74',
    '66c4d95c9861acb09c6c8a8cd70ccef2bd88c3bed15d7d033d8a17e1249951ec',
    '46f16f2181a0984f08c9e1ee3dc26315512b28e9c014cfc53d6bbb72e2d0d637',
    '245e91254c2493856381fe772975100a69a00d739e0654ad3d28cbee578cfbf7',
)
SOURCE_METADATA_SHAS = {
    'manifest.json': '18d020e3f0ddc8e71abb4bf8fb4a62b2ae3eca95a63be76047c7fa545fd3c489',
    'disk.json': '2167cb2b4b56c50754afa10445f0e9dd9110fb60d76e15f7ba47c58a1011e1fd',
}
PLAIN_INPUTS = ('disk.json', 'manifest.json', 'image.tar.zst.enc.sha256')
PAYLOADS = ('boot.img', 'data-pcie.img', 'edk2-macos.fd')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        while data := handle.read(8 * MIB):
            digest.update(data)
    return digest.hexdigest()


def gh(endpoint):
    return json.loads(subprocess.check_output(['gh', 'api', endpoint], text=True))


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f'expected regular file: {path.name}')
    return path


def checked_url(repo, tag, name, value):
    parsed = urlparse(value)
    require(parsed.scheme == 'https' and parsed.netloc == 'github.com' and not parsed.query and not parsed.fragment,
            'unexpected public release URL')
    require(unquote(parsed.path) == f'/{repo}/releases/download/{tag}/{name}', 'release URL path mismatch')
    return value


def curl_asset(asset, path):
    path = Path(path)
    if path.exists() and path.stat().st_size == asset['size'] and 'sha256:' + sha(path) == asset['digest']:
        return
    if path.exists() and path.stat().st_size >= asset['size']:
        path.unlink()  # A complete but corrupt file must not be resumed at EOF.
    subprocess.run(['curl', '--proto', '=https', '--proto-redir', '=https', '--fail', '--location', '--retry', '6', '--retry-all-errors', '--retry-delay', '5',
                    '--connect-timeout', '30', '--max-time', '5400', '--continue-at', '-', '--silent', '--show-error',
                    '--output', str(path), asset['browser_download_url']], check=True)
    regular(path)
    require(path.stat().st_size == asset['size'], f'download length mismatch: {path.name}')
    require('sha256:' + sha(path) == asset['digest'], f'download SHA-256 mismatch: {path.name}')
    print(f'verified {path.name}: {path.stat().st_size} bytes', flush=True)


def release_assets(repo, tag):
    release = gh(f'repos/{repo}/releases/tags/{tag}')
    assets = {a['name']: a for a in release['assets']}
    require(len(assets) == len(release['assets']), 'duplicate source release asset names')
    return release, assets


def checked_asset(assets, repo, tag, name):
    require(name in assets and assets[name]['state'] == 'uploaded', f'missing source asset: {name}')
    asset = assets[name]
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', asset.get('digest') or ''), f'missing server digest: {name}')
    checked_url(repo, tag, name, asset['browser_download_url'])
    return asset


def candidate_metadata(root, source, repo, tag, assets):
    expected = tag + '-plain'
    endpoint = f"repos/{repo}/actions/runs/{source['id']}/artifacts"
    items = gh(f'{endpoint}?name={expected}')['artifacts']
    matches = [a for a in items if a['name'] == expected and a['expired'] is False]
    require(len(matches) == 1, f'expected one live Actions artifact: {expected}')
    artifact = matches[0]
    require(type(artifact['size_in_bytes']) is int and 0 < artifact['size_in_bytes'] <= MIB,
            'candidate metadata artifact exceeds its size limit')
    out = root / 'private/source-artifact'
    out.mkdir()
    subprocess.run(['gh', 'run', 'download', str(source['id']), '--repo', repo, '--name', expected,
                    '--dir', str(out)], check=True)
    metadata_shas = {}
    for name in PLAIN_INPUTS:
        path = regular(out / name)
        asset = checked_asset(assets, repo, tag, name)
        digest = sha(path)
        require(0 < path.stat().st_size <= MIB and asset['size'] == path.stat().st_size
                and asset['digest'] == f'sha256:{digest}', f'Actions artifact/Release mismatch: {name}')
        shutil.copyfile(path, root / 'plain' / name)
        if name in SOURCE_METADATA_SHAS:
            metadata_shas[name] = digest
    return metadata_shas, artifact['id']


def plan(root, source_run, candidate_commit=''):
    require(re.fullmatch(r'[0-9]+', source_run), 'source_run must be ASCII digits')
    if candidate_commit:
        require(re.fullmatch(r'[0-9a-f]{40}', candidate_commit), 'candidate commit must be a full lowercase Git SHA')
    else:
        require(int(source_run) == SOURCE_RUN, 'source run is outside this reviewed image pairing')
    repo = os.environ['GH_REPO']
    source = gh(f'repos/{repo}/actions/runs/{source_run}')
    require(source['id'] == int(source_run), 'source run ID mismatch')
    require(source['repository']['full_name'] == repo and source['head_repository']['full_name'] == repo, 'source repository mismatch')
    require(source['path'] == '.github/workflows/image.yml' and source['event'] == 'workflow_dispatch', 'source workflow/event mismatch')
    require(source['status'] == 'completed' and source['head_sha'] == (candidate_commit or SOURCE_SHA),
            'unreviewed or incomplete source run')
    if candidate_commit:
        require(source['head_branch'] == CANDIDATE_BRANCH and source['conclusion'] == 'success',
                'candidate requires a successful recovery branch image run')
    # The legacy source failed only at duplicate release upload; its separately
    # recovered parts and decrypted metadata remain pinned below.
    number = source['run_number']
    require(type(number) is int and number > 0, 'bad source run number')
    tag = f'image-27.2-{number}'
    release, assets = release_assets(repo, tag)
    for folder in ('parts', 'plain', 'raw', 'private', 'tools', 'package', 'dist'):
        (root / folder).mkdir(parents=True, exist_ok=True)
    if candidate_commit:
        metadata_shas, artifact_id = candidate_metadata(root, source, repo, tag, assets)
        _, firmware_assets = release_assets(repo, FIRMWARE_TAG)
    else:
        metadata_shas, firmware_assets = SOURCE_METADATA_SHAS, assets
        for name in PLAIN_INPUTS:
            curl_asset(checked_asset(assets, repo, tag, name), root / 'plain' / name)
            if name in metadata_shas:
                require(sha(root / 'plain' / name) == metadata_shas[name], f'unreviewed source metadata: {name}')
    firmware = checked_asset(firmware_assets, repo, FIRMWARE_TAG if candidate_commit else tag, 'edk2-macos.fd')
    require(firmware['digest'] == 'sha256:' + FIRMWARE_SHA and firmware['size'] == 4194304, 'unreviewed macOS firmware')
    curl_asset(firmware, root / 'raw/edk2-macos.fd')
    manifest, layout = read(root / 'plain/manifest.json'), read(root / 'plain/disk.json')
    require(manifest['commit'] == source['head_sha'] and manifest['dirty'] is False, 'source manifest commit/dirty mismatch')
    require(manifest['product'] == 'k27' and manifest['tag'] == manifest['env']['MACOS_TAG'] == layout['tag'] == '27.2', 'wrong image product')
    if candidate_commit:
        require(layout['seed'] == 'scratch-data.img' and layout['store'] == 'data-store.img',
                'unexpected candidate disk layout files')
        require(type(layout['bytes']) is int and 2 * GIB < layout['bytes'] and layout['bytes'] % 4096 == 0
                and type(layout['window_offset']) is int and layout['window_offset'] > 0
                and layout['window_offset'] % 4096 == 0, 'invalid candidate disk layout geometry')
        require(str(uuid.UUID(layout['system']['uuid'])) == layout['system']['uuid'].lower(),
                'noncanonical candidate root UUID')
    rows = []
    for line in (root / 'plain/image.tar.zst.enc.sha256').read_text().splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  (image\.tar\.zst\.enc\.[0-9]{3})', line)
        require(m is not None, 'bad source checksum row')
        rows.append((m[2], m[1]))
    names = [name for name, _ in rows]
    if candidate_commit:
        require(1 <= len(names) <= 16 and names == [f'image.tar.zst.enc.{i:03d}' for i in range(len(names))],
                'candidate source parts are missing, repeated or out of order')
        require(set(names) == {n for n in assets if n.startswith('image.tar.zst.enc.') and n not in PLAIN_INPUTS},
                'candidate Release contains missing or unexpected source parts')
    else:
        require(names == [f'image.tar.zst.enc.{i:03d}' for i in range(7)], 'need all seven source parts in order')
        require(tuple(digest for _, digest in rows) == SOURCE_PART_SHAS, 'source parts differ from reviewed image pairing')
    for index, (name, digest) in enumerate(rows):
        asset = checked_asset(assets, repo, tag, name)
        require(asset['digest'] == 'sha256:' + digest, f'server/source digest mismatch: {name}')
        if candidate_commit:
            size = asset['size']
            require(type(size) is int and 0 < size <= 1900 * MIB and size % 16 == 0
                    and (index == len(rows) - 1 or size == 1900 * MIB), f'invalid encrypted part size: {name}')
    if candidate_commit:
        total = sum(assets[name]['size'] for name in names)
        require(total >= 32 and total <= shutil.disk_usage(root).free - 2 * GIB, 'candidate source parts exceed available disk')
    summary = {k: source[k] for k in ('id', 'run_number', 'head_sha', 'path', 'event', 'status', 'conclusion', 'html_url', 'created_at')}
    summary['repository'] = repo
    source_plan = {'source_run': summary, 'source_release': release['html_url'], 'parts': names,
                   'assets': {**{n: assets[n] for n in [*PLAIN_INPUTS, *names]}, 'edk2-macos.fd': firmware}}
    if candidate_commit:
        summary['head_branch'] = source['head_branch']
        source_plan.update(candidate_commit=candidate_commit, source_metadata_shas=metadata_shas,
                           source_metadata_artifact_id=artifact_id)
    write(root / 'private/source-plan.json', source_plan)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write(f'source_number={number}\n')
    print(json.dumps(summary, indent=2))


def download(root, parallel):
    plan = read(root / 'private/source-plan.json')
    assets = plan['assets']
    names = plan.get('parts', [f'image.tar.zst.enc.{i:03d}' for i in range(7)])
    require(names and names == [f'image.tar.zst.enc.{i:03d}' for i in range(len(names))], 'invalid planned part sequence')
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        jobs = {pool.submit(curl_asset, assets[name], root / 'parts' / name): name for name in names}
        for job in as_completed(jobs):
            job.result()
    write(root / 'private/source-parts-verified.json', {'sha256_verified': True, 'parts': names})


def verify_source(root):
    """Bind decrypted image metadata to the pinned public release metadata."""
    expected = {'boot.img', 'data-store.img', 'scratch-data.img', 'disk.json',
                'manifest.json', 'kernel.macho.trustcache', 'edk2-macos.fd'}
    require({p.name for p in (root / 'raw').iterdir()} == expected, 'unexpected decrypted source payload set')
    for name in expected:
        regular(root / 'raw' / name)
    plan_path = root / 'private/source-plan.json'
    source_plan = read(plan_path) if plan_path.is_file() else {}
    candidate = source_plan.get('candidate_commit')
    metadata_shas = source_plan['source_metadata_shas'] if candidate else SOURCE_METADATA_SHAS
    require(set(metadata_shas) == set(SOURCE_METADATA_SHAS), 'invalid source metadata identity set')
    for name, digest in metadata_shas.items():
        require(sha(root / 'raw' / name) == digest == sha(root / 'plain' / name),
                f'decrypted/public metadata mismatch: {name}')
    require(sha(root / 'raw/edk2-macos.fd') == FIRMWARE_SHA, 'firmware changed after download')
    pair = read(root / 'private/source-pair-validation.json')
    require(pair['passed'] is True and pair['commit'] == (candidate or SOURCE_SHA) and pair['tag'] == '27.2'
            and pair['dirty'] is False and pair['device_boot_tested'] is False, 'unverified image pairing')
    if candidate:
        layout = read(root / 'raw/disk.json')
        require(pair['root_uuid'] == layout['system']['uuid'] and pair['store_logical_bytes']
                == layout['bytes'] + layout['window_offset'] == (root / 'raw/data-store.img').stat().st_size,
                'candidate root UUID/store length mismatch')
    else:
        require(pair['store_logical_bytes'] == 51541188608, 'unexpected source store length')
    run = source_plan['source_run']['id'] if candidate else SOURCE_RUN
    proof = {'passed': True, 'source_run': run, 'source_metadata_pinned_and_matched': True,
             'decrypted_payloads_regular': True, 'static_source_pairing_passed': True,
             'device_boot_tested': False, 'performance_tested': False}
    if candidate:
        proof.update(candidate_commit=candidate, source_metadata_artifact_id=source_plan['source_metadata_artifact_id'],
                     source_metadata_shas=metadata_shas)
    write(root / 'private/source-verified.json', proof)
    print(json.dumps(proof, indent=2))


def budget(root, phase):
    free = shutil.disk_usage(root).free
    if phase == 'convert':
        pre = read(root / 'private/store-preflight.json')
        extra = pre['present_pages'] * 4096 + 2 * MIB + 3 * GIB
    elif phase == 'package':
        extra = (root / 'raw/data-pcie.img').stat().st_blocks * 512 + (root / 'raw/boot.img').stat().st_size + 3 * GIB
    else:
        extra = (root / 'package' / NAME).stat().st_size + 2 * GIB
    require(free >= extra, f'{phase}: free physical bytes {free} below needed bytes {extra}')
    report = {'phase': phase, 'free_physical_bytes': free, 'required_additional_physical_bytes': extra, 'passed': True}
    write(root / f'private/budget-{phase}.json', report)
    print(json.dumps(report))


def gpt_header(handle, lba, sectors):
    handle.seek(lba * 512)
    header = handle.read(512)
    require(header[:8] == b'EFI PART', 'missing GPT header')
    revision, size, crc = struct.unpack_from('<III', header, 8)
    require(revision == 0x10000 and size == 92, 'unsupported GPT header')
    checked = bytearray(header[:size]); checked[16:20] = bytes(4)
    require(zlib.crc32(checked) == crc, 'GPT header CRC mismatch')
    current, other, first, last = struct.unpack_from('<QQQQ', header, 24)
    require(current == lba and other == (sectors - 1 if lba == 1 else 1), 'GPT current/backup LBA mismatch')
    table, count, width, entries_crc = struct.unpack_from('<QIII', header, 72)
    require(count == 128 and width == 128, 'unsupported GPT entries')
    require(table == (2 if lba == 1 else sectors - 33) and first == 34 and last == sectors - 34,
            'GPT entry table/usable range mismatch')
    handle.seek(table * 512); entries = handle.read(count * width)
    require(len(entries) == count * width and zlib.crc32(entries) == entries_crc, 'GPT entries CRC mismatch')
    return {'guid': header[56:72], 'first': first, 'last': last, 'entries': entries}


def verify_gpt(root):
    pre = read(root / 'private/store-preflight.json')
    logical = pre['logical_bytes']
    store, target = root / 'raw/data-store.img', root / 'raw/data-pcie.img'
    require(target.stat().st_size == logical + 2 * MIB, 'GPT disk length mismatch')
    text = (root / 'private/store-copy.log').read_text()
    match = re.search(r'copy_and_byte_verify=PASS bytes=([0-9]+)', text)
    require(match and int(match[1]) == pre['present_pages'] * 4096, 'two-pass copy verification missing/mismatched')
    with target.open('rb') as handle:
        sectors = target.stat().st_size // 512
        mbr = handle.read(512)
        require(mbr[510:512] == b'\x55\xaa' and mbr[450] == 0xee, 'protective MBR mismatch')
        primary, backup = gpt_header(handle, 1, sectors), gpt_header(handle, sectors - 1, sectors)
        require(primary == backup, 'primary/backup GPT contents differ')
        entry = primary['entries'][:128]
        require(uuid.UUID(bytes_le=entry[:16]) == uuid.UUID('69646961-6700-11AA-AA11-00306543ECAC'), 'GPT partition type mismatch')
        start, end = struct.unpack_from('<QQ', entry, 32)
        require(start == 2048 and end - start + 1 == logical // 512, 'GPT partition geometry mismatch')
        require(not any(primary['entries'][128:]), 'unexpected additional partition')
        handle.seek(MIB); target_nx = handle.read(4096)
    with store.open('rb') as handle:
        handle.seek(pre['window_offset']); source_nx = handle.read(4096)
    require(target_nx == source_nx and target_nx[32:36] == b'NXSB', 'APFS container block zero changed')
    report = {'passed': True, 'source_empty_seed_preflight_passed': True, 'two_pass_byte_verify_passed': True,
              'copied_present_bytes': int(match[1]), 'primary_backup_gpt_crc_passed': True,
              'apfs_container_block_zero_unchanged': True, 'apfs_container_uuid': str(uuid.UUID(bytes=target_nx[72:88])),
              'apfs_volume_bytes_preserved': True, 'logical_container_bytes': logical, 'gpt_disk_bytes': target.stat().st_size,
              'gpt_disk_allocated_bytes': target.stat().st_blocks * 512,
              'scope': 'Empty-seed reconstruction with byte-for-byte verification of all present pages; not a full APFS tree fsck or a guest boot.'}
    write(root / 'private/conversion-verified.json', report)
    print(json.dumps(report, indent=2))


def manifest(root, template):
    value = read(template)
    require(value['format'] == 'vmpkg' and value['manifest_version'] == 1 and value['app_version_code'] == 5090, 'unreviewed package format')
    require([(r['index'], r['archive_path']) for r in value['disks']] == [(0, 'boot.img'), (1, 'data-pcie.img')], 'unexpected disk mapping')
    require(len(value['boots']) == 1 and value['boots'][0]['kind'] == 'uefi' and value['boots'][0]['archive_path'] == 'edk2-macos.fd', 'unexpected boot mapping')
    require(not value['vm'].get('disks') and not value['vm']['boot']['uefi'].get('firmware') and not value['vm']['boot']['uefi'].get('vars_enabled', False), 'nonportable VM path/vars configuration')
    value['compression'] = 'ZSTD'
    if 'created_at' not in value:
        source = read(root / 'private/source-plan.json')['source_run']
        value['created_at'] = int(datetime.fromisoformat(source['created_at'].replace('Z', '+00:00')).timestamp() * 1000)
    for row in [*value['disks'], *value['boots']]:
        require(not row.get('path'), 'package source paths must be blank')
        path = regular(root / 'raw' / row['archive_path'])
        row['size'], row['sha256'] = path.stat().st_size, sha(path)
    write(root / 'private/package-manifest.json', value)
    write(root / 'private/template-identity.json', {'template_sha256': sha(template), 'effective_manifest_sha256': sha(root / 'private/package-manifest.json')})


def seal(root):
    source = read(root / 'private/source-plan.json')
    pack = read(root / 'package' / (NAME + '.report.json'))
    inspected = read(root / 'private/package-inspect.json')
    require(pack['status'] == 'package_written_not_device_tested' and inspected['status'] == 'payloads_verified_not_device_tested', 'unverified package')
    require(inspected['app_version_code'] == 5090 and inspected['manifest_version'] == 1 and inspected['compression'] == 'ZSTD' and inspected['volume_count'] == 0, 'package schema mismatch')
    require(pack['package_sha256'] == inspected['package_sha256'] and pack['package_bytes'] == inspected['package_bytes'], 'whole package identity mismatch')
    transport = (root / 'private/transport-plaintext.sha256').read_text().strip()
    require(re.fullmatch(r'[0-9a-f]{64}  -', transport) and transport[:64] == pack['package_sha256'],
            'encrypted transport failed decryption SHA-256 roundtrip')
    require(set(inspected['payloads']) == set(pack['payloads']) == set(PAYLOADS), 'unexpected package payload set')
    for name in PAYLOADS:
        actual = inspected['payloads'][name]
        require(actual['sha256_expected_matched'] is True and actual['sha256'] == pack['payloads'][name]['sha256']
                and actual['size'] == pack['payloads'][name]['size'], 'unverified payload identity')
    parts = sorted((root / 'dist').glob(NAME + '.enc.[0-9][0-9][0-9]'))
    require(parts and [p.name for p in parts] == [f'{NAME}.enc.{i:03d}' for i in range(len(parts))], 'noncontiguous encrypted parts')
    hashes = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p)} for p in parts]
    require(all(0 < row['bytes'] <= 1900 * MIB for row in hashes), 'encrypted part size limit exceeded')
    (root / 'dist' / (NAME + '.enc.sha256')).write_text(''.join(f"{r['sha256']}  {r['name']}\n" for r in hashes))
    (root / 'dist' / (NAME + '.sha256')).write_text(f"{pack['package_sha256']}  {NAME}\n")
    public_payloads = {name: {key: pack['payloads'][name][key] for key in ('size', 'sha256')} for name in PAYLOADS}
    report = {'source_run': source['source_run'], 'source_release': source['source_release'],
              'pipeline_commit': os.environ['GITHUB_SHA'], 'package_format': 'vmpkg', 'app_version_code': 5090,
              'manifest_version': 1, 'compression': 'ZSTD', 'volume_count': 0,
              'package_filename': NAME, 'plaintext_package_bytes': pack['package_bytes'], 'plaintext_package_sha256': pack['package_sha256'],
              'package_payloads': public_payloads, 'all_package_payloads_sha256_verified': True,
              'source_identity': read(root / 'private/source-verified.json'),
              'profile_identity': read(root / 'private/template-identity.json'),
              'conversion': read(root / 'private/conversion-verified.json'),
              'encrypted_parts': hashes, 'transport': 'OpenSSL AES-256-CBC PBKDF2 salted; SHA256 checked encrypted parts',
              'transport_decryption_plaintext_sha256_verified': True,
              'plaintext_package_published': False, 'credentials_published': False,
              'device_import_tested': False, 'device_boot_tested': False, 'performance_tested': False}
    write(root / 'dist/vmpkg-build-report.json', report)
    expected = {*(p.name for p in parts), NAME + '.enc.sha256', NAME + '.sha256', 'vmpkg-build-report.json'}
    require({p.name for p in (root / 'dist').iterdir()} == expected, 'unapproved public distribution file')
    for path in (root / 'dist').iterdir():
        regular(path)
    print(json.dumps({k: report[k] for k in ('package_filename', 'plaintext_package_bytes', 'plaintext_package_sha256', 'device_boot_tested', 'performance_tested')}, indent=2))


def audit_published(root):
    report = read(root / 'dist/vmpkg-build-report.json')
    number = report['source_run']['run_number']
    release = gh(f"repos/{os.environ['GH_REPO']}/releases/tags/vmpkg-27.2-{number}")
    assets = {a['name']: a for a in release['assets']}
    require(len(assets) == len(release['assets']), 'duplicate published asset names')
    allowed = {p.name for p in (root / 'dist').iterdir()} | {'publish-verification.json'}
    require(set(assets) <= allowed, 'release contains unapproved pre-existing/public asset')
    for path in (root / 'dist').iterdir():
        a = assets.get(path.name)
        require(a and a['state'] == 'uploaded' and a['size'] == path.stat().st_size and a['digest'] == 'sha256:' + sha(path),
                f'published asset identity mismatch: {path.name}')
    proof = {'release_url': release['html_url'], 'source_run': report['source_run']['id'],
             'encrypted_parts': len(report['encrypted_parts']), 'all_server_sha256_digests_match': True,
             'plaintext_package_published': False, 'device_boot_tested': False, 'performance_tested': False}
    write(root / 'private/publish-verification.json', proof)
    print(json.dumps(proof, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('plan'); p.add_argument('--source-run', required=True)
    p.add_argument('--candidate-commit', default=os.environ.get('VMPKG_CANDIDATE_COMMIT', ''),
                   help='full source commit for a successful recovery branch image run')
    p = sub.add_parser('download'); p.add_argument('--parallel', type=int, choices=(1, 2, 3, 4), default=4)
    sub.add_parser('verify-source')
    p = sub.add_parser('budget'); p.add_argument('--phase', choices=('convert', 'package', 'encrypt'), required=True)
    sub.add_parser('verify-gpt')
    p = sub.add_parser('manifest'); p.add_argument('--template', type=Path, required=True)
    sub.add_parser('seal')
    sub.add_parser('audit-published')
    args = parser.parse_args(); root = args.work.resolve(); root.mkdir(parents=True, exist_ok=True)
    if args.command == 'plan': plan(root, args.source_run, args.candidate_commit)
    elif args.command == 'download': download(root, args.parallel)
    elif args.command == 'verify-source': verify_source(root)
    elif args.command == 'budget': budget(root, args.phase)
    elif args.command == 'verify-gpt': verify_gpt(root)
    elif args.command == 'manifest': manifest(root, args.template)
    elif args.command == 'seal': seal(root)
    elif args.command == 'audit-published': audit_published(root)


if __name__ == '__main__':
    main()
