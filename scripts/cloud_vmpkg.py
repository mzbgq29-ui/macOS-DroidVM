#!/usr/bin/env python3
"""Recover the already verified package on an ephemeral GitHub runner."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = 'mzbgq29-ui/macOS-DroidVM'
TAG = 'vmpkg-27.2-1'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(8 << 20):
            h.update(block)
    return h.hexdigest()


def recover(work, anchor):
    require(os.environ.get('GITHUB_REPOSITORY') == REPO, 'Unexpected repository')
    require(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'Hosted runner required')
    key = os.environ.get('ARTIFACT_KEY')
    require(key, 'ARTIFACT_KEY is missing')
    name = anchor['package_filename']
    require(name == 'macOS-27.2-DroidVM.vmpkg', 'Unexpected package name')
    parts = anchor['encrypted_parts']
    require([p['name'] for p in parts] == [f'{name}.enc.{i:03d}' for i in range(7)], 'Unexpected part sequence')
    require(shutil.disk_usage(work).free > sum(p['bytes'] for p in parts) + anchor['plaintext_package_bytes'] + 2 * 1024**3,
            'Insufficient free disk for transport and recovered package')
    release = json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPO}/releases/tags/{TAG}']))
    assets = {a['name']: a for a in release['assets']}
    for part in parts:
        a = assets.get(part['name'])
        require(a and a['state'] == 'uploaded' and a['size'] == part['bytes'] and
                a['digest'] == 'sha256:' + part['sha256'], 'Published transport differs from trusted production record')
        require(a['browser_download_url'] == f'https://github.com/{REPO}/releases/download/{TAG}/{part["name"]}',
                'Unexpected download destination')
    directory = work / 'parts'
    directory.mkdir(exist_ok=True)

    def download(part):
        path = directory / part['name']
        subprocess.run(['curl', '--proto', '=https', '--proto-redir', '=https', '--fail', '--location',
                        '--retry', '5', '--retry-all-errors', '--connect-timeout', '30', '--max-time', '3600',
                        '--silent', '--show-error', '--output', str(path), assets[part['name']]['browser_download_url']], check=True)
        require(path.stat().st_size == part['bytes'] and sha(path) == part['sha256'], 'Encrypted part integrity failed')
        print('Verified encrypted part:', part['name'], flush=True)
        return path

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(download, parts))
    out = work / 'ready'
    out.mkdir(exist_ok=True)
    partial = out / (name + '.partial')
    final = out / name
    require(not final.exists() and not partial.exists(), 'Refusing to overwrite package')
    print('Decrypting in ephemeral cloud storage.', flush=True)
    with partial.open('xb') as output:
        process = subprocess.Popen(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-pass', 'env:ARTIFACT_KEY'],
                                   stdin=subprocess.PIPE, stdout=output)
        try:
            for part in parts:
                with (directory / part['name']).open('rb') as source:
                    while block := source.read(8 << 20):
                        process.stdin.write(block)
            process.stdin.close()
            require(process.wait() == 0, 'Transport decryption failed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    os.environ.pop('ARTIFACT_KEY', None)
    require(partial.stat().st_size == anchor['plaintext_package_bytes'] and sha(partial) == anchor['plaintext_package_sha256'],
            'Recovered plaintext does not match the fully verified production package')
    from vmpkg_tool import inspect
    parsed = inspect(partial)
    require(parsed['app_version_code'] == anchor['app_version_code'] and parsed['volume_count'] == 0 and
            parsed['compression'] == 'ZSTD', 'Recovered package format mismatch')
    partial.rename(final)
    shutil.rmtree(directory)
    report = {'status': 'verified_ready_to_import_not_device_tested', 'package_filename': name,
              'package_bytes': final.stat().st_size, 'package_sha256': anchor['plaintext_package_sha256'],
              'matches_fully_verified_production_package': True, 'single_file': True,
              'app_version_code': parsed['app_version_code'], 'device_boot_tested': False, 'performance_tested': False}
    (work / 'cloud-recovery-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--anchor', type=Path, required=True)
    args = p.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    recover(args.work, json.loads(args.anchor.read_text()))


if __name__ == '__main__':
    main()
