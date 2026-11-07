#!/usr/bin/env python3
"""Local Linux audit: public system data, file metadata, redacted JSON."""
import argparse
import datetime
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', default='.', help='ZIP saqlanadigan katalog')
    parser.add_argument('--scan-root', action='append', help='Qidiriladigan katalog; takrorlash mumkin')
    args = parser.parse_args()
    os.umask(0o077)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    host = re.sub(r'[^A-Za-z0-9_.-]', '_', socket.gethostname()) or 'host'
    archive = output / f'audit-{host}.zip'
    if archive.exists():
        parser.error(f'{archive} mavjud; boshqa --output-dir tanlang')
    folder = Path(tempfile.mkdtemp(prefix=f'audit-{host}-', dir=output))
    errors = []

    def save(name, value):
        target = folder / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding='utf-8')

    def command(name, argv):
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=25)
            save(name, result.stdout)
            if result.returncode:
                errors.append(f'{argv[0]}: {result.stderr[:1000]}')
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f'{argv[0]}: {exc}')

    def metadata(path):
        try:
            info = path.lstat()
            return dict(path=str(path), uid=info.st_uid, gid=info.st_gid,
                        mode=stat.filemode(info.st_mode), size=info.st_size,
                        mtime=info.st_mtime, symlink=path.is_symlink())
        except OSError as exc:
            errors.append(f'{path}: {exc}')
            return None

    # Hide every scalar, including numbers and booleans: secrets need not have
    # recognizable names. Preserve only JSON structure and property names.
    def redact(value):
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return '[REDACTED]'

    try:
        save('README.txt', 'Local audit. No private-key contents, histories, password hashes, '
             'environment variables, or cache contents are collected. JSON scalar values '
             'are all redacted; property names remain. ZIP is not encrypted. '
             'Review before sharing. Run only on systems you administer.\n')
        save('system/time.txt', datetime.datetime.now(datetime.timezone.utc).isoformat())
        checks = [
            ('system/kernel.txt', ['uname', '-a']),
            ('system/uptime.txt', ['uptime']),
            ('system/disks.txt', ['df', '-h']),
            ('system/mounts.txt', ['findmnt', '-o', 'TARGET,SOURCE,FSTYPE']),
            ('network/interfaces.txt', ['ip', '-brief', 'address']),
            ('network/routes.txt', ['ip', 'route']),
            ('network/listeners.txt', ['ss', '-lntu']),
            ('services/running.txt', ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager']),
            ('services/timers.txt', ['systemctl', 'list-timers', '--all', '--no-pager']),
        ]
        for name, argv in checks:
            command(name, argv)
        for source in ['/etc/os-release', '/etc/hosts', '/etc/resolv.conf']:
            try:
                save('system/' + Path(source).name + '.txt', Path(source).read_text())
            except OSError as exc:
                errors.append(f'{source}: {exc}')
        if shutil.which('dpkg-query'):
            command('system/packages.txt', ['dpkg-query', '-W'])
        elif shutil.which('rpm'):
            command('system/packages.txt', ['rpm', '-qa'])

        users = pwd.getpwall()
        save('users/users.json', json.dumps([
            dict(name=u.pw_name, uid=u.pw_uid, gid=u.pw_gid,
                 home=u.pw_dir, shell=u.pw_shell) for u in users], indent=2))
        save('users/groups.json', json.dumps([
            dict(name=g.gr_name, gid=g.gr_gid, members=g.gr_mem)
            for g in grp.getgrall()], indent=2))
        records = []
        for home in sorted({u.pw_dir for u in users if u.pw_dir and u.pw_dir != '/'}):
            for relative in ['.bash_history', '.zsh_history', '.config', '.cache', '.ssh']:
                path = Path(home) / relative
                if path.exists() or path.is_symlink():
                    records.append(metadata(path))
            ssh = Path(home) / '.ssh'
            if ssh.is_dir() and not ssh.is_symlink():
                try:
                    records.extend(metadata(p) for p in ssh.iterdir())
                except OSError as exc:
                    errors.append(f'{ssh}: {exc}')
        save('sensitive-file-metadata/home-files.json', json.dumps(records, indent=2))

        roots = args.scan_root or ['/etc', '/opt', '/srv', '/var/www', '/home', '/root', '/app', '/apps', '/usr/local']
        configs = []
        visited = set()
        for root in roots:
            if not Path(root).is_dir():
                continue
            for base, dirs, files in os.walk(root, followlinks=False,
                                            onerror=lambda e: errors.append(str(e))):
                dirs[:] = [d for d in dirs if d not in {
                    '.git', '.cache', 'node_modules', 'proc', 'sys', 'dev'}
                    and not (Path(base) / d).is_symlink()
                    and (Path(base) / d).resolve() != folder]
                for filename in files:
                    lower = filename.lower()
                    if not (lower.endswith('.json') and
                            ('appsettings' in lower or 'app.settings' in lower)):
                        continue
                    path = Path(base) / filename
                    if str(path) in visited:
                        continue
                    visited.add(str(path))
                    configs.append(metadata(path))
                    try:
                        if path.is_symlink() or path.stat().st_size > 2_000_000:
                            errors.append(f'{path}: skipped symlink or file over 2 MB')
                            continue
                        value = json.loads(path.read_text(encoding='utf-8-sig'))
                        save('config-redacted/' + str(path).lstrip('/'),
                             json.dumps(redact(value), indent=2, ensure_ascii=False))
                    except (OSError, ValueError, RecursionError) as exc:
                        # Never copy invalid JSON as raw text.
                        errors.append(f'{path}: {type(exc).__name__}; contents omitted')
        save('sensitive-file-metadata/appsettings.json', json.dumps(configs, indent=2))
        save('errors.log', '\n'.join(errors) + '\n')
        # Exclusive creation avoids overwriting an existing report.
        try:
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as zf:
                for path in folder.rglob('*'):
                    if path.is_file():
                        zf.write(path, arcname=f'audit-{host}/' + str(path.relative_to(folder)))
            with zipfile.ZipFile(archive) as zf:
                if zf.testzip() is not None:
                    raise RuntimeError('ZIP verification failed')
        except Exception:
            # Keep the source folder if archiving fails.
            raise
        shutil.rmtree(folder)
        print(f'Tayyor: {archive}')
    except Exception:
        print(f'Xatolik. Yig‘ilgan papka saqlandi: {folder}')
        raise


if __name__ == '__main__':
    main()
