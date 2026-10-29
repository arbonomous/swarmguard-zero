"""Explicit project-file staging. Never auto-scan home, mount folders or import keys.

Only selected regular UTF-8 source files may cross the workspace boundary.
Returned archives are untrusted and validated fully before any file is written.
"""
from __future__ import annotations
import io
import os
from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_FILES = 200
MAX_TOTAL = 4 * 1024 * 1024
MAX_FILE = 512 * 1024
SOURCE_SUFFIXES = {'.py', '.js', '.ts', '.tsx', '.jsx', '.html', '.css', '.md', '.txt', '.json', '.toml', '.yaml', '.yml', '.sh', '.sql', '.rs', '.go'}
BLOCKED_PARTS = {'.git', '.ssh', '.aws', '.config', 'node_modules', '.venv', '__pycache__'}
SECRET_NAME = re.compile(r'(^|[._-])(env|secret|secrets|credential|credentials|token|tokens|password|passwords|private|id_rsa|id_ed25519)([._-]|$)', re.I)
SECRET_CONTENT = re.compile(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH)|(?:api[_-]?key|password|access[_-]?token|client[_-]?secret)\s*[:=]\s*["\']?[A-Za-z0-9_+/=-]{12,}', re.I)


def safe_name(name: str) -> str:
    if not name or '\\' in name or '\x00' in name:
        raise ValueError('Invalid workspace path')
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in ('..', '.') for p in name.split('/')):
        raise ValueError('Workspace paths must be relative without dot segments')
    if any(p in BLOCKED_PARTS or p.startswith('.') or SECRET_NAME.search(p) for p in path.parts):
        raise ValueError('Private, hidden or generated paths are not accepted')
    if path.suffix.lower() not in SOURCE_SUFFIXES:
        raise ValueError('Only supported text source files are accepted')
    if len(name) > 240 or any(ord(c) < 32 for c in name):
        raise ValueError('Invalid workspace filename')
    return str(path)


def validate_files(files: dict[str, bytes]) -> dict[str, bytes]:
    if not files or len(files) > MAX_FILES:
        raise ValueError('Select 1 to 200 source files')
    total = 0
    clean = {}
    for name, data in files.items():
        name = safe_name(name)
        if not isinstance(data, bytes) or len(data) > MAX_FILE:
            raise ValueError('Each source file must be at most 512 KiB')
        total += len(data)
        if total > MAX_TOTAL:
            raise ValueError('Selected source must be at most 4 MiB total')
        text = data.decode('utf-8')
        if '\x00' in text or SECRET_CONTENT.search(text):
            raise ValueError('Binary content or a possible credential was found; remove it before import')
        if name in clean:
            raise ValueError('Duplicate normalized filename')
        clean[name] = data
    return clean


def selected_files(root: Path, names: list[str]) -> dict[str, bytes]:
    """Read only explicit selections; reject symlinks at every path component."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Select an existing project directory, not a symlink')
    result = {}
    for name in names:
        safe_name(name)
        # Walk through directory FDs so parent-component symlink swaps cannot escape.
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = PurePosixPath(name).parts
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                import stat
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE:
                    raise ValueError('Select only small regular source files')
                result[name] = stream.read(MAX_FILE + 1)
        except OSError as exc:
            raise ValueError('Selected file is unavailable, unsafe or a symlink') from exc
        finally:
            os.close(directory)
    return validate_files(result)


def make_archive(files: dict[str, bytes]) -> bytes:
    files = validate_files(files)
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode='w') as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data);info.mode = 0o600;info.uid = 65534;info.gid = 65534
            archive.addfile(info, io.BytesIO(data))
    return target.getvalue()


def read_archive(data: bytes) -> dict[str, bytes]:
    """Never extract a container-created tar directly onto the host."""
    if len(data) > 6 * 1024 * 1024:
        raise ValueError('Returned archive is too large')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for entry in archive:
            if len(files) >= MAX_FILES or not entry.isfile() or entry.size > MAX_FILE or entry.size < 0:
                raise ValueError('Returned archive has an unsafe entry or too many files')
            name = safe_name(entry.name)
            if name in files:
                raise ValueError('Duplicate returned path')
            stream = archive.extractfile(entry)
            if stream is None:
                raise ValueError('Unreadable returned file')
            files[name] = stream.read(MAX_FILE + 1)
    return validate_files(files)
