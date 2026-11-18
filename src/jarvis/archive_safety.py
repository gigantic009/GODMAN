"""Read-only archive metadata inspection; never extracts or executes archive members."""
from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10000
MAX_DECLARED_EXPANSION_BYTES = 2 * 1024 * 1024 * 1024
SUSPICIOUS_RATIO = 100.0


def _resolve_workspace_file(workspace: str | Path, relative_path: str) -> Path:
    root = Path(workspace).expanduser().resolve()
    target = (root / relative_path).resolve()
    if target == root or root not in target.parents:
        raise ValueError("Path must identify a file inside the configured GODMAN workspace.")
    if not target.is_file():
        raise FileNotFoundError(relative_path)
    return target


def inspect_zip_safety(workspace: str | Path, relative_path: str) -> dict:
    """Inspect ZIP central-directory metadata without decompressing any member."""
    target = _resolve_workspace_file(workspace, relative_path)
    size = target.stat().st_size
    if size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"Archive exceeds the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB inspection limit.")
    if not zipfile.is_zipfile(target):
        raise ValueError("File is not recognized as a ZIP archive.")
    with zipfile.ZipFile(target, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ValueError(f"Archive exceeds the {MAX_ARCHIVE_MEMBERS} member inspection limit.")
        total_compressed = sum(max(0, item.compress_size) for item in infos)
        total_uncompressed = sum(max(0, item.file_size) for item in infos)
        max_ratio = max(
            ((item.file_size / max(1, item.compress_size)) for item in infos if item.file_size),
            default=0.0,
        )
        suspicious_paths = []
        nested_archives = []
        suspicious_symlinks = []
        for item in infos:
            name = item.filename
            posix = PurePosixPath(name)
            windows = PureWindowsPath(name)
            if posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts:
                suspicious_paths.append(name[:240])
            if name.lower().endswith((".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz")):
                nested_archives.append(name[:240])
            unix_mode = (item.external_attr >> 16) & 0xFFFF
            if (unix_mode & 0o170000) == 0o120000:
                suspicious_symlinks.append(name[:240])
        flags = []
        if max_ratio >= SUSPICIOUS_RATIO:
            flags.append("high_compression_ratio")
        if total_uncompressed >= MAX_DECLARED_EXPANSION_BYTES:
            flags.append("large_declared_expansion")
        if suspicious_paths:
            flags.append("path_traversal_member_names")
        if suspicious_symlinks:
            flags.append("symlink_members")
        if nested_archives:
            flags.append("nested_archives")
        return {
            "file": target.name,
            "archive_bytes": size,
            "member_count": len(infos),
            "declared_compressed_bytes": total_compressed,
            "declared_uncompressed_bytes": total_uncompressed,
            "maximum_member_compression_ratio": round(max_ratio, 2),
            "flags": flags,
            "suspicious_member_paths": suspicious_paths[:50],
            "symlink_members": suspicious_symlinks[:50],
            "nested_archive_members": nested_archives[:50],
            "assessment": "Metadata-based risk indicators only. No member was extracted, decompressed, scanned, or executed; verify with an isolated scanner before opening.",
        }
