#!/usr/bin/env python3
"""Create release artifacts for CodeSentinel v2.0.0."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

VERSION = "2.0.0"
ARCHIVE_NAME = f"CodeSentinel-Windows-v{VERSION}.zip"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_release_paths(project_root: Path) -> tuple[list[Path], list[Path]]:
    required_files = [
        Path("CodeSentinel.exe"),
        Path("codesentinel.cmd"),
        Path("codesentinel.ps1"),
        Path("codesentinel.config.json"),
        Path("codesentinel.rules.lock.json"),
        Path("README.md"),
        Path("README.zh-CN.md"),
        Path("INSTALLATION.md"),
        Path("RELEASE_NOTES.md"),
        Path("checksums.txt"),
        Path(".env.example"),
        Path("quick_start.bat"),
        Path("LICENSE"),
    ]
    required_dirs = [
        Path("docs"),
        Path("schemas"),
        Path("policies"),
        Path("rulepacks"),
    ]

    missing: list[Path] = []
    files: list[Path] = []

    for rel in required_files:
        full = project_root / rel
        if not full.is_file():
            missing.append(rel)
            continue
        files.append(rel)

    for rel_dir in required_dirs:
        full_dir = project_root / rel_dir
        if not full_dir.is_dir():
            missing.append(rel_dir)
            continue
        for child in full_dir.rglob("*"):
            if child.is_file():
                files.append(child.relative_to(project_root))

    return sorted(files), missing


def write_archive(project_root: Path, release_dir: Path, files: list[Path]) -> Path:
    release_dir.mkdir(parents=True, exist_ok=True)
    archive_path = release_dir / ARCHIVE_NAME
    with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as zf:
        for rel in files:
            zf.write(project_root / rel, rel.as_posix())
    return archive_path


def write_manifest(project_root: Path, release_dir: Path, archive_path: Path) -> Path:
    manifest = {
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "archive": {
            "name": archive_path.name,
            "sha256": sha256_file(archive_path),
            "size_bytes": archive_path.stat().st_size,
        },
        "binary": {
            "name": "CodeSentinel.exe",
            "sha256": sha256_file(project_root / "CodeSentinel.exe"),
            "size_bytes": (project_root / "CodeSentinel.exe").stat().st_size,
        },
    }
    manifest_path = release_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def copy_release_notes(project_root: Path, release_dir: Path) -> Path:
    src = project_root / "RELEASE_NOTES.md"
    dst = release_dir / "RELEASE_NOTES.md"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return dst


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    release_dir = project_root / "release"

    files, missing = collect_release_paths(project_root)
    if missing:
        print("Missing required release inputs:")
        for item in missing:
            print(f"  - {item.as_posix()}")
        return 1

    archive_path = write_archive(project_root, release_dir, files)
    manifest_path = write_manifest(project_root, release_dir, archive_path)
    notes_path = copy_release_notes(project_root, release_dir)

    print(f"Release archive: {archive_path}")
    print(f"Release manifest: {manifest_path}")
    print(f"Release notes: {notes_path}")
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())