#!/usr/bin/env python3
"""Repository export helper (cross-platform).

Ez a script a HEAD állapotban lévő, git által követett fájlokat gyűjti össze
és tar.gz vagy zip archívumba csomagolja. Windows alatt is futtatható,
mert csak a Python standard könyvtárára és a `git` parancsra támaszkodik.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Iterable

try:
    import zipfile
except ImportError:  # pragma: no cover - a standard modul, de biztos ami biztos
    zipfile = None


def repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parent.parent


def list_tracked_files(root: Path) -> Iterable[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=str(root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit("A 'git' parancs nem található a PATH-ban.") from exc
    except subprocess.CalledProcessError as exc:  # pragma: no cover - hiba eset
        raise SystemExit(f"A git ls-files hibaüzenettel leállt: {exc.stderr.strip()}") from exc

    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not files:
        raise SystemExit("A repóban nincs követett fájl, nincs mit archiválni.")
    return files


def export_tar(root: Path, files: Iterable[str], out_path: Path) -> None:
    with tarfile.open(out_path, mode="w:gz") as tar:
        for rel in files:
            full = root / rel
            tar.add(full, arcname=rel)


def export_zip(root: Path, files: Iterable[str], out_path: Path) -> None:
    if zipfile is None:
        raise SystemExit("A zipfile modul nem érhető el ebben a Python-ban.")
    with zipfile.ZipFile(out_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in files:
            full = root / rel
            zf.write(full, arcname=rel)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HEAD állapot exportálása tar.gz vagy zip archívumba.",
    )
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--tar", action="store_true", help="tar.gz archívum készítése")
    fmt.add_argument("--zip", action="store_true", help="zip archívum készítése")
    parser.add_argument(
        "-o",
        "--output",
        metavar="FÁJL",
        help="kimeneti fájlnév (alapértelmezés: esp32_olimex_anchore-head.tar.gz vagy .zip)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()

    default_tar = "esp32_olimex_anchore-head.tar.gz"
    default_zip = "esp32_olimex_anchore-head.zip"

    if args.output:
        out_path = Path(args.output)
    elif args.zip:
        out_path = Path(default_zip)
    else:
        out_path = Path(default_tar)

    # Ha relatív út, a repó gyökeréhez mérjük.
    if not out_path.is_absolute():
        out_path = root / out_path

    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.zip:
        fmt = "zip"
    elif args.tar:
        fmt = "tar"
    else:
        fmt = "tar"

    files = list(list_tracked_files(root))

    if fmt == "zip":
        export_zip(root, files, out_path)
    else:
        export_tar(root, files, out_path)

    print(f"Készen: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())