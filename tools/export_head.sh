#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_TAR="esp32_olimex_anchore-head.tar.gz"
DEFAULT_ZIP="esp32_olimex_anchore-head.zip"
FORMAT="tar.gz"
OUT=""

usage(){
  local rc=${1:-0}
  cat <<USAGE
Használat: $(basename "$0") [--tar|--zip] [--output fajl]
  --tar           tar.gz csomagot hoz létre (alapértelmezett)
  --zip           zip archívumot készít
  -o, --output    egyedi kimeneti fájl megadása
  -h, --help      súgó megjelenítése
USAGE
  exit "$rc"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tar)
      FORMAT="tar.gz"
      shift
      ;;
    --zip)
      FORMAT="zip"
      shift
      ;;
    -o|--output)
      [[ $# -ge 2 ]] || { echo "Hiányzó kimeneti fájlnév" >&2; exit 1; }
      OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage 0
      ;;
    *)
      if [[ "$1" == -* ]]; then
        echo "Ismeretlen opció: $1" >&2
        usage 1
      fi
      if [[ -n "$OUT" ]]; then
        echo "Több kimeneti fájl lett megadva" >&2
        usage 1
      fi
      OUT="$1"
      shift
      ;;
  esac
done

if [[ -z "$OUT" ]]; then
  if [[ "$FORMAT" == "zip" ]]; then
    OUT="$DEFAULT_ZIP"
  else
    OUT="$DEFAULT_TAR"
  fi
fi

if [[ "$OUT" != /* ]]; then
  OUT="$ROOT/$OUT"
fi

mkdir -p "$(dirname "$OUT")"

if [[ -f "$OUT" ]]; then
  rm -f "$OUT"
fi

git -C "$ROOT" archive --format="$FORMAT" --output "$OUT" HEAD

echo "Készen: $OUT"
