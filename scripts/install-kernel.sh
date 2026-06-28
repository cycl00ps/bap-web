#!/usr/bin/env bash
set -euo pipefail

src="${1:-/home/lab03/projects/bap/vmlinux-5.10.bin}"
dst="${2:-/var/lib/microvms/kernels/vmlinux-5.10.bin}"

if [[ ! -f "$src" ]]; then
  echo "Kernel source not found: $src" >&2
  exit 1
fi

mkdir -p "$(dirname "$dst")"
install -m 0644 "$src" "$dst"
file "$dst"

