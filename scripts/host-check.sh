#!/usr/bin/env bash
set -euo pipefail

echo "==> bap-web host check"

need_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "MISSING command: $name"
    return 1
  fi
  echo "OK command: $name ($(command -v "$name"))"
}

need_path() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "MISSING path: $path"
    return 1
  fi
  echo "OK path: $path"
}

need_cmd go
need_cmd firecracker
need_cmd jailer
need_cmd nft
need_cmd ip
need_cmd ssh
need_cmd ssh-keygen
need_cmd mkfs.ext4
need_cmd mkfs.xfs
need_cmd resize2fs
need_cmd xfs_growfs
need_cmd mount
need_cmd umount
need_cmd chroot
need_cmd dnf
need_cmd git

need_path /dev/kvm
need_path /var/lib/bap-web
need_path /var/lib/bap-web/keys
need_path /var/lib/bap-web/image-builds
need_path /var/lib/bap-web/image-hooks
need_path /var/lib/microvms
need_path /var/lib/microvms/base
need_path /var/lib/microvms/kernels
need_path /srv/jailer
need_path /etc/bap-web

echo "==> versions"
go version
firecracker --version || true
jailer --version || true
nft --version

echo "==> kernel/rootfs"
if [[ -f /var/lib/microvms/kernels/vmlinux-5.10.bin ]]; then
  file /var/lib/microvms/kernels/vmlinux-5.10.bin
else
  echo "MISSING kernel: /var/lib/microvms/kernels/vmlinux-5.10.bin"
fi

if [[ -f /var/lib/microvms/base/base-rootfs.ext4 ]]; then
  file /var/lib/microvms/base/base-rootfs.ext4
else
  echo "MISSING base rootfs: /var/lib/microvms/base/base-rootfs.ext4"
fi

echo "==> networking"
sysctl net.ipv4.ip_forward
ip route show default
nft list ruleset >/dev/null

echo "==> firecracker socket sanity"
sock=/tmp/bap-web-fc-test.sock
log=/tmp/bap-web-fc-test.log
rm -f "$sock" "$log"
firecracker --api-sock "$sock" >"$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -f "$sock" "$log"' EXIT
for _ in $(seq 1 100); do
  [[ -S "$sock" ]] && break
  sleep 0.05
done
if [[ ! -S "$sock" ]]; then
  echo "Firecracker socket did not appear"
  cat "$log" || true
  exit 1
fi
curl -fsS --unix-socket "$sock" http://localhost/ >/dev/null
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
trap - EXIT
rm -f "$sock" "$log"

echo "OK host ready for bap-web development"
