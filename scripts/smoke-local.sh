#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true' EXIT

cat >"$tmp/config.yaml" <<EOF
server:
  bind_address: "127.0.0.1"
  port: 18080
  static_dir: "$tmp/static"
  trusted_hosts:
    - "127.0.0.1:18080"
  allowed_origins:
    - "http://127.0.0.1:18080"
database:
  driver: "sqlite"
  dsn: "$tmp/bap-web.db"
paths:
  state_dir: "$tmp/state"
  log_dir: "$tmp/log"
  key_dir: "$tmp/keys"
  runtime_dir: "$tmp/runtime"
  image_dir: "/var/lib/microvms"
  kernel_dir: "/var/lib/microvms/kernels"
  kernel_image: "/var/lib/microvms/kernels/vmlinux-5.10.bin"
  base_image_dir: "/var/lib/microvms/base"
  base_rootfs: "/var/lib/microvms/base/base-rootfs.ext4"
  jailer_base_dir: "/srv/jailer"
  firecracker_bin: "/usr/local/bin/firecracker"
  jailer_bin: "/usr/local/bin/jailer"
network:
  backend: "nftables"
  vm_cidr: "172.31.0.0/16"
  ssh_port_range: "20000-29999"
  default_network_mode: "routed_ptp"
security:
  session_idle_timeout: "30m"
  session_absolute_timeout: "12h"
  terminal_recording: "metadata"
EOF

./bap-webd --config "$tmp/config.yaml" >"$tmp/server.log" 2>&1 &
pid=$!
for _ in $(seq 1 100); do
  if curl -fsS http://127.0.0.1:18080/api/health >/dev/null; then
    echo "OK health"
    exit 0
  fi
  sleep 0.05
done
cat "$tmp/server.log"
exit 1

