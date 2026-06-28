#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

install -m 0755 ./bap-webd /usr/local/bin/bap-webd
mkdir -p \
  /etc/bap-web \
  /usr/local/share/bap-web/static \
  /var/lib/bap-web \
  /var/lib/bap-web/image-builds \
  /var/lib/bap-web/image-hooks \
  /var/lib/microvms/base \
  /var/lib/microvms/kernels \
  /var/log/bap-web
chmod 0700 /var/lib/bap-web /var/lib/bap-web/image-builds /var/lib/bap-web/image-hooks
cp -a ./internal/app/static/. /usr/local/share/bap-web/static/

if [[ ! -f /etc/bap-web/config.yaml ]]; then
  install -m 0640 ./config.example.yaml /etc/bap-web/config.yaml
fi

cat >/etc/systemd/system/bap-webd.service <<'UNIT'
[Unit]
Description=BAP Web Firecracker microVM manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bap-webd --config /etc/bap-web/config.yaml
Restart=on-failure
RestartSec=3
WorkingDirectory=/var/lib/bap-web
KillMode=process

# v1 runs as root because it manages KVM, TAP, mounts, jailer, nftables, and rootfs images.
User=root
Group=root

NoNewPrivileges=false
PrivateTmp=true
ProtectHome=true
ReadWritePaths=/var/lib/bap-web /var/lib/microvms /srv/jailer /var/log/bap-web /etc/bap-web /tmp /mnt

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable bap-webd
systemctl restart bap-webd
systemctl --no-pager --full status bap-webd
