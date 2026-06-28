#!/usr/bin/env bash
set -euo pipefail

rootfs="${1:-/var/lib/microvms/base/base-rootfs.ext4}"
mount_root="${2:-/mnt/microvm-root}"
size_mib="${BAP_WEB_BASE_SIZE_MIB:-2048}"

if [[ -f "$rootfs" ]]; then
  echo "Base rootfs already exists: $rootfs"
  exit 0
fi

mkdir -p "$(dirname "$rootfs")" "$mount_root"
truncate -s "${size_mib}M" "$rootfs"
mkfs.ext4 -q "$rootfs"

cleanup() {
  umount "$mount_root/dev" 2>/dev/null || true
  umount "$mount_root/proc" 2>/dev/null || true
  umount "$mount_root/sys" 2>/dev/null || true
  umount "$mount_root" 2>/dev/null || true
}
trap cleanup EXIT

mount -o loop "$rootfs" "$mount_root"
dnf install --installroot="$mount_root" \
  --releasever=10 \
  --setopt=install_weak_deps=False \
  -y \
  almalinux-release \
  systemd \
  openssh-server \
  iproute \
  iputils \
  sudo \
  bash \
  coreutils \
  procps-ng \
  passwd \
  vim \
  tar \
  libstdc++ \
  curl \
  git \
  NetworkManager

mount --bind /dev "$mount_root/dev"
mount -t proc proc "$mount_root/proc"
mount -t sysfs sys "$mount_root/sys"

chroot "$mount_root" /bin/bash -s <<'CHROOT'
set -euo pipefail
useradd -m -s /bin/bash dev 2>/dev/null || true
usermod -aG wheel dev
passwd -l root || true
mkdir -p /etc/sudoers.d /etc/bootstrap.d /etc/NetworkManager/system-connections
echo '%wheel ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/wheel
chmod 0440 /etc/sudoers.d/wheel
sed -i -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' -e 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
cat >/usr/local/sbin/project-bootstrap.sh <<'BOOT'
#!/usr/bin/env bash
set -euo pipefail
SENTINEL="/var/lib/first-run.done"
[[ -f "$SENTINEL" ]] && exit 0
[[ -f /etc/project.env ]] || { echo "Missing /etc/project.env"; exit 1; }
source /etc/project.env
DEV_USER="${DEV_USER:-dev}"
WORK_DIR="${WORK_DIR:-/work}"
PROJECT="${PROJECT:-project}"
id "$DEV_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$DEV_USER"
install -d -m 0700 -o "$DEV_USER" -g "$DEV_USER" "/home/$DEV_USER/.ssh"
if [[ -n "${DEV_SSH_KEY:-}" ]]; then
  printf '%s\n' "$DEV_SSH_KEY" >"/home/$DEV_USER/.ssh/authorized_keys"
  chmod 0600 "/home/$DEV_USER/.ssh/authorized_keys"
fi
chown -R "$DEV_USER:$DEV_USER" "/home/$DEV_USER/.ssh"
install -d -m 0755 -o "$DEV_USER" -g "$DEV_USER" "$WORK_DIR"
if [[ -n "${REPO_URL:-}" ]]; then
  if [[ ! -d "$WORK_DIR/$PROJECT/.git" ]]; then
    sudo -u "$DEV_USER" git clone "$REPO_URL" "$WORK_DIR/$PROJECT"
  fi
  cd "$WORK_DIR/$PROJECT"
  sudo -u "$DEV_USER" git fetch --all --prune || true
  sudo -u "$DEV_USER" git checkout -f "${GIT_REF:-HEAD}" || true
fi
for f in /etc/bootstrap.d/*.sh; do
  [[ -f "$f" && -x "$f" ]] && "$f" || true
done
touch "$SENTINEL"
BOOT
chmod +x /usr/local/sbin/project-bootstrap.sh
cat >/etc/systemd/system/project-bootstrap.service <<'UNIT'
[Unit]
Description=Project bootstrap (first-run)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/project-bootstrap.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl enable NetworkManager
systemctl enable sshd
systemctl enable project-bootstrap.service
echo microvm >/etc/hostname
CHROOT

cleanup
trap - EXIT
chmod 0644 "$rootfs"
file "$rootfs"
