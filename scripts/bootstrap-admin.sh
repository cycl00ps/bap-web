#!/usr/bin/env bash
set -euo pipefail

url="${1:-http://127.0.0.1:8080}"
user="${BAP_WEB_ADMIN_USER:-admin}"
secret_file="${BAP_WEB_ADMIN_SECRET_FILE:-/etc/bap-web/initial-admin.txt}"

if curl -fsS "$url/" | grep -q "MicroVMs"; then
  echo "bap-web already has an admin/session path; not bootstrapping"
  exit 0
fi

password="$(python3 - <<'PY'
import secrets
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,.^-"
print("".join(secrets.choice(alphabet) for _ in range(32)))
PY
)"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

code="$(curl -sS -o "$tmp" -w '%{http_code}' \
  -X POST "$url/setup" \
  -d "username=${user}" \
  --data-urlencode "password=${password}")"

if [[ "$code" != "303" && "$code" != "302" ]]; then
  cat "$tmp" >&2
  echo "setup failed: HTTP $code" >&2
  exit 1
fi

install -m 0600 /dev/null "$secret_file"
cat >"$secret_file" <<EOF
username=${user}
password=${password}
url=${url}
EOF
echo "Initial admin credentials written to $secret_file"
