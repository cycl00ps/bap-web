#!/usr/bin/env bash
set -euo pipefail

base_url="${BAP_WEB_URL:-http://127.0.0.1:8080}"
username="${BAP_WEB_USERNAME:-}"
password="${BAP_WEB_PASSWORD:-}"

if [[ -z "$username" || -z "$password" ]]; then
  if [[ -r /etc/bap-web/initial-admin.txt ]]; then
    username="${username:-$(awk -F= '/^username=/{print $2}' /etc/bap-web/initial-admin.txt)}"
    password="${password:-$(awk -F= '/^password=/{print $2}' /etc/bap-web/initial-admin.txt)}"
  elif command -v sudo >/dev/null 2>&1 && sudo test -r /etc/bap-web/initial-admin.txt; then
    username="${username:-$(sudo awk -F= '/^username=/{print $2}' /etc/bap-web/initial-admin.txt)}"
    password="${password:-$(sudo awk -F= '/^password=/{print $2}' /etc/bap-web/initial-admin.txt)}"
  fi
fi

if [[ -z "$username" || -z "$password" ]]; then
  echo "Set BAP_WEB_USERNAME and BAP_WEB_PASSWORD, or make /etc/bap-web/initial-admin.txt readable." >&2
  exit 1
fi

for cmd in curl ip jq ssh; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing command: $cmd" >&2
    exit 1
  fi
done

cookie="$(mktemp)"
private_key="$(mktemp)"
vm_ids=()
key_id=""
network_id=""
cleanup() {
  set +e
  if [[ -n "$cookie" && -f "$cookie" ]]; then
    csrf="$(curl -fsS -b "$cookie" "$base_url/api/session" 2>/dev/null | jq -r '.csrf // empty' 2>/dev/null)"
    if [[ -n "$csrf" ]]; then
      for vm_id in "${vm_ids[@]}"; do
        curl -fsS -b "$cookie" -H "X-CSRF-Token: $csrf" -X DELETE "$base_url/api/vms/$vm_id" >/dev/null 2>&1
      done
    fi
    if [[ -n "$csrf" && -n "$network_id" ]]; then
      curl -fsS -b "$cookie" -H "X-CSRF-Token: $csrf" -X DELETE "$base_url/api/networks/$network_id" >/dev/null 2>&1
    fi
    if [[ -n "$csrf" && -n "$key_id" ]]; then
      curl -fsS -b "$cookie" -H "X-CSRF-Token: $csrf" -X DELETE "$base_url/api/ssh-keys/$key_id" >/dev/null 2>&1
    fi
    rm -f "$cookie"
  fi
  rm -f "$private_key"
}
trap cleanup EXIT

api() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  if [[ -n "$data" ]]; then
    curl -fsS -b "$cookie" -H "X-CSRF-Token: $csrf" -H "Content-Type: application/json" -X "$method" -d "$data" "$base_url$path"
  else
    curl -fsS -b "$cookie" -H "X-CSRF-Token: $csrf" -X "$method" "$base_url$path"
  fi
}

wait_for_ssh() {
  local guest_ip="$1"
  for _ in $(seq 1 90); do
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -i "$private_key" "dev@$guest_ip" true >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

assert_link_absent() {
  local link="$1"
  for _ in $(seq 1 10); do
    if ! ip link show dev "$link" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "link still exists after cleanup: $link" >&2
  return 1
}

delete_vm_and_verify_tap() {
  local vm_id="$1"
  local tap="$2"
  api DELETE "/api/vms/$vm_id" >/dev/null
  for i in "${!vm_ids[@]}"; do
    if [[ "${vm_ids[$i]}" == "$vm_id" ]]; then
      unset 'vm_ids[$i]'
    fi
  done
  assert_link_absent "$tap"
}

curl -fsS -c "$cookie" \
  -d "username=$username" \
  --data-urlencode "password=$password" \
  "$base_url/login" >/dev/null

csrf="$(curl -fsS -b "$cookie" "$base_url/api/session" | jq -r .csrf)"
name="smoke$(date +%s)"

key_json="$(api POST /api/ssh-keys/generate "{\"name\":\"${name}key\"}")"
key_id="$(jq -r .key.id <<<"$key_json")"
jq -r .private_key <<<"$key_json" > "$private_key"
chmod 0600 "$private_key"

routed_name="${name}r"
vm_json="$(api POST /api/vms "{\"name\":\"$routed_name\",\"vcpu_count\":1,\"mem_mib\":512,\"ssh_key_id\":\"$key_id\",\"network_mode\":\"routed_ptp\",\"egress_mode\":\"deny_all\"}")"
vm_id="$(jq -r .id <<<"$vm_json")"
vm_ids+=("$vm_id")

started="$(api POST "/api/vms/$vm_id/start")"
guest_ip="$(jq -r .guest_ip <<<"$started")"
tap_name="$(jq -r .tap_name <<<"$started")"
state="$(jq -r .state <<<"$started")"

if [[ "$state" != "running" ]]; then
  echo "VM did not reach running state: $started" >&2
  exit 1
fi

if (( ${#tap_name} > 15 )); then
  echo "tap name too long: $tap_name" >&2
  exit 1
fi

if ! wait_for_ssh "$guest_ip"; then
  echo "routed VM started but SSH login did not succeed on $guest_ip:22" >&2
  exit 1
fi

delete_vm_and_verify_tap "$vm_id" "$tap_name"

for octet in $(seq 210 250); do
  if network_json="$(api POST /api/networks "{\"name\":\"${name}net$octet\",\"cidr\":\"172.31.$octet.0/29\"}" 2>/dev/null)"; then
    network_id="$(jq -r .id <<<"$network_json")"
    break
  fi
done
if [[ -z "$network_id" ]]; then
  echo "could not allocate a shared test network" >&2
  exit 1
fi
bridge_name="br-bap-$network_id"

vm_a_json="$(api POST /api/vms "{\"name\":\"${name}a\",\"vcpu_count\":1,\"mem_mib\":512,\"ssh_key_id\":\"$key_id\",\"network_mode\":\"shared_bridge\",\"network_id\":\"$network_id\",\"egress_mode\":\"allow_all\"}")"
vm_b_json="$(api POST /api/vms "{\"name\":\"${name}b\",\"vcpu_count\":1,\"mem_mib\":512,\"ssh_key_id\":\"$key_id\",\"network_mode\":\"shared_bridge\",\"network_id\":\"$network_id\",\"egress_mode\":\"allow_all\"}")"
vm_a="$(jq -r .id <<<"$vm_a_json")"
vm_b="$(jq -r .id <<<"$vm_b_json")"
vm_ids+=("$vm_a" "$vm_b")

started_a="$(api POST "/api/vms/$vm_a/start")"
started_b="$(api POST "/api/vms/$vm_b/start")"
guest_a="$(jq -r .guest_ip <<<"$started_a")"
guest_b="$(jq -r .guest_ip <<<"$started_b")"
tap_a="$(jq -r .tap_name <<<"$started_a")"
tap_b="$(jq -r .tap_name <<<"$started_b")"

if ! wait_for_ssh "$guest_a"; then
  echo "shared VM A started but SSH login did not succeed on $guest_a:22" >&2
  exit 1
fi
if ! wait_for_ssh "$guest_b"; then
  echo "shared VM B started but SSH login did not succeed on $guest_b:22" >&2
  exit 1
fi
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -i "$private_key" "dev@$guest_a" "ping -c 2 -W 2 $guest_b" >/dev/null

delete_vm_and_verify_tap "$vm_a" "$tap_a"
delete_vm_and_verify_tap "$vm_b" "$tap_b"
api DELETE "/api/networks/$network_id" >/dev/null
network_id=""
assert_link_absent "$bridge_name"

echo "OK live VM smoke: routed cleanup and shared-network ping passed ($guest_a -> $guest_b)"
