#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
go test ./...
go build -o ./bap-webd ./cmd/bap-webd
./scripts/host-check.sh

if [[ "${BAP_WEB_RUN_LIVE_VM_SMOKE:-0}" == "1" ]]; then
  ./scripts/live-vm-smoke.sh
fi
