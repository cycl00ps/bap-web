# BAP Web Agent Guide

This guide is for LLMs and automation agents using BAP Web through HTTP APIs.

## Authentication

Operational API calls require authentication. Use a bearer token supplied by the user or administrator:

```http
Authorization: Bearer bap_...
```

Bearer-token API requests do not need CSRF headers. Browser-session mutating requests must include `X-CSRF-Token` from `GET /api/session`, but agents should prefer bearer tokens.

Agents should not expect unauthenticated operational access. Agents should not create their own token unless the user has already authenticated and explicitly asks for token creation. Non-admin bearer tokens cannot create more API tokens; admin bearer tokens can create tokens but should only do so when the user asks.

Use the least privilege token that can complete the task:

- Non-admin token: normal VM, shell, SSH key, network, and egress policy operations.
- Admin token: token management, image builds, image hooks, kernel import/upload/test/status/delete, and other administrative operations.
- Token expiry defaults to 30 days when omitted; prefer shorter expiration times for temporary agent work.

## Discovery

Start with:

```http
GET /api/health
GET /api/session
GET /openapi.json
```

Use the OpenAPI document for complete route, request, response, and error shapes. Confirm `user` and `is_admin` from `/api/session` before admin-only work.

Common resource discovery endpoints:

```http
GET /api/ssh-keys
GET /api/base-images
GET /api/kernels
GET /api/networks
GET /api/egress-policies
GET /api/vms
GET /api/host/status
```

Before creating or starting many VMs, check `GET /api/host/status`. Prefer hosts where checks are `ok` and orphans/conflicts are empty.

## Name and size rules

Names for VMs, networks, and egress policies must match:

```text
^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}$
```

VM resources:

- `vcpu_count`: 1–32
- `mem_mib`: 128–262144
- `rootfs_size_mib`: at least the selected base image virtual size; at most the server `max_vm_rootfs_mib` limit

## SSH keys

Reusable SSH keys are required for guest login and for BAP `exec` (the control plane reaches the guest over SSH).

Generate a key:

```http
POST /api/ssh-keys/generate
Content-Type: application/json

{"name":"agent-key"}
```

Response includes `key` (metadata + `public_key`) and a one-time `private_key`. Store `private_key` securely outside BAP. Later `GET /api/ssh-keys` and `GET /api/ssh-keys/{id}` never return the private key.

Import an existing public key:

```http
POST /api/ssh-keys/import
Content-Type: application/json

{"name":"imported-key","public_key":"ssh-ed25519 AAAA... comment"}
```

List/get/delete:

- `GET /api/ssh-keys`
- `GET /api/ssh-keys/{id}`
- `DELETE /api/ssh-keys/{id}`

## Choose base image and kernel

1. `GET /api/base-images` and pick an item with `status` = `active`.
2. `GET /api/kernels` and pick an item with `status` = `active`.

Omitting `base_image_id` / `kernel_id` on create selects the server defaults among active resources. Prefer explicit IDs so the VM is reproducible.

Building or registering new base images and importing/uploading kernels are **admin** operations (`POST /api/base-images/build`, register/upload/import/test). Non-admin agents should only select existing active images and kernels.

## Networking modes

- `routed_ptp` (default when omitted, unless the server config overrides): isolated point-to-point link for one VM. Leave `network_id` empty.
- `shared_bridge`: VM joins a shared L2 network. `network_id` is **required**. Creating without it returns `422` with `network_id: required for shared_bridge`.

### Shared bridge networks

```http
POST /api/networks
Content-Type: application/json

{"name":"lab-net","cidr":"172.31.90.0/28","gateway_ip":"172.31.90.1"}
```

Rules observed by the API:

- `cidr` must be an IPv4 prefix inside the configured host `vm_cidr` (commonly `172.31.0.0/16`).
- CIDRs must not overlap other shared networks or routed VM allocations (`409 conflict`).
- `gateway_ip` is optional; when set it must be a usable address inside the CIDR.
- `GET /api/networks` / `DELETE /api/networks/{id}`
- Delete fails with `409` while any VM still references the network. Delete VMs first.

### Egress

Per-VM modes when no policy is attached: `allow_all` or `deny_all` (default `allow_all`).

Reusable policies:

```http
POST /api/egress-policies
Content-Type: application/json

{
  "name": "web-only",
  "mode": "restricted",
  "tcp_ports": "80,443",
  "udp_ports": "53",
  "cidrs": "0.0.0.0/0"
}
```

- `mode`: `allow_all`, `deny_all`, or `restricted`.
- Restricted policies need at least one of `tcp_ports`, `udp_ports`, or `cidrs` (comma-separated).
- Attach at create with `egress_policy_id`, or later:

```http
PUT /api/vms/{id}/egress-policy
Content-Type: application/json

{"egress_policy_id":"policy-id"}
```

or `{"mode":"allow_all"}` / `{"mode":"deny_all"}` to clear the policy. When a policy is attached, the VM’s effective `egress_mode` becomes the policy’s mode (for example `restricted`).

### Ingress (port forwards)

Map a host TCP/UDP port to a guest port:

```http
POST /api/vms/{id}/ingress-rules
Content-Type: application/json

{"protocol":"tcp","host_port":8081,"guest_port":80,"description":"http"}
```

- `protocol`: `tcp` or `udp`.
- `host_port` / `guest_port`: 1–65535.
- `host_port` must not collide with allocated VM SSH ports or other listeners (`409 conflict`).
- Inspect rules with `GET /api/vms/{id}/network` (`ingress_rules`, optional `network`, `egress_policy`).
- Delete with `DELETE /api/vms/{id}/ingress-rules/{rule_id}`.

Every running VM also gets an automatic host `ssh_port` that DNATs to guest port 22. Use that for interactive SSH; use ingress rules for application ports.

## Create and run a MicroVM

Recommended workflow:

1. Confirm user intent before creating or deleting resources.
2. Ensure an SSH key exists; note active `base_image_id` and `kernel_id`.
3. Optionally create a shared network and/or egress policy.
4. Create the VM with `POST /api/vms` (returns `state: stopped`).
5. Start with `POST /api/vms/{id}/start`.
6. Poll `GET /api/vms/{id}` until `state` is `running` (or `error` — then read `last_error` and `GET /api/vms/{id}/logs`).
7. Run commands with `POST /api/vms/{id}/exec`.
8. Add ingress rules if the user needs published ports.
9. Stop or delete temporary VMs unless the user asks to keep them.

Create example:

```http
POST /api/vms
Content-Type: application/json

{
  "name": "agent-vm",
  "vcpu_count": 1,
  "mem_mib": 512,
  "dev_user": "dev",
  "ssh_key_id": "key-id",
  "extra_authorized_keys": "",
  "base_image_id": "image-id",
  "rootfs_size_mib": 2048,
  "kernel_id": "kernel-id",
  "network_mode": "routed_ptp",
  "network_id": "",
  "egress_mode": "allow_all",
  "egress_policy_id": "",
  "repo_url": "",
  "git_ref": "HEAD"
}
```

Required: `name`, `vcpu_count`, `mem_mib`, and either `ssh_key_id` or non-empty `extra_authorized_keys`.

Useful response fields: `id`, `state`, `ssh_port`, `guest_ip`, `host_ip`, `network_mode`, `network_id`, `egress_mode`, `egress_policy_id`, `last_error`.

Shared-bridge create uses `"network_mode":"shared_bridge"` and a real `"network_id"`.

`DELETE /api/vms/{id}` works for running VMs (no separate stop required). Prefer stop when the user only wants to pause.

## Shell access

Prefer non-interactive exec:

```http
POST /api/vms/{id}/exec
Content-Type: application/json

{
  "command": "uname -a && id",
  "timeout_seconds": 60,
  "cwd": "",
  "env": {},
  "stdin": "",
  "pty": false
}
```

The response includes `stdout`, `stderr`, `exit_code`, `timed_out`, and `truncated`. Always inspect those fields. Compound commands with `&&` fail the whole chain if an early command is missing.

For long-running commands, use exec jobs:

```http
POST /api/vms/{id}/exec-jobs
GET /api/vms/{id}/exec-jobs/{job_id}
GET /api/vms/{id}/exec-jobs/{job_id}/logs?lines=300
POST /api/vms/{id}/exec-jobs/{job_id}/cancel
```

### Guest SSH (humans / verification)

```bash
ssh -i /path/to/private_key -p {ssh_port} {dev_user}@{bap-host}
```

`{bap-host}` is a host address that receives the published SSH DNAT (often the BAP server’s LAN or public IP). Connecting to `127.0.0.1` or to `guest_ip` from an unrelated client network often fails. Prefer `/api/vms/{id}/exec` for automation.

Use the websocket terminal only when a human-style interactive TTY is required:

```http
GET /ws/vms/{id}/terminal?cols=120&rows=40
```

## Cleanup order

Delete only when the user asks. Safe order for agent-created resources:

1. Cancel exec jobs if any.
2. Delete ingress rules (optional; VM delete also removes them).
3. `DELETE /api/vms/{id}` for each created VM.
4. `DELETE /api/networks/{id}` (fails with `409` if still assigned).
5. `DELETE /api/egress-policies/{id}`.
6. `DELETE /api/ssh-keys/{id}` (after no VM needs that key).
7. Discard any locally stored private keys.

Endpoints:

- VMs: `GET/POST /api/vms`, `GET/DELETE /api/vms/{id}`, `POST .../start|stop|restart`, `PUT .../resources`, `GET .../logs`
- Network view: `GET /api/vms/{id}/network`

## Errors

API errors use a structured JSON body:

```json
{
  "error": {
    "code": "unprocessable",
    "message": "VM must be running to execute commands",
    "fields": {"state": "stopped"},
    "request_id": "..."
  }
}
```

Common codes: `invalid` (400), `not_found` (404), `conflict` (409), `unprocessable` (422). Always surface `message` and relevant `fields` to the user.

## Safety Rules

- Do not use an admin token for ordinary VM tasks if a non-admin token is available.
- Do not expose bearer tokens, generated private keys, or command output containing secrets.
- Do not delete VMs, images, kernels, networks, or policies unless the user explicitly requests it.
- Use bounded timeouts for commands.
- Avoid interactive prompts; pass input through `stdin` when possible.
- Prefer API exec over websocket terminal for automation.
