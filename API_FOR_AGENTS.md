# BAP Web API for Agents

This guide is for LLMs and other programmatic clients that need to manage BAP Web MicroVMs through the API.

Web-accessible agent resources are also available from a running server:

- `GET /docs/agents.md`
- `GET /llms.txt`
- `GET /openapi.json`
- `GET /docs/api`

## Authentication

Browser sessions are supported, but agents should use API tokens.

1. An admin creates a token:

```http
POST /api/tokens
X-CSRF-Token: <csrf-from-/api/session>
Cookie: bap_web_session=<session>
Content-Type: application/json

{"name":"agent","is_admin":true}
```

The response includes `secret` once. Store it securely.

```json
{"token":{"id":"...","name":"agent","prefix":"bap_...","is_admin":true},"secret":"bap_..."}
```

2. Use the token on later API requests:

```http
Authorization: Bearer bap_...
```

Bearer-token requests do not need CSRF. Browser-session mutating requests must send `X-CSRF-Token` from `GET /api/session`.

Token lifecycle endpoints:

- `GET /api/tokens`
- `POST /api/tokens`
- `DELETE /api/tokens/{id}`

All API errors use:

```json
{"error":{"code":"unprocessable","message":"...","fields":{"field":"reason"},"request_id":"..."}}
```

## Recommended Agent Workflow

1. Check the service: `GET /api/health`
2. Inspect identity: `GET /api/session`
3. Select or create support resources:
   - SSH keys: `/api/ssh-keys`
   - base images: `/api/base-images`
   - kernels: `/api/kernels`
   - networks: `/api/networks`
   - egress policies: `/api/egress-policies`
4. Create a VM: `POST /api/vms`
5. Start the VM: `POST /api/vms/{id}/start`
6. Poll `GET /api/vms/{id}` until `state` is `running`
7. Run commands with `POST /api/vms/{id}/exec`
8. Inspect logs with `GET /api/vms/{id}/logs`
9. Stop or delete the VM when finished.

## MicroVMs

- `GET /api/vms`
- `POST /api/vms`
- `GET /api/vms/{id}`
- `POST /api/vms/{id}/start`
- `POST /api/vms/{id}/stop`
- `POST /api/vms/{id}/restart`
- `PUT /api/vms/{id}/resources`
- `DELETE /api/vms/{id}`
- `GET /api/vms/{id}/logs?lines=300`

Create VM request fields include:

```json
{
  "name": "agent-vm",
  "vcpu_count": 2,
  "mem_mib": 2048,
  "dev_user": "dev",
  "ssh_key_id": "key-id",
  "extra_authorized_keys": "",
  "base_image_id": "image-id",
  "rootfs_size_mib": 4096,
  "kernel_id": "kernel-id",
  "network_mode": "routed_ptp",
  "network_id": "",
  "egress_mode": "allow_all",
  "egress_policy_id": "",
  "repo_url": "",
  "git_ref": "HEAD"
}
```

## Shell Access for Agents

Prefer non-interactive exec. It returns clean stdout, stderr, exit code, timeout, and truncation fields.

```http
POST /api/vms/{id}/exec
Authorization: Bearer bap_...
Content-Type: application/json

{
  "command": "uname -a && id",
  "timeout_seconds": 60,
  "cwd": "",
  "env": {"EXAMPLE": "value"},
  "stdin": "",
  "pty": false
}
```

Response:

```json
{
  "stdout": "Linux ...\nuid=1000(dev) ...\n",
  "stderr": "",
  "exit_code": 0,
  "started_at": "2026-06-28T04:00:00Z",
  "finished_at": "2026-06-28T04:00:01Z",
  "timed_out": false,
  "truncated": false
}
```

Rules:

- The VM must be `running`.
- `command` is required.
- Default timeout is 60 seconds.
- Maximum timeout is 900 seconds.
- stdout and stderr are each capped; check `truncated`.
- Prefer `pty:false`. Use `pty:true` only for commands that require a terminal; stderr may not stay cleanly separated.
- Avoid interactive prompts. Provide input through `stdin`.
- Always inspect `exit_code` and `timed_out`.

For long-running commands, use exec jobs:

- `POST /api/vms/{id}/exec-jobs`
- `GET /api/vms/{id}/exec-jobs`
- `GET /api/vms/{id}/exec-jobs/{job_id}`
- `GET /api/vms/{id}/exec-jobs/{job_id}/logs?lines=300`
- `POST /api/vms/{id}/exec-jobs/{job_id}/cancel`

The interactive human terminal remains available at:

- `GET /ws/vms/{id}/terminal?cols=120&rows=40`

This is a websocket PTY. Agents can use it, but it requires handling prompts, ANSI control sequences, terminal state, and command completion detection. Prefer `/api/vms/{id}/exec`.

## Networking

- `GET /api/networks`
- `POST /api/networks`
- `DELETE /api/networks/{id}`
- `GET /api/vms/{id}/network`
- `POST /api/vms/{id}/ingress-rules`
- `DELETE /api/vms/{id}/ingress-rules/{rule_id}`
- `GET /api/egress-policies`
- `POST /api/egress-policies`
- `PUT /api/vms/{id}/egress-policy`
- `DELETE /api/egress-policies/{id}`

Ingress rule example:

```json
{"protocol":"tcp","host_port":8081,"guest_port":80,"description":"agent test service"}
```

Egress policy example:

```json
{"name":"web-only","mode":"restricted","tcp_ports":"80,443","udp_ports":"53","cidrs":"0.0.0.0/0"}
```

## SSH Keys

- `GET /api/ssh-keys`
- `POST /api/ssh-keys/generate`
- `POST /api/ssh-keys/import`
- `GET /api/ssh-keys/{id}`
- `DELETE /api/ssh-keys/{id}`

Generated private keys are returned once in `private_key`; BAP Web stores only the public key.

## Base Images

- `GET /api/base-images`
- `POST /api/base-images/register`
- `POST /api/base-images/build`
- `PATCH /api/base-images/{id}`
- `DELETE /api/base-images/{id}`
- `GET /api/image-build-jobs/{id}`
- `GET /api/image-build-jobs/{id}/logs?lines=300`
- `GET /api/image-hooks`
- `POST /api/image-hooks`
- `DELETE /api/image-hooks/{id}`

## Kernels

- `GET /api/kernels`
- `POST /api/kernels/firecracker-ci/scan`
- `GET /api/kernels/firecracker-ci/scan-jobs`
- `GET /api/kernels/firecracker-ci/scan-jobs/{id}`
- `GET /api/kernels/firecracker-ci/items?job_id={id}`
- `POST /api/kernels/import-firecracker-ci`
- `POST /api/kernels/upload`
- `PATCH /api/kernels/{id}`
- `DELETE /api/kernels/{id}`
- `POST /api/kernels/{id}/test`
- `GET /api/kernel-test-jobs/{id}`
- `GET /api/kernel-test-jobs/{id}/logs?lines=300`

## Host Status

- `GET /api/host/status`
- `GET /api/host/orphans`
- `POST /api/host/orphans/cleanup`

Agents should check host status before creating or starting many VMs.
