# BAP Web Agent Guide

This guide is for LLMs and automation agents using BAP Web through HTTP APIs.

## Authentication

Operational API calls require authentication. Use a bearer token supplied by the user or administrator:

```http
Authorization: Bearer bap_...
```

Bearer-token API requests do not need CSRF headers. Browser-session mutating requests must include `X-CSRF-Token` from `GET /api/session`, but agents should prefer bearer tokens.

Agents should not expect unauthenticated operational access. Agents should not create their own token unless the user has already authenticated as an admin and explicitly asks for token creation.

Use the least privilege token that can complete the task:

- Non-admin token: normal VM, shell, SSH key, network, and egress policy operations.
- Admin token: token management, image builds, image hooks, kernel import/upload/test/status/delete, and other administrative operations.
- Prefer short expiration times for agent tokens.

## Discovery

Start with:

```http
GET /api/health
GET /api/session
GET /openapi.json
```

Use the OpenAPI document for complete route, request, response, and error shapes.

Common resource discovery endpoints:

```http
GET /api/ssh-keys
GET /api/base-images
GET /api/kernels
GET /api/networks
GET /api/egress-policies
GET /api/vms
```

## Recommended VM Workflow

1. Confirm user intent before creating or deleting resources.
2. Pick an existing SSH key, active base image, active kernel, network mode, and egress policy.
3. Create the VM with `POST /api/vms`.
4. Start it with `POST /api/vms/{id}/start`.
5. Poll `GET /api/vms/{id}` until `state` is `running`.
6. Run shell commands with `POST /api/vms/{id}/exec`.
7. Inspect `exit_code`, `timed_out`, and `truncated` on every command result.
8. Stop or delete VMs created for temporary tasks unless the user asks to keep them.

## Shell Access

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

The response includes `stdout`, `stderr`, `exit_code`, `timed_out`, and `truncated`.

For long-running commands, use exec jobs:

```http
POST /api/vms/{id}/exec-jobs
GET /api/vms/{id}/exec-jobs/{job_id}
GET /api/vms/{id}/exec-jobs/{job_id}/logs?lines=300
POST /api/vms/{id}/exec-jobs/{job_id}/cancel
```

Use the websocket terminal only when a human-style interactive TTY is required:

```http
GET /ws/vms/{id}/terminal?cols=120&rows=40
```

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

Always surface the error message and relevant fields to the user.

## Safety Rules

- Do not use an admin token for ordinary VM tasks if a non-admin token is available.
- Do not expose bearer tokens, generated private keys, or command output containing secrets.
- Do not delete VMs, images, kernels, networks, or policies unless the user explicitly requests it.
- Use bounded timeouts for commands.
- Avoid interactive prompts; pass input through `stdin` when possible.
- Prefer API exec over websocket terminal for automation.
