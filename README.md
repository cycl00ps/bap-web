# BAP Web

BAP Web is a Go and HTMX control plane for running and managing Firecracker microVMs from a web browser or an API client. It exists to make short-lived, isolated Linux environments easier to create, inspect, automate, and retire without requiring every user or automation agent to understand Firecracker sockets, jailer setup, nftables rules, disk image management, and SSH bootstrap details.

The project is built for two primary audiences:

- Human operators who need a browser UI to create, start, stop, inspect, and troubleshoot microVMs.
- LLM agents and other automation clients that need a documented API for creating VMs, running commands, collecting results, and cleaning up resources.

BAP Web is API-first. The HTML interface is a human client over the same service layer used by the JSON API, OpenAPI document, and agent instructions.

## What It Provides

BAP Web manages the host-side lifecycle around Firecracker microVMs:

- Firecracker and jailer launch.
- SQLite-backed registry for VMs, SSH keys, API tokens, images, kernels, networks, and jobs.
- Web UI for VM lifecycle, shell access, resources, networking, images, kernels, and API tokens.
- JSON APIs under `/api/...` for automation.
- HTMX UI actions under `/ui/...`.
- WebSocket terminal access under `/ws/...`.
- Public API and agent documentation at `/openapi.json`, `/docs/api`, `/docs/agents.md`, and `/llms.txt`.

### MicroVM Management

- Create, start, stop, restart, and delete Firecracker microVMs.
- Configure vCPU and memory at creation time.
- Edit CPU and memory while a VM is stopped.
- Select an active base rootfs image and tested kernel when creating a VM.
- Choose routed point-to-point networking or shared bridge networking.
- View VM logs, state, shell, networking, resources, and errors from the VM detail page.

### Shell And Agent Execution

- Browser users can open an interactive terminal to a running microVM.
- API clients can run non-interactive shell commands with clean stdout, stderr, exit code, timeout, and truncation fields.
- Long-running command jobs can be started, polled, logged, and cancelled through the API.
- Agent-facing documentation explains the recommended workflow for selecting resources, creating a VM, running commands, and cleaning up.

See [API_FOR_AGENTS.md](./API_FOR_AGENTS.md) for the full automation guide.

### Authentication And Tokens

- Initial setup creates a local admin user.
- Browser sessions use secure cookies and CSRF protection.
- API clients should use bearer tokens.
- Admins can create, list, and revoke tokens for any existing user.
- Non-admin users can create, list, and revoke only their own non-admin tokens.
- Generated API token secrets and SSH private keys are shown once; BAP Web stores only hashes or public keys.

### SSH Keys

- Generate EC2-style SSH keys from the UI or API.
- Import existing public keys.
- Select a key when creating a VM.
- Generated private keys are never stored by the server after the one-time export.

### Networking

- nftables-backed ingress, egress, NAT, anti-spoofing, and protected-host rules.
- Default routed `/30` point-to-point VM networking.
- Optional shared bridge networks for multiple microVMs on the same subnet.
- Per-VM ingress rules mapping host TCP/UDP ports to guest ports.
- Reusable egress policies with `allow_all`, `deny_all`, and restricted TCP/UDP/CIDR modes.
- Host status checks for network conflicts and stale host-side devices.

### Images And Rootfs Management

- Register existing base rootfs images.
- Build new base images with package lists and optional hooks.
- Track image build jobs and logs.
- Select a base image when creating a VM.
- Configure the derived VM rootfs size at creation time.
- Use sparse or reflink copies where the host filesystem supports them.

### Kernel Management

- Register a configured kernel path from `paths.kernel_image`.
- Import Firecracker CI kernels.
- Upload local kernels.
- Run kernel test jobs that boot an ephemeral VM, check `uname -r`, and verify gateway connectivity.
- Mark successfully tested kernels active for VM creation.

See [KERNELS.md](./KERNELS.md) for Firecracker CI discovery, manual browsing, imports, and testing details.

## Supported Platforms

BAP Web is intended to run on a Linux host that can launch Firecracker microVMs.

Required host capabilities:

- Linux with KVM available at `/dev/kvm`.
- `systemd` for the packaged service workflow.
- `nftables` for host networking policy.
- Firecracker and jailer installed at the configured paths.
- Root privileges for v1 because the service manages KVM, TAP devices, mounts, jailer directories, nftables, rootfs images, and runtime metadata access.

Best-supported deployment path today:

- Fedora, RHEL, CentOS Stream, AlmaLinux, Rocky Linux, or a similar RHEL-family host.
- The included rootfs and host-prep scripts currently assume `dnf`.

Other Linux distributions may work if equivalent packages and Firecracker binaries are installed manually, but the helper scripts are not yet distro-neutral.

Not supported for launching microVMs:

- macOS or Windows as the Firecracker host.
- WSL without real KVM access.
- Containers or unprivileged environments without `/dev/kvm`, TAP, mount, and nftables privileges.

## Deployment Quickstart

These steps describe a host deployment using the included systemd service.

### 1. Install Host Dependencies

Install the runtime tools expected by BAP Web:

- Go matching the version in [go.mod](./go.mod).
- Firecracker.
- jailer.
- nftables.
- iproute tools.
- OpenSSH client tools.
- filesystem tools such as `mkfs.ext4`, `mkfs.xfs`, `resize2fs`, and `xfs_growfs`.
- `dnf` if using the included base-rootfs builder.
- `git`, `curl`, `mount`, `umount`, and `chroot`.

The host must expose `/dev/kvm`.

### 2. Build The Binary

```bash
go mod download
go test ./...
go build -o ./bap-webd ./cmd/bap-webd
```

### 3. Install The systemd Service

```bash
sudo bash ./scripts/install-systemd.sh
sudo systemctl status bap-webd --no-pager
```

The installer:

- copies `./bap-webd` to `/usr/local/bin/bap-webd`,
- installs static assets to `/usr/local/share/bap-web/static`,
- creates `/etc/bap-web/config.yaml` if it does not already exist,
- creates runtime directories under `/var/lib/bap-web`, `/var/lib/microvms`, `/srv/jailer`, and `/var/log/bap-web`,
- installs and starts `bap-webd.service`.

Default local URL:

```text
http://127.0.0.1:8080
```

### 4. Bootstrap The Initial Admin

```bash
sudo bash ./scripts/bootstrap-admin.sh
```

The generated initial credentials are written root-only to:

```text
/etc/bap-web/initial-admin.txt
```

### 5. Prepare A Kernel And Base Rootfs

Install or import a Firecracker-compatible kernel. The default configured kernel path is:

```text
/var/lib/microvms/kernels/vmlinux-5.10.bin
```

If you have a known-good kernel file, install it with:

```bash
sudo bash ./scripts/install-kernel.sh /path/to/vmlinux /var/lib/microvms/kernels/vmlinux-5.10.bin
```

Create a default base rootfs image with:

```bash
sudo bash ./scripts/create-base-rootfs.sh
```

The default base rootfs path is:

```text
/var/lib/microvms/base/base-rootfs.ext4
```

You can also manage kernels and base images through the web UI after the service is running.

### 6. Validate Host Readiness

```bash
sudo bash ./scripts/host-check.sh
```

This checks required commands, key paths, KVM access, nftables, default kernel/rootfs files, routing, and Firecracker socket startup.

### 7. Configure Remote Access

BAP Web binds to `127.0.0.1:8080` by default. For remote browser access, keep BAP Web bound locally and place a TLS reverse proxy such as Caddy or nginx in front of it.

Example Caddy config:

```text
:80 {
	reverse_proxy 127.0.0.1:8080
}
```

See [deploy/Caddyfile](./deploy/Caddyfile) and [deploy/config.local-caddy.yaml](./deploy/config.local-caddy.yaml) for local examples.

When exposing BAP Web through a proxy, update `server.trusted_hosts` and `server.allowed_origins` in `/etc/bap-web/config.yaml`.

## Configuration

The default service config lives at:

```text
/etc/bap-web/config.yaml
```

The example config is [config.example.yaml](./config.example.yaml).

Important defaults:

- `server.bind_address`: `127.0.0.1`
- `server.port`: `8080`
- `database.driver`: `sqlite`
- `database.dsn`: `/var/lib/bap-web/bap-web.db`
- `paths.base_image_dir`: `/var/lib/microvms/base`
- `paths.kernel_dir`: `/var/lib/microvms/kernels`
- `network.backend`: `nftables`
- `network.vm_cidr`: `172.31.0.0/16`
- `network.ssh_port_range`: `20000-29999`
- `security.terminal_recording`: `metadata`

SQLite is the implemented database backend in v1.

## Development

```bash
go mod download
go test ./...
go run ./cmd/bap-webd --config ./config.example.yaml
```

For a local smoke check that starts the web service with a temporary config:

```bash
go build -o ./bap-webd ./cmd/bap-webd
./scripts/smoke-local.sh
```

Host integration checks and real VM launch require root privileges, KVM, Firecracker, jailer, nftables, and a base rootfs:

```bash
sudo bash ./scripts/dev-integration.sh
```

Run the live VM smoke test against a prepared host with:

```bash
sudo BAP_WEB_RUN_LIVE_VM_SMOKE=1 bash ./scripts/dev-integration.sh
```

## Repository Layout

- `cmd/bap-webd`: server entry point.
- `internal/app`: HTTP routes, templates, static assets, OpenAPI and agent docs.
- `internal/lifecycle`: Firecracker, jailer, VM lifecycle, images, kernels, shell execution, and networking orchestration.
- `internal/store`: SQLite schema and registry access.
- `internal/config`: YAML config loading and defaults.
- `scripts`: build, host prep, systemd install, rootfs creation, and smoke tests.
- `deploy`: example reverse-proxy and local deployment config.

## Security Notes

- BAP Web should bind to localhost by default and be exposed remotely only through a TLS reverse proxy.
- The v1 systemd service runs as root because it manages privileged host resources.
- Keep `/etc/bap-web/config.yaml`, `/etc/bap-web/initial-admin.txt`, and `/var/lib/bap-web` root-restricted.
- Use short-lived, least-privilege API tokens for agents and scripts.
- Generated API token secrets and SSH private keys are shown once and cannot be recovered later.
- Browser mutating requests require CSRF protection; bearer-token API requests do not use CSRF.
- Networking controls are enforced with nftables, but admins should still review egress policies and protected host CIDRs before running untrusted workloads.
- Full terminal session recording is configurable, but the default is metadata-only recording.

## Additional Documentation

- [API_FOR_AGENTS.md](./API_FOR_AGENTS.md): API guide for LLMs and automation agents.
- [KERNELS.md](./KERNELS.md): kernel discovery, import, upload, and testing.
- [UI_LAYOUT.md](./UI_LAYOUT.md): UI layout and responsive design rules.
