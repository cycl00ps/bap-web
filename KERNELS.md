# Kernel Management

`bap-web` stores guest kernels in the kernel registry and only offers active kernels during normal VM creation.

## Firecracker CI Discovery

Admins can open `/kernels` and use **Refresh Firecracker CI kernels**. A refresh creates a scan job, lists supported kernel artifacts for the host architecture, and records the results in the database.

Default behavior:

- Blank CI prefix scans the latest stable Firecracker CI release prefix matching `firecracker-ci/v<major>.<minor>/`.
- A custom prefix can be supplied, for example `firecracker-ci/v1.15/`.
- The scan reads the architecture folder for the current host, such as `x86_64` or `aarch64`.
- Supported discovered kernels are `vmlinux-5.10.*`, `vmlinux-5.10.*-no-acpi`, and `vmlinux-6.1.*`.
- Debug kernels, compressed debug files, rootfs files, initramfs files, and Firecracker binaries are ignored.

The scan job records `queued`, `running`, `succeeded`, or `failed`, plus item count and any error. Timeouts use `kernels.ci_scan_timeout`.

## Manual Upstream Browsing

The default upstream source is:

```text
https://s3.amazonaws.com/spec.ccfc.min
```

Start by listing release prefixes:

```text
https://s3.amazonaws.com/spec.ccfc.min?list-type=2&prefix=firecracker-ci/&delimiter=/
```

Then inspect an architecture folder:

```text
https://s3.amazonaws.com/spec.ccfc.min?list-type=2&prefix=firecracker-ci/v1.15/x86_64/
https://s3.amazonaws.com/spec.ccfc.min?list-type=2&prefix=firecracker-ci/v1.15/aarch64/
```

Use the configured `kernels.firecracker_ci_base_url` if the deployment points at a mirror.

## Import And Test Workflow

Discovered kernels can be imported from the `/kernels` table. Manual typed import remains available for advanced cases.

Imported Firecracker CI kernels are registered as `pending`. Run the kernel test action to boot an ephemeral VM, SSH into it, run `uname -r`, and verify gateway connectivity. A successful test marks the kernel `active`; failed tests mark it `failed`.

Normal VM creation only offers active kernels.

## Related Config

```yaml
kernels:
  max_kernel_bytes: 536870912
  test_timeout: "5m"
  ci_scan_timeout: "15s"
  ci_import_timeout: "2m"
  firecracker_ci_base_url: "https://s3.amazonaws.com/spec.ccfc.min"
```
