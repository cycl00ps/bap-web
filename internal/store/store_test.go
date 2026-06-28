package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"bap-web/internal/model"
)

func TestUserSessionAndVM(t *testing.T) {
	ctx := context.Background()
	st, err := Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	has, err := st.HasUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("expected no users")
	}

	u := model.User{ID: "u1", Username: "admin", PasswordHash: []byte("hash"), IsAdmin: true, CreatedAt: time.Now()}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := st.UserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != "u1" || !got.IsAdmin {
		t.Fatalf("unexpected user: %#v", got)
	}
	token := model.APIToken{
		ID:        "tok1",
		Name:      "agent",
		Prefix:    "bap_deadbeef",
		IsAdmin:   true,
		CreatedBy: "admin",
		CreatedAt: time.Now(),
	}
	if err := st.CreateAPIToken(ctx, token, "hash1"); err != nil {
		t.Fatal(err)
	}
	gotToken, err := st.GetAPITokenByHash(ctx, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if gotToken == nil || gotToken.Name != "agent" || !gotToken.IsAdmin {
		t.Fatalf("unexpected api token: %#v", gotToken)
	}
	if err := st.TouchAPIToken(ctx, "tok1"); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeAPIToken(ctx, "tok1"); err != nil {
		t.Fatal(err)
	}
	revoked, err := st.GetAPITokenByHash(ctx, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked == nil || revoked.RevokedAt == nil || revoked.LastUsedAt == nil {
		t.Fatalf("expected revoked and touched token: %#v", revoked)
	}

	vm := model.VM{
		ID: "vm1", Name: "testvm", State: model.VMStopped, VCPUCount: 2, MemMiB: 512,
		SSHPort: 20000, TapName: "tap-testvm", HostIP: "172.31.1.1", GuestIP: "172.31.1.2", CIDR: 30,
		KernelPath: "/kernel", KernelID: "kernel1", RootFSPath: "/rootfs", BaseRootFSPath: "/base", DevUser: "dev",
		SSHKeyID: "key1", ManagedSSHPublicKey: "pub", ManagedSSHPrivateKeyPath: "", GitRef: "HEAD",
		EgressMode: "allow_all", NetworkMode: "routed_ptp", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	kernel := model.Kernel{
		ID: "kernel1", Name: "test-kernel", Status: "active", SourceType: "configured",
		Path: "/kernel", Checksum: "checksum", Architecture: "x86_64", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.CreateKernel(ctx, kernel); err != nil {
		t.Fatal(err)
	}
	key := model.SSHKey{
		ID: "key1", Name: "test-key", PublicKey: "pub", Fingerprint: "SHA256:test", KeyType: "ssh-ed25519",
		CreatedBy: "admin", CreatedAt: time.Now(),
	}
	if err := st.CreateSSHKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateVM(ctx, vm); err != nil {
		t.Fatal(err)
	}
	execJob := model.VMExecJob{
		ID: "job1", VMID: vm.ID, Status: "succeeded", Command: "id", EnvJSON: "{}", TimeoutSeconds: 60,
		Stdout: "uid=1000\n", ExitCode: 0, LogPath: "/tmp/job.log", CreatedBy: "agent", CreatedAt: time.Now(),
	}
	if err := st.CreateVMExecJob(ctx, execJob); err != nil {
		t.Fatal(err)
	}
	gotExecJob, err := st.GetVMExecJob(ctx, vm.ID, "job1")
	if err != nil {
		t.Fatal(err)
	}
	if gotExecJob == nil || gotExecJob.Stdout != "uid=1000\n" || gotExecJob.ExitCode != 0 {
		t.Fatalf("unexpected exec job: %#v", gotExecJob)
	}
	gotExecJob.Status = "failed"
	gotExecJob.Error = "boom"
	gotExecJob.Truncated = true
	if err := st.UpdateVMExecJob(ctx, *gotExecJob); err != nil {
		t.Fatal(err)
	}
	jobs, err := st.ListVMExecJobs(ctx, vm.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Status != "failed" || !jobs[0].Truncated {
		t.Fatalf("unexpected exec jobs: %#v", jobs)
	}
	keys, err := st.ListSSHKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Name != "test-key" {
		t.Fatalf("unexpected keys: %#v", keys)
	}
	list, err := st.ListVMs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "testvm" {
		t.Fatalf("unexpected VMs: %#v", list)
	}
	vm.State = model.VMRunning
	if err := st.UpdateVM(ctx, vm); err != nil {
		t.Fatal(err)
	}
	updated, err := st.GetVM(ctx, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || updated.State != model.VMRunning {
		t.Fatalf("unexpected updated VM: %#v", updated)
	}
	if updated.KernelID != "kernel1" {
		t.Fatalf("kernel id was not persisted: %#v", updated)
	}
	if err := st.DeleteKernel(ctx, "kernel1"); err == nil {
		t.Fatal("expected deleting an assigned kernel to fail")
	}
	legacyKernel := model.Kernel{
		ID: "kernel2", Name: "legacy-kernel", Status: "active", SourceType: "configured",
		Path: "/kernel2", Checksum: "checksum2", Architecture: "x86_64", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.CreateKernel(ctx, legacyKernel); err != nil {
		t.Fatal(err)
	}
	legacyVM := model.VM{
		ID: "vm2", Name: "legacyvm", State: model.VMStopped, VCPUCount: 1, MemMiB: 512,
		SSHPort: 20001, TapName: "tap-legacy", HostIP: "172.31.2.1", GuestIP: "172.31.2.2", CIDR: 30,
		KernelPath: "/kernel2", RootFSPath: "/rootfs2", BaseRootFSPath: "/base", DevUser: "dev",
		ManagedSSHPublicKey: "pub", GitRef: "HEAD", EgressMode: "allow_all", NetworkMode: "routed_ptp",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.CreateVM(ctx, legacyVM); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteKernel(ctx, "kernel2"); err == nil {
		t.Fatal("expected deleting a legacy path-assigned kernel to fail")
	}
	if err := st.BackfillVMKernelID(ctx, "kernel2", "/kernel2"); err != nil {
		t.Fatal(err)
	}
	backfilled, err := st.GetVM(ctx, "vm2")
	if err != nil {
		t.Fatal(err)
	}
	if backfilled == nil || backfilled.KernelID != "kernel2" {
		t.Fatalf("legacy kernel id was not backfilled: %#v", backfilled)
	}
	discoveryJob := model.KernelDiscoveryJob{
		ID: "disc1", Status: "running", SourceURL: "https://s3.amazonaws.com/spec.ccfc.min",
		CIPrefix: "firecracker-ci/v1.15/", Architecture: "x86_64", CreatedBy: "admin", CreatedAt: time.Now(),
	}
	if err := st.CreateKernelDiscoveryJob(ctx, discoveryJob); err != nil {
		t.Fatal(err)
	}
	discoveryJob.Status = "succeeded"
	discoveryJob.ItemCount = 1
	completed := time.Now()
	discoveryJob.CompletedAt = &completed
	if err := st.UpdateKernelDiscoveryJob(ctx, discoveryJob); err != nil {
		t.Fatal(err)
	}
	items := []model.KernelDiscoveryItem{{
		ID: "artifact1", JobID: "disc1", Version: "6.1.155", Variant: "standard", Architecture: "x86_64",
		CIPrefix: "firecracker-ci/v1.15/", KernelKey: "firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
		ConfigKey: "firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config",
		KernelURL: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
		ConfigURL: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config",
		CreatedAt: time.Now(),
	}}
	if err := st.ReplaceKernelDiscoveryItems(ctx, "disc1", items); err != nil {
		t.Fatal(err)
	}
	gotJob, err := st.GetKernelDiscoveryJob(ctx, "disc1")
	if err != nil {
		t.Fatal(err)
	}
	if gotJob == nil || gotJob.Status != "succeeded" || gotJob.ItemCount != 1 || gotJob.CompletedAt == nil {
		t.Fatalf("unexpected discovery job: %#v", gotJob)
	}
	gotItems, err := st.ListKernelDiscoveryItems(ctx, "disc1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gotItems) != 1 || gotItems[0].Version != "6.1.155" || gotItems[0].AlreadyRegistered {
		t.Fatalf("unexpected discovery items: %#v", gotItems)
	}
	if err := st.MarkKernelDiscoveryItemRegistered(ctx, "artifact1", true); err != nil {
		t.Fatal(err)
	}
	gotItem, err := st.GetKernelDiscoveryItem(ctx, "artifact1")
	if err != nil {
		t.Fatal(err)
	}
	if gotItem == nil || !gotItem.AlreadyRegistered {
		t.Fatalf("expected item to be registered: %#v", gotItem)
	}

	network := model.Network{
		ID: "net1", Name: "devnet", CIDR: "172.31.50.0/29", GatewayIP: "172.31.50.1",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	networks, err := st.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 || networks[0].Name != "devnet" {
		t.Fatalf("unexpected networks: %#v", networks)
	}

	rule := model.IngressRule{
		ID: "rule1", VMID: "vm1", Protocol: "tcp", HostPort: 21080, GuestPort: 80,
		Description: "web", CreatedAt: time.Now(),
	}
	if err := st.CreateIngressRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	rules, err := st.ListIngressRules(ctx, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].HostPort != 21080 {
		t.Fatalf("unexpected ingress rules: %#v", rules)
	}

	policy := model.EgressPolicy{
		ID: "eg1", Name: "web", Mode: "restricted", TCPPorts: "80,443", UDPPorts: "53", CIDRs: "203.0.113.0/24",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.CreateEgressPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	policies, err := st.ListEgressPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].Name != "web" {
		t.Fatalf("unexpected egress policies: %#v", policies)
	}
}
