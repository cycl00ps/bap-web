package lifecycle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-web/internal/config"
	"bap-web/internal/model"
	"bap-web/internal/store"

	"github.com/gorilla/websocket"
)

func TestTapNameForIDFitsLinuxLimit(t *testing.T) {
	name := tapNameForID("8725ee030cb1d96b")
	if len(name) > maxLinuxIFNameLen {
		t.Fatalf("tap name %q length = %d, want <= %d", name, len(name), maxLinuxIFNameLen)
	}
	if name != "tap-8725ee030cb" {
		t.Fatalf("tap name = %q", name)
	}
	if !validIFName(name) {
		t.Fatalf("tap name %q should be valid", name)
	}
}

func TestValidIFNameRejectsTooLongTapName(t *testing.T) {
	if validIFName("tap-8725ee030cb1d96b") {
		t.Fatal("expected long tap name to be rejected")
	}
}

func TestCleanupOKTreatsMissingDevicesAsSuccess(t *testing.T) {
	cases := []string{
		"ip link delete tap-test: Cannot find device",
		"umount /srv/jailer/test: exit status 32: not mounted",
		"umount /srv/jailer/test: exit status 32: no mount point specified",
		"ip link set dev tap-test nomaster: exit status 2: Invalid argument",
	}
	for _, msg := range cases {
		if !cleanupOK(errors.New(msg)) {
			t.Fatalf("cleanupOK(%q) = false", msg)
		}
	}
	if cleanupOK(errors.New("permission denied")) {
		t.Fatal("expected permission denied to remain an error")
	}
	if cleanupOK(errors.New("ip tuntap del dev tap-test mode tap: Device or resource busy")) {
		t.Fatal("expected busy TAP to remain an error")
	}
}

func TestParseTerminalResizeMessage(t *testing.T) {
	size, ok := parseTerminalResizeMessage([]byte(`{"type":"resize","cols":160,"rows":36}`))
	if !ok {
		t.Fatal("expected resize message to parse")
	}
	if size.Cols != 160 || size.Rows != 36 {
		t.Fatalf("size = %#v", size)
	}
	size, ok = parseTerminalResizeMessage([]byte(`{"type":"resize","cols":1,"rows":1}`))
	if !ok {
		t.Fatal("expected resize message with invalid dimensions to parse with defaults")
	}
	if size.Cols != 120 || size.Rows != 40 {
		t.Fatalf("defaulted size = %#v", size)
	}
	if _, ok := parseTerminalResizeMessage([]byte(`plain input`)); ok {
		t.Fatal("plain input should not parse as resize")
	}
	if _, ok := parseTerminalResizeMessage([]byte(`{"type":"input","cols":160,"rows":36}`)); ok {
		t.Fatal("non-resize control message should not parse as resize")
	}
}

type recordingWSWriter struct {
	messageTypes []int
	messages     []string
	err          error
}

func (w *recordingWSWriter) WriteMessage(messageType int, data []byte) error {
	if w.err != nil {
		return w.err
	}
	w.messageTypes = append(w.messageTypes, messageType)
	w.messages = append(w.messages, string(data))
	return nil
}

func TestTerminalOutputToWSWritesBinaryMessagesInOrder(t *testing.T) {
	writer := &recordingWSWriter{}
	out := make(chan []byte, 2)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	out <- []byte("first")
	out <- []byte("second")
	close(out)

	terminalOutputToWS(writer, out, done, errCh)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected terminal writer error: %v", err)
		}
	default:
		t.Fatal("expected clean terminal writer completion")
	}
	if got, want := len(writer.messages), 2; got != want {
		t.Fatalf("message count = %d, want %d", got, want)
	}
	for i, messageType := range writer.messageTypes {
		if messageType != websocket.BinaryMessage {
			t.Fatalf("message %d type = %d, want binary", i, messageType)
		}
	}
	if strings.Join(writer.messages, "|") != "first|second" {
		t.Fatalf("messages = %#v", writer.messages)
	}
}

func TestTerminalOutputToWSReportsWriteError(t *testing.T) {
	writeErr := errors.New("write failed")
	writer := &recordingWSWriter{err: writeErr}
	out := make(chan []byte, 1)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	out <- []byte("output")

	terminalOutputToWS(writer, out, done, errCh)

	select {
	case err := <-errCh:
		if !errors.Is(err, writeErr) {
			t.Fatalf("error = %v, want %v", err, writeErr)
		}
	default:
		t.Fatal("expected write error")
	}
}

func TestNormalizeVMExecRequestValidatesAndDefaults(t *testing.T) {
	req, err := normalizeVMExecRequest(VMExecRequest{Command: "  id  "})
	if err != nil {
		t.Fatal(err)
	}
	if req.Command != "id" || req.TimeoutSeconds != defaultVMExecTimeoutSeconds {
		t.Fatalf("normalized request = %#v", req)
	}
	if _, err := normalizeVMExecRequest(VMExecRequest{}); err == nil {
		t.Fatal("expected empty command to fail")
	}
	if _, err := normalizeVMExecRequest(VMExecRequest{Command: "id", TimeoutSeconds: maxVMExecTimeoutSeconds + 1}); err == nil {
		t.Fatal("expected excessive timeout to fail")
	}
	if _, err := normalizeVMExecRequest(VMExecRequest{Command: "id", Env: map[string]string{"BAD-NAME": "x"}}); err == nil {
		t.Fatal("expected invalid env name to fail")
	}
}

func TestBuildRemoteExecCommandQuotesCWDEnvAndCommand(t *testing.T) {
	req := VMExecRequest{
		Command: "printf '%s' \"$GREETING\"",
		CWD:     "/tmp/dir with space",
		Env: map[string]string{
			"GREETING": "hello world",
			"Z":        "last",
		},
	}
	got := buildRemoteExecCommand(req)
	for _, want := range []string{
		"cd '/tmp/dir with space'",
		"env GREETING='hello world' Z='last'",
		"sh -lc 'printf '\\''%s'\\'' \"$GREETING\"'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("command %q missing %q", got, want)
		}
	}
}

func TestLimitedBufferTruncatesWithoutShortWrite(t *testing.T) {
	buf := &limitedBuffer{limit: 4}
	n, err := buf.Write([]byte("abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("write count = %d", n)
	}
	if buf.String() != "abcd" || !buf.Truncated() {
		t.Fatalf("buffer = %q truncated=%t", buf.String(), buf.Truncated())
	}
}

func TestExecuteVMCommandRejectsStoppedVMBeforeSSH(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	now := time.Now().UTC()
	vm := model.VM{
		ID: "vm-exec-stopped", Name: "execstopped", State: model.VMStopped, VCPUCount: 1, MemMiB: 512,
		SSHPort: 26001, TapName: "tap-execstop", HostIP: "172.31.91.1", GuestIP: "172.31.91.2", CIDR: 30,
		KernelPath: "/kernel", RootFSPath: "/rootfs", BaseRootFSPath: "/base", DevUser: "dev",
		GitRef: "HEAD", EgressMode: "allow_all", NetworkMode: "routed_ptp", CreatedAt: now, UpdatedAt: now,
	}
	if err := svc.store.CreateVM(ctx, vm); err != nil {
		t.Fatal(err)
	}
	_, err := svc.ExecuteVMCommand(ctx, vm.ID, VMExecRequest{Command: "id"})
	var domain *DomainError
	if !errors.As(err, &domain) || domain.Code != CodeUnusable {
		t.Fatalf("expected unprocessable stopped VM error, got %#v", err)
	}
}

func TestCreateNetworkRejectsOverlappingSharedCIDRs(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()

	if _, err := svc.CreateNetwork(ctx, "base", "172.31.50.0/25", ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cidr string
	}{
		{"duplicate", "172.31.50.0/25"},
		{"parent", "172.31.50.0/24"},
		{"child", "172.31.50.64/26"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateNetwork(ctx, tc.name, tc.cidr, "")
			if err == nil {
				t.Fatalf("expected %s to be rejected", tc.cidr)
			}
			var domain *DomainError
			if !errors.As(err, &domain) || domain.Code != CodeConflict || domain.Fields["cidr"] == "" {
				t.Fatalf("expected conflict field error, got %#v", err)
			}
		})
	}
	if _, err := svc.CreateNetwork(ctx, "adjacent", "172.31.50.128/25", ""); err != nil {
		t.Fatalf("adjacent CIDR should be accepted: %v", err)
	}
}

func TestCreateNetworkRejectsOverlapWithRoutedVM(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	now := time.Now().UTC()
	if err := svc.store.CreateVM(ctx, model.VM{
		ID: "vm1", Name: "routed", State: model.VMStopped, VCPUCount: 1, MemMiB: 512,
		SSHPort: 20001, TapName: "tap-vm1", HostIP: "172.31.60.1", GuestIP: "172.31.60.2", CIDR: 30,
		KernelPath: "/kernel", RootFSPath: "/rootfs", BaseRootFSPath: "/base", DevUser: "dev",
		GitRef: "HEAD", EgressMode: "allow_all", NetworkMode: "routed_ptp", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := svc.CreateNetwork(ctx, "bad", "172.31.60.0/29", "")
	if err == nil {
		t.Fatal("expected routed overlap to be rejected")
	}
	var domain *DomainError
	if !errors.As(err, &domain) || domain.Code != CodeConflict || domain.Fields["cidr"] == "" {
		t.Fatalf("expected conflict field error, got %#v", err)
	}
	if _, err := svc.CreateNetwork(ctx, "ok", "172.31.60.4/30", ""); err != nil {
		t.Fatalf("adjacent routed CIDR should be accepted: %v", err)
	}
}

func TestAllocateP2PSkipsExistingSharedNetworks(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	if _, err := svc.CreateNetwork(ctx, "first-block", "172.31.0.0/30", ""); err != nil {
		t.Fatal(err)
	}
	host, guest, cidr, err := svc.allocateP2P(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if host != "172.31.0.5" || guest != "172.31.0.6" || cidr != 30 {
		t.Fatalf("unexpected allocation: host=%s guest=%s cidr=%d", host, guest, cidr)
	}
}

func TestNetworkConflictsReportsExistingBadRecords(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	now := time.Now().UTC()
	if err := svc.store.CreateNetwork(ctx, model.Network{ID: "n1", Name: "parent", CIDR: "172.31.80.0/24", GatewayIP: "172.31.80.1", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.CreateNetwork(ctx, model.Network{ID: "n2", Name: "child", CIDR: "172.31.80.0/25", GatewayIP: "172.31.80.1", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	conflicts, err := svc.NetworkConflicts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %#v", conflicts)
	}
	if !strings.Contains(conflicts[0].Message, "parent") || !strings.Contains(conflicts[0].Message, "child") {
		t.Fatalf("unexpected message: %q", conflicts[0].Message)
	}
}

func TestDeleteManagedBaseImageRemovesGeneratedFile(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	imageDir := filepath.Join(svc.cfg.Paths.BaseImageDir, "managed-job")
	imagePath := filepath.Join(imageDir, "rootfs.ext4")
	if err := os.MkdirAll(imageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(imagePath, []byte("image"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := svc.store.CreateBaseImage(ctx, model.BaseImage{
		ID:             "img1",
		Name:           "managed",
		Status:         imageStatusActive,
		Filesystem:     "ext4",
		Path:           imagePath,
		VirtualSizeMiB: 1,
		DiskSizeBytes:  5,
		Checksum:       "checksum",
		Provenance:     "managed build job job1",
		CreatedBy:      "admin",
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.DeleteBaseImage(ctx, "img1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(imagePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed image file still exists or stat failed unexpectedly: %v", err)
	}
	if _, err := os.Stat(imageDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed image directory still exists or stat failed unexpectedly: %v", err)
	}
}

func TestEnsureDefaultKernelRegistersConfiguredKernel(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	kernelPath := filepath.Join(svc.cfg.Paths.KernelDir, "vmlinux-5.10.bin")
	if err := os.MkdirAll(filepath.Dir(kernelPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kernelPath, []byte("test-kernel"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.cfg.Paths.KernelImage = kernelPath
	now := time.Now().UTC()
	if err := svc.store.CreateVM(ctx, model.VM{
		ID: "legacy-vm", Name: "legacy", State: model.VMStopped, VCPUCount: 1, MemMiB: 512,
		SSHPort: 21001, TapName: "tap-legacy", HostIP: "172.31.70.1", GuestIP: "172.31.70.2", CIDR: 30,
		KernelPath: kernelPath, RootFSPath: "/rootfs", BaseRootFSPath: "/base", DevUser: "dev",
		GitRef: "HEAD", EgressMode: "allow_all", NetworkMode: "routed_ptp", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := svc.EnsureDefaultKernel(ctx); err != nil {
		t.Fatal(err)
	}
	kernel, err := svc.store.DefaultKernel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kernel == nil || kernel.Name != "default-kernel-5-10" || kernel.Status != "active" || kernel.SourceType != "configured" {
		t.Fatalf("unexpected default kernel: %#v", kernel)
	}
	vm, err := svc.store.GetVM(ctx, "legacy-vm")
	if err != nil {
		t.Fatal(err)
	}
	if vm == nil || vm.KernelID != kernel.ID {
		t.Fatalf("legacy VM kernel id was not backfilled: vm=%#v kernel=%#v", vm, kernel)
	}
}

func TestUploadKernelValidationFailureRemovesStagingDirectory(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()

	_, err := svc.UploadKernel(ctx, UploadKernelRequest{
		Name:         "bad-kernel",
		Version:      "0.0",
		KernelName:   "vmlinux-bad",
		KernelReader: strings.NewReader("not a kernel"),
	}, "admin")
	if err == nil {
		t.Fatal("expected invalid upload to fail")
	}
	var domain *DomainError
	if !errors.As(err, &domain) || domain.Code != CodeInvalid || domain.Fields["kernel"] == "" {
		t.Fatalf("expected invalid kernel field error, got %#v", err)
	}
	entries, readErr := os.ReadDir(svc.cfg.Paths.KernelDir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("expected upload staging directory cleanup, got %#v", entries)
	}
}

func TestLatestFirecrackerCIPrefixSelectsStableRelease(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <CommonPrefixes><Prefix>firecracker-ci/v1.15/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/vTest-bchalios/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/v1.15-vmclock/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/v1.9/</Prefix></CommonPrefixes>
</ListBucketResult>`))
	}))
	defer server.Close()
	svc.cfg.Kernels.FirecrackerCIBaseURL = server.URL

	prefix, err := svc.latestFirecrackerCIPrefix(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "firecracker-ci/v1.15/" {
		t.Fatalf("prefix = %q", prefix)
	}
}

func TestKernelDiscoveryScansSupportedArtifacts(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.URL.Query().Get("delimiter") == "/":
			_, _ = w.Write([]byte(`<ListBucketResult>
  <CommonPrefixes><Prefix>firecracker-ci/v1.15/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/vTest-bchalios/</Prefix></CommonPrefixes>
  <CommonPrefixes><Prefix>firecracker-ci/v1.14/</Prefix></CommonPrefixes>
</ListBucketResult>`))
		case r.URL.Query().Get("prefix") == "firecracker-ci/v1.15/x86_64/":
			_, _ = w.Write([]byte(`<ListBucketResult>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-5.10.245-no-acpi</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-5.10.245-no-acpi.config</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/debug/vmlinux-6.1.155</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.debug.gz</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/initramfs.cpio</Key></Contents>
</ListBucketResult>`))
		default:
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
	}))
	defer server.Close()
	svc.cfg.Kernels.FirecrackerCIBaseURL = server.URL

	job, err := svc.StartKernelDiscovery(ctx, DiscoverFirecrackerCIKernelsRequest{}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	job = waitForDiscoveryJob(t, svc, job.ID)
	if job.Status != jobStatusSucceeded || job.CIPrefix != "firecracker-ci/v1.15/" || job.ItemCount != 2 {
		t.Fatalf("unexpected discovery job: %#v", job)
	}
	items, err := svc.store.ListKernelDiscoveryItems(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %#v", items)
	}
	if items[0].Version != "6.1.155" || items[0].Variant != "standard" {
		t.Fatalf("unexpected first item: %#v", items[0])
	}
	if items[1].Version != "5.10.245-no-acpi" || items[1].Variant != "no-acpi" || items[1].ConfigKey == "" {
		t.Fatalf("unexpected second item: %#v", items[1])
	}
}

func TestKernelDiscoveryTimeoutMarksJobFailed(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`<ListBucketResult></ListBucketResult>`))
	}))
	defer server.Close()
	svc.cfg.Kernels.FirecrackerCIBaseURL = server.URL
	svc.cfg.Kernels.CIScanTimeout = config.Duration{Duration: 50 * time.Millisecond}

	job, err := svc.StartKernelDiscovery(ctx, DiscoverFirecrackerCIKernelsRequest{}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	job = waitForDiscoveryJob(t, svc, job.ID)
	if job.Status != jobStatusFailed || job.Error == "" {
		t.Fatalf("expected failed timeout job, got %#v", job)
	}
}

func TestImportDiscoveredKernelDetectsExistingProvenance(t *testing.T) {
	ctx := context.Background()
	svc, closeStore := newTestService(t)
	defer closeStore()
	now := time.Now().UTC()
	item := model.KernelDiscoveryItem{
		ID: "artifact1", JobID: "job1", Version: "6.1.155", Variant: "standard", Architecture: "x86_64",
		CIPrefix: "firecracker-ci/v1.15/", KernelKey: "firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
		KernelURL: "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
		CreatedAt: now,
	}
	if err := svc.store.ReplaceKernelDiscoveryItems(ctx, "job1", []model.KernelDiscoveryItem{item}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.CreateKernel(ctx, model.Kernel{
		ID: "kernel1", Name: "existing", Version: "6.1.155", Architecture: "x86_64", Status: "active",
		SourceType: "firecracker-ci", Path: filepath.Join(svc.cfg.Paths.KernelDir, "vmlinux-6.1.155"),
		Checksum: "checksum", Provenance: item.KernelURL, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := svc.ImportFirecrackerCIKernel(ctx, ImportFirecrackerCIKernelRequest{ArtifactID: "artifact1"}, "admin")
	if err == nil {
		t.Fatal("expected duplicate artifact import to fail")
	}
	var domain *DomainError
	if !errors.As(err, &domain) || domain.Code != CodeConflict || domain.Fields["artifact_id"] == "" {
		t.Fatalf("expected artifact conflict, got %#v", err)
	}
	updated, err := svc.store.GetKernelDiscoveryItem(ctx, "artifact1")
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || !updated.AlreadyRegistered {
		t.Fatalf("expected discovery item marked registered: %#v", updated)
	}
}

func waitForDiscoveryJob(t *testing.T, svc *Service, id string) *model.KernelDiscoveryJob {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err := svc.store.GetKernelDiscoveryJob(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if job != nil && job.Status != jobStatusQueued && job.Status != jobStatusRunning {
			return job
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, _ := svc.store.GetKernelDiscoveryJob(context.Background(), id)
	t.Fatalf("discovery job did not finish: %#v", job)
	return nil
}

func newTestService(t *testing.T) (*Service, func()) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp(wd, ".test-lifecycle-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tmp)
	})
	st, err := store.Open("sqlite", filepath.Join(tmp, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Network.VMCIDR = "172.31.0.0/16"
	cfg.Paths.BaseImageDir = filepath.Join(tmp, "base-images")
	cfg.Paths.KernelDir = filepath.Join(tmp, "kernels")
	cfg.Paths.KernelImage = filepath.Join(cfg.Paths.KernelDir, "vmlinux-5.10.bin")
	cfg.Images.BuildDir = filepath.Join(tmp, "image-builds")
	cfg.Images.HookDir = filepath.Join(tmp, "image-hooks")
	return New(cfg, st), func() { _ = st.Close() }
}
