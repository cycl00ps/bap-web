package lifecycle

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"bap-web/internal/config"
	"bap-web/internal/model"
	"bap-web/internal/random"
	"bap-web/internal/store"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type Service struct {
	cfg               *config.Config
	store             *store.Store
	terminalMu        sync.Mutex
	terminalKeys      []terminalKey
	imageBuildMu      sync.Mutex
	kernelDiscoveryMu sync.Mutex
	execMu            sync.Mutex
	execCancels       map[string]context.CancelFunc
}

type terminalKey struct {
	VMID      string
	User      string
	PublicKey string
	ExpiresAt time.Time
}

type TerminalSize struct {
	Rows int
	Cols int
}

type terminalControlMessage struct {
	Type string `json:"type"`
	Rows int    `json:"rows"`
	Cols int    `json:"cols"`
}

type terminalResizer interface {
	WindowChange(h, w int) error
}

type websocketMessageWriter interface {
	WriteMessage(messageType int, data []byte) error
}

type VMExecRequest struct {
	Command        string            `json:"command"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	CWD            string            `json:"cwd"`
	Env            map[string]string `json:"env"`
	Stdin          string            `json:"stdin"`
	PTY            bool              `json:"pty"`
}

type VMExecResult struct {
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	TimedOut   bool      `json:"timed_out"`
	Truncated  bool      `json:"truncated"`
}

type CreateRequest struct {
	Name                string
	VCPUCount           int
	MemMiB              int
	SSHPort             int
	DevUser             string
	SSHKeyID            string
	ExtraAuthorizedKeys string
	RepoURL             string
	GitRef              string
	EgressMode          string
	EgressPolicyID      string
	NetworkMode         string
	NetworkID           string
	BaseImageID         string
	RootFSSizeMiB       int
	KernelID            string
	AllowPendingKernel  bool
}

type HostStatus struct {
	Checks           map[string]string `json:"checks"`
	Orphans          HostOrphans       `json:"orphans"`
	NetworkConflicts []NetworkConflict `json:"network_conflicts"`
}

type ErrorCode string

const (
	CodeInvalid  ErrorCode = "invalid"
	CodeNotFound ErrorCode = "not_found"
	CodeConflict ErrorCode = "conflict"
	CodeUnusable ErrorCode = "unprocessable"
	CodeInternal ErrorCode = "internal"
)

type DomainError struct {
	Code    ErrorCode         `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

func (e *DomainError) Error() string {
	return e.Message
}

func Invalid(message string, fields map[string]string) error {
	return &DomainError{Code: CodeInvalid, Message: message, Fields: fields}
}

func NotFound(message string) error {
	return &DomainError{Code: CodeNotFound, Message: message}
}

func Conflict(message string) error {
	return &DomainError{Code: CodeConflict, Message: message}
}

func ConflictFields(message string, fields map[string]string) error {
	return &DomainError{Code: CodeConflict, Message: message, Fields: fields}
}

func Unprocessable(message string, fields map[string]string) error {
	return &DomainError{Code: CodeUnusable, Message: message, Fields: fields}
}

type HostOrphans struct {
	TAPs    []string `json:"taps"`
	Bridges []string `json:"bridges"`
}

type NetworkConflict struct {
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectName     string `json:"subject_name"`
	SubjectCIDR     string `json:"subject_cidr"`
	ConflictingType string `json:"conflicting_type"`
	ConflictingID   string `json:"conflicting_id"`
	ConflictingName string `json:"conflicting_name"`
	ConflictingCIDR string `json:"conflicting_cidr"`
	Message         string `json:"message"`
}

func New(cfg *config.Config, st *store.Store) *Service {
	return &Service{cfg: cfg, store: st, execCancels: map[string]context.CancelFunc{}}
}

func (s *Service) Reconcile(ctx context.Context) error {
	vms, err := s.store.ListVMs(ctx)
	if err != nil {
		return err
	}
	changed := false
	hasRunning := false
	for i := range vms {
		vm := &vms[i]
		if vm.State == model.VMRunning || vm.State == model.VMStarting || vm.State == model.VMStopping {
			hasRunning = true
			if !s.processRunning(ctx, vm) {
				now := time.Now().UTC()
				vm.State = model.VMStopped
				vm.LastStoppedAt = &now
				vm.UpdatedAt = now
				vm.LastError = "reconciled: Firecracker process not running"
				if err := s.cleanupVMRuntime(ctx, vm); err != nil {
					vm.LastError += "; cleanup: " + err.Error()
				}
				if err := s.store.UpdateVM(ctx, *vm); err != nil {
					return err
				}
				changed = true
			}
		}
	}
	if changed || hasRunning {
		return s.applyNFT(ctx)
	}
	return nil
}

func (s *Service) MigrateSSHAccess(ctx context.Context) error {
	vms, err := s.store.ListVMs(ctx)
	if err != nil {
		return err
	}
	for i := range vms {
		vm := &vms[i]
		if vm.SSHKeyID != "" && vm.ManagedSSHPublicKey == "" {
			key, err := s.store.GetSSHKey(ctx, vm.SSHKeyID)
			if err != nil {
				return err
			}
			if key != nil {
				vm.ManagedSSHPublicKey = key.PublicKey
				_ = s.store.UpdateVM(ctx, *vm)
			}
		}
		if vm.RootFSPath == "" {
			continue
		}
		if vm.ManagedSSHPrivateKeyPath != "" {
			if _, err := os.Stat(vm.ManagedSSHPrivateKeyPath); errors.Is(err, os.ErrNotExist) {
				vm.ManagedSSHPrivateKeyPath = ""
				_ = s.store.UpdateVM(ctx, *vm)
			}
		}
		if vm.State == model.VMRunning && s.processRunning(ctx, vm) {
			if vm.ManagedSSHPrivateKeyPath == "" {
				continue
			}
			if _, err := os.Stat(vm.ManagedSSHPrivateKeyPath); err != nil {
				continue
			}
			if err := s.installRunningSSHHelper(ctx, vm); err != nil {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			if err := s.verifyEphemeralSSH(ctx, vm); err != nil {
				continue
			}
			_ = os.Remove(vm.ManagedSSHPrivateKeyPath)
			_ = os.Remove(vm.ManagedSSHPrivateKeyPath + ".pub")
			vm.ManagedSSHPrivateKeyPath = ""
			_ = s.store.UpdateVM(ctx, *vm)
			continue
		}
		if vm.State == model.VMStopped || vm.State == model.VMError {
			if vm.ManagedSSHPrivateKeyPath == "" {
				continue
			}
			if err := s.prepareRootFS(ctx, vm); err != nil {
				continue
			}
			_ = os.Remove(vm.ManagedSSHPrivateKeyPath)
			_ = os.Remove(vm.ManagedSSHPrivateKeyPath + ".pub")
			vm.ManagedSSHPrivateKeyPath = ""
			_ = s.store.UpdateVM(ctx, *vm)
		}
	}
	return nil
}

func (s *Service) installRunningSSHHelper(ctx context.Context, vm *model.VM) error {
	client, err := s.legacySSHClient(vm)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	vmEnv := fmt.Sprintf("VM_ID=%s\nDEV_USER=%s\nBAP_WEB_AUTHORIZED_KEYS_URL=http://%s:%d/metadata/v1/authorized-keys\n",
		shellEnv(vm.ID), shellEnv(vm.DevUser), shellEnv(vm.HostIP), s.cfg.Server.MetadataPort)
	cmd := fmt.Sprintf(`set -euo pipefail
sudo install -d -m 0755 /etc/bap-web /usr/local/sbin /etc/ssh/sshd_config.d
printf %%s %q | base64 -d | sudo tee /etc/bap-web/vm.env >/dev/null
printf %%s %q | base64 -d | sudo tee /usr/local/sbin/bap-web-authorized-keys >/dev/null
printf %%s %q | base64 -d | sudo tee /etc/ssh/sshd_config.d/90-bap-web-authorized-keys.conf >/dev/null
sudo chmod 0644 /etc/bap-web/vm.env /etc/ssh/sshd_config.d/90-bap-web-authorized-keys.conf
sudo chmod 0755 /usr/local/sbin/bap-web-authorized-keys
sudo grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config || printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo systemctl reload sshd || sudo systemctl restart sshd
`,
		base64.StdEncoding.EncodeToString([]byte(vmEnv)),
		base64.StdEncoding.EncodeToString([]byte(authorizedKeysScript())),
		base64.StdEncoding.EncodeToString([]byte(authorizedKeysDropIn())),
	)
	session.Stdin = strings.NewReader(cmd)
	out, err := session.CombinedOutput("bash -s")
	if err != nil {
		return fmt.Errorf("install authorized keys helper: %w: %s", err, string(out))
	}
	return nil
}

func (s *Service) processRunning(ctx context.Context, vm *model.VM) bool {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", fmt.Sprintf("firecracker.*--id.*%s", vm.Name))
	return cmd.Run() == nil
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}$`)

const maxLinuxIFNameLen = 15

func tapNameForID(id string) string {
	const prefix = "tap-"
	suffixLen := maxLinuxIFNameLen - len(prefix)
	if len(id) > suffixLen {
		id = id[:suffixLen]
	}
	return prefix + id
}

func validIFName(name string) bool {
	return len(name) > 0 && len(name) <= maxLinuxIFNameLen && !strings.ContainsAny(name, "/ \t\n\r")
}

func (s *Service) ensureTapName(ctx context.Context, vm *model.VM) error {
	if validIFName(vm.TapName) {
		return nil
	}
	if vm.State == model.VMRunning || vm.State == model.VMStarting {
		return fmt.Errorf("running VM has invalid tap_name %q", vm.TapName)
	}
	vm.TapName = tapNameForID(vm.ID)
	return s.store.UpdateVM(ctx, *vm)
}

func (s *Service) CreateVM(ctx context.Context, req CreateRequest) (*model.VM, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !nameRe.MatchString(req.Name) {
		return nil, Invalid("VM name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	if req.VCPUCount <= 0 || req.VCPUCount > 32 {
		return nil, Invalid("VM resource request is invalid", map[string]string{"vcpu_count": "must be between 1 and 32"})
	}
	if req.MemMiB < 128 || req.MemMiB > 262144 {
		return nil, Invalid("VM resource request is invalid", map[string]string{"mem_mib": "must be between 128 and 262144"})
	}
	if req.DevUser == "" {
		req.DevUser = "dev"
	}
	if req.GitRef == "" {
		req.GitRef = "HEAD"
	}
	if req.EgressMode == "" {
		req.EgressMode = "allow_all"
	}
	if req.NetworkMode == "" {
		req.NetworkMode = s.cfg.Network.DefaultNetworkMode
	}
	if req.NetworkMode != "routed_ptp" && req.NetworkMode != "shared_bridge" {
		return nil, Invalid("Network mode is invalid", map[string]string{"network_mode": "must be routed_ptp or shared_bridge"})
	}
	if req.EgressPolicyID != "" {
		policy, err := s.store.GetEgressPolicy(ctx, req.EgressPolicyID)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			return nil, NotFound("egress_policy_id does not exist")
		}
		req.EgressMode = policy.Mode
	} else if req.EgressMode != "allow_all" && req.EgressMode != "deny_all" {
		return nil, Invalid("Egress mode is invalid", map[string]string{"egress_mode": "must be allow_all or deny_all unless egress_policy_id is set"})
	}
	if existing, err := s.store.GetVMByName(ctx, req.Name); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, Conflict("VM name already exists")
	}
	kernel, err := s.resolveKernelForVM(ctx, req.KernelID, req.AllowPendingKernel)
	if err != nil {
		return nil, err
	}
	baseImage, rootfsSizeMiB, err := s.resolveBaseImageForVM(ctx, req.BaseImageID, req.RootFSSizeMiB)
	if err != nil {
		return nil, err
	}
	var primaryKey string
	if req.SSHKeyID != "" {
		key, err := s.store.GetSSHKey(ctx, req.SSHKeyID)
		if err != nil {
			return nil, err
		}
		if key == nil {
			return nil, NotFound("ssh_key_id does not exist")
		}
		primaryKey = key.PublicKey
	} else if strings.TrimSpace(req.ExtraAuthorizedKeys) == "" {
		return nil, Unprocessable("Select an SSH key or paste at least one authorized public key.", map[string]string{
			"ssh_key_id":            "select a reusable SSH key or leave blank only when extra_authorized_keys is set",
			"extra_authorized_keys": "required when no SSH key is selected",
		})
	}

	port, err := s.allocatePort(ctx, req.SSHPort)
	if err != nil {
		return nil, err
	}

	id := random.Hex(8)
	hostIP, guestIP, cidr, err := s.allocateNetwork(ctx, req.NetworkMode, req.NetworkID)
	if err != nil {
		return nil, err
	}
	rootfsExt := "ext4"
	if baseImage.Filesystem == "xfs" {
		rootfsExt = "xfs"
	}
	rootfsPath := filepath.Join(s.cfg.Paths.ImageDir, req.Name, "rootfs."+rootfsExt)
	now := time.Now().UTC()
	vm := model.VM{
		ID:                       id,
		Name:                     req.Name,
		State:                    model.VMStopped,
		VCPUCount:                req.VCPUCount,
		MemMiB:                   req.MemMiB,
		SSHPort:                  port,
		TapName:                  tapNameForID(id),
		HostIP:                   hostIP,
		GuestIP:                  guestIP,
		CIDR:                     cidr,
		KernelPath:               kernel.Path,
		KernelID:                 kernel.ID,
		RootFSPath:               rootfsPath,
		BaseRootFSPath:           baseImage.Path,
		BaseImageID:              baseImage.ID,
		RootFSSizeMiB:            rootfsSizeMiB,
		DevUser:                  req.DevUser,
		SSHKeyID:                 req.SSHKeyID,
		ManagedSSHPublicKey:      primaryKey,
		ManagedSSHPrivateKeyPath: "",
		ExtraAuthorizedKeys:      strings.TrimSpace(req.ExtraAuthorizedKeys),
		RepoURL:                  strings.TrimSpace(req.RepoURL),
		GitRef:                   req.GitRef,
		EgressMode:               req.EgressMode,
		EgressPolicyID:           req.EgressPolicyID,
		NetworkMode:              req.NetworkMode,
		NetworkID:                req.NetworkID,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
	if err := s.prepareRootFS(ctx, &vm); err != nil {
		return nil, err
	}
	if err := s.store.CreateVM(ctx, vm); err != nil {
		return nil, err
	}
	if req.SSHKeyID != "" {
		_ = s.store.TouchSSHKey(ctx, req.SSHKeyID)
	}
	return &vm, nil
}

func (s *Service) StartVM(ctx context.Context, id string) error {
	vm, err := s.store.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vm == nil {
		return NotFound("VM not found")
	}
	if err := s.ensureTapName(ctx, vm); err != nil {
		return err
	}
	if err := s.ensureVMNetworkUsable(ctx, vm); err != nil {
		return err
	}
	if vm.State == model.VMRunning && s.processRunning(ctx, vm) {
		return nil
	}
	now := time.Now().UTC()
	vm.State = model.VMStarting
	vm.LastError = ""
	vm.UpdatedAt = now
	if err := s.store.UpdateVM(ctx, *vm); err != nil {
		return err
	}
	if err := s.setupTap(ctx, vm); err != nil {
		return s.failVM(ctx, vm, err)
	}
	if err := s.applyNFT(ctx); err != nil {
		return s.failVM(ctx, vm, err)
	}
	if err := s.startFirecracker(ctx, vm); err != nil {
		return s.failVM(ctx, vm, err)
	}
	vm.State = model.VMRunning
	vm.LastStartedAt = &now
	vm.UpdatedAt = time.Now().UTC()
	return s.store.UpdateVM(ctx, *vm)
}

func (s *Service) StopVM(ctx context.Context, id string) error {
	vm, err := s.store.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vm == nil {
		return NotFound("VM not found")
	}
	vm.State = model.VMStopping
	_ = s.store.UpdateVM(ctx, *vm)
	_ = s.firecrackerAction(ctx, vm, map[string]string{"action_type": "SendCtrlAltDel"})
	time.Sleep(2 * time.Second)
	_ = run(ctx, "pkill", "-9", "-f", fmt.Sprintf("firecracker.*--id.*%s", vm.Name))
	_ = run(ctx, "pkill", "-9", "-f", fmt.Sprintf("jailer.*--id.*%s", vm.Name))
	cleanupErr := s.cleanupVMRuntime(ctx, vm)
	now := time.Now().UTC()
	vm.State = model.VMStopped
	vm.LastStoppedAt = &now
	vm.UpdatedAt = now
	vm.LastError = lifecycleErrorString(cleanupErr)
	if err := s.store.UpdateVM(ctx, *vm); err != nil {
		return err
	}
	if err := s.applyNFT(ctx); err != nil {
		return err
	}
	return cleanupErr
}

func (s *Service) DeleteVM(ctx context.Context, id string) error {
	vm, err := s.store.GetVM(ctx, id)
	if err != nil {
		return err
	}
	if vm == nil {
		return NotFound("VM not found")
	}
	if err := s.StopVM(ctx, id); err != nil {
		return err
	}
	if vm.RootFSPath != "" {
		_ = os.Remove(vm.RootFSPath)
		_ = os.Remove(filepath.Dir(vm.RootFSPath))
	}
	if vm.ManagedSSHPrivateKeyPath != "" {
		_ = os.Remove(vm.ManagedSSHPrivateKeyPath)
		_ = os.Remove(vm.ManagedSSHPrivateKeyPath + ".pub")
	}
	return s.store.DeleteVM(ctx, id)
}

func (s *Service) cleanupVMRuntime(ctx context.Context, vm *model.VM) error {
	var errs []string
	chrootRoot := s.chrootRoot(vm)
	ignore := func(label string, err error) {
		if cleanupOK(err) {
			return
		}
		errs = append(errs, label+": "+err.Error())
	}
	ignore("unmount kernels", run(ctx, "umount", filepath.Join(chrootRoot, "var/lib/microvms/kernels")))
	ignore("unmount rootfs", run(ctx, "umount", filepath.Join(chrootRoot, "var/lib/microvms", vm.Name)))
	if err := os.RemoveAll(filepath.Join(s.cfg.Paths.JailerBaseDir, "firecracker", vm.Name)); err != nil {
		errs = append(errs, "remove jailer dir: "+err.Error())
	}
	if vm.TapName != "" {
		ignore("cleanup tap", cleanupTap(ctx, vm.TapName))
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Service) RestartVM(ctx context.Context, id string, vcpuCount, memMiB int) (*model.VM, error) {
	if vcpuCount > 0 || memMiB > 0 {
		vm, err := s.UpdateResources(ctx, id, vcpuCount, memMiB, true)
		if err != nil {
			return nil, err
		}
		if vm != nil && vm.State == model.VMRunning {
			return vm, nil
		}
	}
	if err := s.StopVM(ctx, id); err != nil {
		return nil, err
	}
	if err := s.StartVM(ctx, id); err != nil {
		return nil, err
	}
	return s.store.GetVM(ctx, id)
}

func (s *Service) UpdateResources(ctx context.Context, id string, vcpuCount, memMiB int, restart bool) (*model.VM, error) {
	vm, err := s.store.GetVM(ctx, id)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, NotFound("VM not found")
	}
	if vcpuCount <= 0 {
		vcpuCount = vm.VCPUCount
	}
	if memMiB <= 0 {
		memMiB = vm.MemMiB
	}
	if vcpuCount <= 0 || vcpuCount > 32 {
		return nil, Invalid("VM resource request is invalid", map[string]string{"vcpu_count": "must be between 1 and 32"})
	}
	if memMiB < 128 || memMiB > 262144 {
		return nil, Invalid("VM resource request is invalid", map[string]string{"mem_mib": "must be between 128 and 262144"})
	}
	running := vm.State == model.VMRunning || vm.State == model.VMStarting
	if running && !restart {
		return nil, Unprocessable("VM must be stopped to update resources, or restart must be true", map[string]string{"restart": "select restart to update a running VM"})
	}
	if running {
		if err := s.StopVM(ctx, id); err != nil {
			return nil, err
		}
		vm, err = s.store.GetVM(ctx, id)
		if err != nil {
			return nil, err
		}
		if vm == nil {
			return nil, NotFound("VM not found")
		}
	}
	vm.VCPUCount = vcpuCount
	vm.MemMiB = memMiB
	if err := s.store.UpdateVM(ctx, *vm); err != nil {
		return nil, err
	}
	if running {
		if err := s.StartVM(ctx, id); err != nil {
			return nil, err
		}
	}
	return s.store.GetVM(ctx, id)
}

func (s *Service) CreateNetwork(ctx context.Context, name, cidr, gatewayIP string) (*model.Network, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return nil, Invalid("Network name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	normalizedCIDR, normalizedGateway, err := s.validateSharedNetwork(ctx, cidr, gatewayIP)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	network := model.Network{
		ID:        random.Hex(8),
		Name:      name,
		CIDR:      normalizedCIDR,
		GatewayIP: normalizedGateway,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateNetwork(ctx, network); err != nil {
		return nil, err
	}
	return &network, nil
}

func (s *Service) DeleteNetwork(ctx context.Context, id string) error {
	network, err := s.store.GetNetwork(ctx, id)
	if err != nil {
		return err
	}
	if network == nil {
		return NotFound("network not found")
	}
	if err := s.store.DeleteNetwork(ctx, id); err != nil {
		return err
	}
	return cleanupBridge(ctx, bridgeName(network.ID))
}

func (s *Service) CreateEgressPolicy(ctx context.Context, name, mode, tcpPorts, udpPorts, cidrs string) (*model.EgressPolicy, error) {
	name = strings.TrimSpace(name)
	if !nameRe.MatchString(name) {
		return nil, Invalid("Egress policy name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	mode = strings.TrimSpace(mode)
	tcpPorts, udpPorts, cidrs, err := validateEgressPolicy(mode, tcpPorts, udpPorts, cidrs)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	policy := model.EgressPolicy{
		ID:        random.Hex(8),
		Name:      name,
		Mode:      mode,
		TCPPorts:  tcpPorts,
		UDPPorts:  udpPorts,
		CIDRs:     cidrs,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreateEgressPolicy(ctx, policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (s *Service) DeleteEgressPolicy(ctx context.Context, id string) error {
	return s.store.DeleteEgressPolicy(ctx, id)
}

func (s *Service) SetVMEgressPolicy(ctx context.Context, id, mode, policyID string) (*model.VM, error) {
	vm, err := s.store.GetVM(ctx, id)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, NotFound("VM not found")
	}
	mode = strings.TrimSpace(mode)
	if policyID != "" {
		policy, err := s.store.GetEgressPolicy(ctx, policyID)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			return nil, NotFound("egress policy not found")
		}
		vm.EgressMode = policy.Mode
		vm.EgressPolicyID = policy.ID
	} else {
		if mode == "" {
			mode = "allow_all"
		}
		if mode != "allow_all" && mode != "deny_all" {
			return nil, Invalid("Egress mode is invalid", map[string]string{"egress_mode": "must be allow_all or deny_all when no policy is selected"})
		}
		vm.EgressMode = mode
		vm.EgressPolicyID = ""
	}
	if err := s.store.UpdateVM(ctx, *vm); err != nil {
		return nil, err
	}
	if vm.State == model.VMRunning || vm.State == model.VMStarting {
		if err := s.applyNFT(ctx); err != nil {
			return nil, err
		}
	}
	return s.store.GetVM(ctx, id)
}

func (s *Service) AddIngressRule(ctx context.Context, vmID, protocol string, hostPort, guestPort int, description string) (*model.IngressRule, error) {
	vm, err := s.store.GetVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, NotFound("VM not found")
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" {
		return nil, Invalid("Ingress rule is invalid", map[string]string{"protocol": "must be tcp or udp"})
	}
	if hostPort < 1 || hostPort > 65535 || guestPort < 1 || guestPort > 65535 {
		return nil, Invalid("Ingress rule is invalid", map[string]string{"host_port": "must be between 1 and 65535", "guest_port": "must be between 1 and 65535"})
	}
	sshPorts, err := s.store.UsedSSHPorts(ctx)
	if err != nil {
		return nil, err
	}
	if sshPorts[hostPort] || portOpen(hostPort) {
		return nil, Conflict("host_port already in use")
	}
	rule := model.IngressRule{
		ID:          random.Hex(8),
		VMID:        vm.ID,
		Protocol:    protocol,
		HostPort:    hostPort,
		GuestPort:   guestPort,
		Description: strings.TrimSpace(description),
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.CreateIngressRule(ctx, rule); err != nil {
		return nil, err
	}
	if vm.State == model.VMRunning || vm.State == model.VMStarting {
		if err := s.applyNFT(ctx); err != nil {
			return nil, err
		}
	}
	return &rule, nil
}

func (s *Service) DeleteIngressRule(ctx context.Context, vmID, ruleID string) error {
	vm, err := s.store.GetVM(ctx, vmID)
	if err != nil {
		return err
	}
	if vm == nil {
		return NotFound("VM not found")
	}
	if err := s.store.DeleteIngressRule(ctx, vmID, ruleID); err != nil {
		return err
	}
	if vm.State == model.VMRunning || vm.State == model.VMStarting {
		return s.applyNFT(ctx)
	}
	return nil
}

func (s *Service) VMLogs(ctx context.Context, vm *model.VM, lines int) (string, []string, error) {
	if lines <= 0 || lines > 2000 {
		lines = 300
	}
	path := filepath.Join(s.cfg.Paths.LogDir, vm.Name+".log")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, nil, nil
		}
		return path, nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := make([]string, 0, lines)
	for scanner.Scan() {
		if len(out) == lines {
			copy(out, out[1:])
			out[len(out)-1] = scanner.Text()
		} else {
			out = append(out, scanner.Text())
		}
	}
	return path, out, scanner.Err()
}

func (s *Service) HostStatus(ctx context.Context) HostStatus {
	checks := map[string]string{}
	check := func(name string, err error) {
		if err != nil {
			checks[name] = err.Error()
		} else {
			checks[name] = "ok"
		}
	}
	check("kvm", requireFile("/dev/kvm"))
	check("firecracker", requireExecutable(s.cfg.Paths.FirecrackerBin))
	check("jailer", requireExecutable(s.cfg.Paths.JailerBin))
	if kernel, err := s.store.DefaultKernel(ctx); err != nil {
		check("kernel", err)
	} else if kernel == nil {
		check("kernel", fmt.Errorf("no active kernel"))
	} else {
		check("kernel", requireFile(kernel.Path))
	}
	check("base_rootfs", requireFile(s.cfg.Paths.BaseRootFS))
	check("ip_forward", commandOK(ctx, "sysctl", "net.ipv4.ip_forward"))
	check("nftables", commandOK(ctx, "nft", "list", "ruleset"))
	orphans, err := s.HostOrphans(ctx)
	if err != nil {
		checks["orphan_scan"] = err.Error()
	}
	if len(orphans.TAPs) > 0 || len(orphans.Bridges) > 0 {
		checks["network_orphans"] = fmt.Sprintf("%d TAP(s), %d bridge(s)", len(orphans.TAPs), len(orphans.Bridges))
	}
	conflicts, err := s.NetworkConflicts(ctx)
	if err != nil {
		checks["network_conflicts"] = err.Error()
	} else if len(conflicts) > 0 {
		checks["network_conflicts"] = fmt.Sprintf("%d conflict(s)", len(conflicts))
	}
	return HostStatus{Checks: checks, Orphans: orphans, NetworkConflicts: conflicts}
}

func (s *Service) HostOrphans(ctx context.Context) (HostOrphans, error) {
	vms, err := s.store.ListVMs(ctx)
	if err != nil {
		return HostOrphans{}, err
	}
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return HostOrphans{}, err
	}
	activeTAPs := map[string]bool{}
	for _, vm := range vms {
		if (vm.State == model.VMRunning || vm.State == model.VMStarting) && vm.TapName != "" {
			activeTAPs[vm.TapName] = true
		}
	}
	activeBridges := map[string]bool{}
	for _, network := range networks {
		activeBridges[bridgeName(network.ID)] = true
	}
	links, err := hostLinks(ctx)
	if err != nil {
		return HostOrphans{}, err
	}
	out := HostOrphans{TAPs: []string{}, Bridges: []string{}}
	for _, link := range links {
		if strings.HasPrefix(link, "tap-") && !activeTAPs[link] {
			out.TAPs = append(out.TAPs, link)
		}
		if strings.HasPrefix(link, "br-bap-") && !activeBridges[link] {
			out.Bridges = append(out.Bridges, link)
		}
	}
	return out, nil
}

func (s *Service) CleanupHostOrphans(ctx context.Context) (HostOrphans, error) {
	orphans, err := s.HostOrphans(ctx)
	if err != nil {
		return HostOrphans{}, err
	}
	var errs []string
	for _, tap := range orphans.TAPs {
		if err := cleanupTap(ctx, tap); !cleanupOK(err) {
			errs = append(errs, tap+": "+err.Error())
		}
	}
	for _, bridge := range orphans.Bridges {
		if err := cleanupBridge(ctx, bridge); !cleanupOK(err) {
			errs = append(errs, bridge+": "+err.Error())
		}
	}
	if err := s.applyNFT(ctx); err != nil {
		errs = append(errs, "apply nftables: "+err.Error())
	}
	if len(errs) > 0 {
		return orphans, errors.New(strings.Join(errs, "; "))
	}
	return orphans, nil
}

type networkCIDROwner struct {
	kind  string
	id    string
	name  string
	cidr  string
	ipnet *net.IPNet
}

func (o networkCIDROwner) displayName() string {
	if o.name != "" {
		return o.kind + " " + o.name
	}
	if o.id != "" {
		return o.kind + " " + o.id
	}
	return o.kind
}

func (s *Service) NetworkConflicts(ctx context.Context) ([]NetworkConflict, error) {
	owners, err := s.networkCIDROwners(ctx)
	if err != nil {
		return nil, err
	}
	conflicts := []NetworkConflict{}
	for i := 0; i < len(owners); i++ {
		for j := i + 1; j < len(owners); j++ {
			if cidrOverlaps(owners[i].ipnet, owners[j].ipnet) {
				conflicts = append(conflicts, networkConflict(owners[i], owners[j]))
			}
		}
	}
	return conflicts, nil
}

func (s *Service) networkCIDROwners(ctx context.Context) ([]networkCIDROwner, error) {
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	vms, err := s.store.ListVMs(ctx)
	if err != nil {
		return nil, err
	}
	owners := []networkCIDROwner{}
	for _, network := range networks {
		_, ipnet, err := net.ParseCIDR(network.CIDR)
		if err != nil {
			continue
		}
		owners = append(owners, networkCIDROwner{
			kind:  "network",
			id:    network.ID,
			name:  network.Name,
			cidr:  ipnet.String(),
			ipnet: ipnet,
		})
	}
	for _, vm := range vms {
		ipnet, cidr, ok := vmRoutedCIDR(vm)
		if !ok {
			continue
		}
		owners = append(owners, networkCIDROwner{
			kind:  "VM",
			id:    vm.ID,
			name:  vm.Name,
			cidr:  cidr,
			ipnet: ipnet,
		})
	}
	return owners, nil
}

func (s *Service) findCIDROverlap(ctx context.Context, candidate *net.IPNet, ignoreID string) (*NetworkConflict, error) {
	owners, err := s.networkCIDROwners(ctx)
	if err != nil {
		return nil, err
	}
	candidateOwner := networkCIDROwner{kind: "CIDR", cidr: candidate.String(), ipnet: candidate}
	for _, owner := range owners {
		if owner.id != "" && owner.id == ignoreID {
			continue
		}
		if cidrOverlaps(candidate, owner.ipnet) {
			conflict := networkConflict(owner, candidateOwner)
			return &conflict, nil
		}
	}
	return nil, nil
}

func (s *Service) sharedNetworkCIDRs(ctx context.Context) ([]*net.IPNet, error) {
	networks, err := s.store.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	out := []*net.IPNet{}
	for _, network := range networks {
		_, existing, err := net.ParseCIDR(network.CIDR)
		if err != nil {
			continue
		}
		out = append(out, existing)
	}
	return out, nil
}

func (s *Service) ensureVMNetworkUsable(ctx context.Context, vm *model.VM) error {
	switch vm.NetworkMode {
	case "shared_bridge":
		network, err := s.store.GetNetwork(ctx, vm.NetworkID)
		if err != nil {
			return err
		}
		if network == nil {
			return NotFound("network_id does not exist")
		}
		return s.ensureSharedNetworkUsable(ctx, network)
	case "routed_ptp", "":
		ipnet, cidr, ok := vmRoutedCIDR(*vm)
		if !ok {
			return nil
		}
		conflict, err := s.findCIDROverlap(ctx, ipnet, vm.ID)
		if err != nil {
			return err
		}
		if conflict != nil {
			return conflictError(fmt.Sprintf("VM network %s overlaps %s %s", cidr, conflict.SubjectName, conflict.SubjectCIDR), "network")
		}
	}
	return nil
}

func (s *Service) ensureSharedNetworkUsable(ctx context.Context, network *model.Network) error {
	_, ipnet, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		return Invalid("Shared network CIDR is invalid", map[string]string{"cidr": err.Error()})
	}
	conflict, err := s.findCIDROverlap(ctx, ipnet, network.ID)
	if err != nil {
		return err
	}
	if conflict == nil {
		return nil
	}
	return ConflictFields(
		fmt.Sprintf("Shared network %s is unusable because %s overlaps %s %s", network.Name, network.CIDR, conflict.SubjectName, conflict.SubjectCIDR),
		map[string]string{
			"network_id": "select a non-overlapping shared network",
			"cidr":       "overlaps " + conflict.SubjectName + " " + conflict.SubjectCIDR,
		},
	)
}

func networkConflict(a, b networkCIDROwner) NetworkConflict {
	return NetworkConflict{
		SubjectType:     a.kind,
		SubjectID:       a.id,
		SubjectName:     a.displayName(),
		SubjectCIDR:     a.cidr,
		ConflictingType: b.kind,
		ConflictingID:   b.id,
		ConflictingName: b.displayName(),
		ConflictingCIDR: b.cidr,
		Message:         fmt.Sprintf("%s %s overlaps %s %s", a.displayName(), a.cidr, b.displayName(), b.cidr),
	}
}

func conflictError(message, field string) error {
	fields := map[string]string{}
	if field != "" {
		fields[field] = message
	}
	return ConflictFields(message, fields)
}

func vmRoutedCIDR(vm model.VM) (*net.IPNet, string, bool) {
	if vm.NetworkMode != "" && vm.NetworkMode != "routed_ptp" {
		return nil, "", false
	}
	if vm.HostIP == "" || vm.CIDR <= 0 || vm.CIDR > 32 {
		return nil, "", false
	}
	ip := net.ParseIP(vm.HostIP).To4()
	if ip == nil {
		return nil, "", false
	}
	ipnet := &net.IPNet{IP: ip.Mask(net.CIDRMask(vm.CIDR, 32)), Mask: net.CIDRMask(vm.CIDR, 32)}
	return ipnet, ipnet.String(), true
}

func cidrOverlaps(a, b *net.IPNet) bool {
	aStart, aEnd, ok := ipNetRange(a)
	if !ok {
		return false
	}
	bStart, bEnd, ok := ipNetRange(b)
	if !ok {
		return false
	}
	return aStart <= bEnd && bStart <= aEnd
}

func cidrOverlapsAny(candidate *net.IPNet, existing []*net.IPNet) bool {
	for _, ipnet := range existing {
		if cidrOverlaps(candidate, ipnet) {
			return true
		}
	}
	return false
}

func ipNetRange(ipnet *net.IPNet) (uint64, uint64, bool) {
	if ipnet == nil {
		return 0, 0, false
	}
	ip := ipnet.IP.To4()
	ones, bits := ipnet.Mask.Size()
	if ip == nil || bits != 32 || ones < 0 {
		return 0, 0, false
	}
	start := uint64(ipToUint32(ip))
	size := uint64(1) << uint(32-ones)
	return start, start + size - 1, true
}

func (s *Service) failVM(ctx context.Context, vm *model.VM, err error) error {
	vm.State = model.VMError
	vm.LastError = err.Error()
	vm.UpdatedAt = time.Now().UTC()
	_ = s.store.UpdateVM(ctx, *vm)
	return err
}

func (s *Service) allocatePort(ctx context.Context, requested int) (int, error) {
	start, end, err := parseRange(s.cfg.Network.SSHPortRange)
	if err != nil {
		return 0, err
	}
	used, err := s.store.UsedSSHPorts(ctx)
	if err != nil {
		return 0, err
	}
	ingress, err := s.store.UsedIngressHostPorts(ctx)
	if err != nil {
		return 0, err
	}
	for p := range ingress {
		used[p] = true
	}
	if requested != 0 {
		if requested < start || requested > end {
			return 0, Invalid("SSH port is outside the configured range", map[string]string{"ssh_port": fmt.Sprintf("must be between %d and %d", start, end)})
		}
		if used[requested] || portOpen(requested) {
			return 0, Conflict("ssh_port already in use")
		}
		return requested, nil
	}
	for p := start; p <= end; p++ {
		if !used[p] && !portOpen(p) {
			return p, nil
		}
	}
	return 0, Conflict("no free SSH ports in range")
}

func (s *Service) allocateNetwork(ctx context.Context, mode, networkID string) (string, string, int, error) {
	switch mode {
	case "routed_ptp":
		return s.allocateP2P(ctx)
	case "shared_bridge":
		if networkID == "" {
			return "", "", 0, Unprocessable("Select a shared network when using shared_bridge mode.", map[string]string{"network_id": "required for shared_bridge"})
		}
		network, err := s.store.GetNetwork(ctx, networkID)
		if err != nil {
			return "", "", 0, err
		}
		if network == nil {
			return "", "", 0, NotFound("network_id does not exist")
		}
		if err := s.ensureSharedNetworkUsable(ctx, network); err != nil {
			return "", "", 0, err
		}
		host, guest, cidr, err := s.allocateShared(ctx, network)
		if err != nil {
			return "", "", 0, err
		}
		return host, guest, cidr, nil
	default:
		return "", "", 0, fmt.Errorf("unsupported network mode %q", mode)
	}
}

func (s *Service) allocateP2P(ctx context.Context) (string, string, int, error) {
	used, err := s.store.UsedGuestIPs(ctx)
	if err != nil {
		return "", "", 0, err
	}
	_, network, err := net.ParseCIDR(s.cfg.Network.VMCIDR)
	if err != nil {
		return "", "", 0, err
	}
	base := network.IP.To4()
	ones, bits := network.Mask.Size()
	if base == nil || bits != 32 || ones > 30 {
		return "", "", 0, fmt.Errorf("vm_cidr must be an IPv4 CIDR with room for /30 networks")
	}
	sharedCIDRs, err := s.sharedNetworkCIDRs(ctx)
	if err != nil {
		return "", "", 0, err
	}
	start := ipToUint32(base)
	size := uint32(1) << uint32(32-ones)
	for offset := uint32(0); offset+3 < size; offset += 4 {
		host := uint32ToIP(start + offset + 1).String()
		guest := uint32ToIP(start + offset + 2).String()
		ipnet := &net.IPNet{IP: uint32ToIP(start + offset), Mask: net.CIDRMask(30, 32)}
		if !used[guest] && !cidrOverlapsAny(ipnet, sharedCIDRs) {
			return host, guest, 30, nil
		}
	}
	return "", "", 0, fmt.Errorf("no free /30 networks")
}

func (s *Service) allocateShared(ctx context.Context, network *model.Network) (string, string, int, error) {
	used, err := s.store.UsedGuestIPs(ctx)
	if err != nil {
		return "", "", 0, err
	}
	_, ipnet, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		return "", "", 0, err
	}
	base := ipnet.IP.To4()
	ones, bits := ipnet.Mask.Size()
	if base == nil || bits != 32 || ones > 30 {
		return "", "", 0, fmt.Errorf("shared network must be an IPv4 CIDR larger than /30")
	}
	gateway := net.ParseIP(network.GatewayIP).To4()
	if gateway == nil || !ipnet.Contains(gateway) {
		return "", "", 0, fmt.Errorf("network gateway_ip is invalid")
	}
	start := ipToUint32(base)
	size := uint32(1) << uint32(32-ones)
	gatewayString := gateway.String()
	for offset := uint32(1); offset+1 < size; offset++ {
		guest := uint32ToIP(start + offset).String()
		if guest != gatewayString && !used[guest] {
			return gatewayString, guest, ones, nil
		}
	}
	return "", "", 0, fmt.Errorf("no free IPs in shared network")
}

func (s *Service) generateKey(path string) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
		if err := run(context.Background(), "ssh-keygen", "-t", "ed25519", "-N", "", "-f", path, "-C", "bap-web-managed"); err != nil {
			return "", err
		}
		_ = os.Chmod(path, 0o600)
	}
	b, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Service) prepareRootFS(ctx context.Context, vm *model.VM) error {
	if err := s.prepareRootFSImage(ctx, vm); err != nil {
		return err
	}
	mountRoot := filepath.Join("/mnt", "bap-web-"+vm.ID)
	if err := os.MkdirAll(mountRoot, 0o755); err != nil {
		return err
	}
	mounted := false
	defer func() {
		if mounted {
			_ = run(context.Background(), "umount", filepath.Join(mountRoot, "dev"))
			_ = run(context.Background(), "umount", mountRoot)
		}
		_ = os.RemoveAll(mountRoot)
	}()
	if err := run(ctx, "mount", "-o", "loop", vm.RootFSPath, mountRoot); err != nil {
		return err
	}
	mounted = true
	if err := s.resizeMountedRootFS(ctx, vm, mountRoot); err != nil {
		return err
	}
	if err := writeGuestFiles(mountRoot, vm, s.cfg.Server.MetadataPort); err != nil {
		return err
	}
	if err := run(ctx, "mount", "--bind", "/dev", filepath.Join(mountRoot, "dev")); err != nil {
		return err
	}
	_ = run(ctx, "chroot", mountRoot, "chown", "-R", vm.DevUser+":"+vm.DevUser, "/home/"+vm.DevUser+"/.ssh")
	_ = run(ctx, "umount", filepath.Join(mountRoot, "dev"))
	if err := run(ctx, "umount", mountRoot); err != nil {
		return err
	}
	mounted = false
	return nil
}

func writeGuestFiles(root string, vm *model.VM, metadataPort int) error {
	env := fmt.Sprintf("DEV_USER='%s'\nPROJECT='%s'\nWORK_DIR=/work\nREPO_URL='%s'\nGIT_REF='%s'\nDEV_SSH_KEY='%s'\n",
		shellQuote(vm.DevUser), shellQuote(vm.Name), shellQuote(vm.RepoURL), shellQuote(vm.GitRef), shellQuote(strings.TrimSpace(vm.ManagedSSHPublicKey+"\n"+vm.ExtraAuthorizedKeys)))
	if err := os.WriteFile(filepath.Join(root, "etc/project.env"), []byte(env), 0o644); err != nil {
		return err
	}
	if err := writeGuestSSHKeySupport(root, vm, metadataPort); err != nil {
		return err
	}
	nm := fmt.Sprintf(`[connection]
id=eth0
type=ethernet
interface-name=eth0

[ipv4]
method=manual
addresses=%s/%d
gateway=%s
dns=1.1.1.1;

[ipv6]
method=disabled
`, vm.GuestIP, vm.CIDR, vm.HostIP)
	nmPath := filepath.Join(root, "etc/NetworkManager/system-connections/eth0.nmconnection")
	if err := os.MkdirAll(filepath.Dir(nmPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(nmPath, []byte(nm), 0o600); err != nil {
		return err
	}
	sshDir := filepath.Join(root, "home", vm.DevUser, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	keys := strings.TrimSpace(vm.ManagedSSHPublicKey + "\n" + vm.ExtraAuthorizedKeys)
	if keys != "" {
		if err := os.WriteFile(filepath.Join(sshDir, "authorized_keys"), []byte(keys+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeGuestSSHKeySupport(root string, vm *model.VM, metadataPort int) error {
	if err := os.MkdirAll(filepath.Join(root, "etc/bap-web"), 0o755); err != nil {
		return err
	}
	env := fmt.Sprintf("VM_ID=%s\nDEV_USER=%s\nBAP_WEB_AUTHORIZED_KEYS_URL=http://%s:%d/metadata/v1/authorized-keys\n",
		shellEnv(vm.ID), shellEnv(vm.DevUser), shellEnv(vm.HostIP), metadataPort)
	if err := os.WriteFile(filepath.Join(root, "etc/bap-web/vm.env"), []byte(env), 0o644); err != nil {
		return err
	}
	scriptPath := filepath.Join(root, "usr/local/sbin/bap-web-authorized-keys")
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(scriptPath, []byte(authorizedKeysScript()), 0o755); err != nil {
		return err
	}
	dropIn := filepath.Join(root, "etc/ssh/sshd_config.d/90-bap-web-authorized-keys.conf")
	if err := os.MkdirAll(filepath.Dir(dropIn), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dropIn, []byte(authorizedKeysDropIn()), 0o644); err != nil {
		return err
	}
	sshdConfig := filepath.Join(root, "etc/ssh/sshd_config")
	b, err := os.ReadFile(sshdConfig)
	if err == nil && !strings.Contains(string(b), "Include /etc/ssh/sshd_config.d/*.conf") {
		f, err := os.OpenFile(sshdConfig, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, werr := f.WriteString("\nInclude /etc/ssh/sshd_config.d/*.conf\n")
		cerr := f.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return cerr
		}
	}
	return nil
}

func authorizedKeysScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail
user="${1:-}"
[[ -f /etc/bap-web/vm.env ]] || exit 0
source /etc/bap-web/vm.env
[[ -n "${VM_ID:-}" && -n "${BAP_WEB_AUTHORIZED_KEYS_URL:-}" ]] || exit 0
curl -fsS --max-time 3 --get \
  --data-urlencode "vm_id=${VM_ID}" \
  --data-urlencode "user=${user}" \
  "${BAP_WEB_AUTHORIZED_KEYS_URL}" 2>/dev/null || true
`
}

func authorizedKeysDropIn() string {
	return `AuthorizedKeysCommand /usr/local/sbin/bap-web-authorized-keys %u
AuthorizedKeysCommandUser nobody
`
}

func shellQuote(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

func shellEnv(s string) string {
	return "'" + shellQuote(s) + "'"
}

func (s *Service) setupTap(ctx context.Context, vm *model.VM) error {
	if !validIFName(vm.TapName) {
		return fmt.Errorf("tap_name %q is invalid; Linux interface names must be 1-%d bytes", vm.TapName, maxLinuxIFNameLen)
	}
	if err := run(ctx, "ip", "tuntap", "add", "dev", vm.TapName, "mode", "tap"); err != nil && !strings.Contains(err.Error(), "File exists") {
		return err
	}
	_ = run(ctx, "ip", "addr", "flush", "dev", vm.TapName)
	if vm.NetworkMode == "shared_bridge" {
		network, err := s.store.GetNetwork(ctx, vm.NetworkID)
		if err != nil {
			return err
		}
		if network == nil {
			return fmt.Errorf("network not found")
		}
		bridge := bridgeName(network.ID)
		if err := s.ensureBridge(ctx, network); err != nil {
			return err
		}
		if err := run(ctx, "ip", "link", "set", vm.TapName, "master", bridge); err != nil {
			return err
		}
		return run(ctx, "ip", "link", "set", vm.TapName, "up")
	}
	if err := run(ctx, "ip", "addr", "add", fmt.Sprintf("%s/%d", vm.HostIP, vm.CIDR), "dev", vm.TapName); err != nil {
		return err
	}
	return run(ctx, "ip", "link", "set", vm.TapName, "up")
}

func (s *Service) ensureBridge(ctx context.Context, network *model.Network) error {
	bridge := bridgeName(network.ID)
	if !linkExists(ctx, bridge) {
		if err := run(ctx, "ip", "link", "add", bridge, "type", "bridge"); err != nil {
			return err
		}
	}
	_ = run(ctx, "ip", "addr", "add", fmt.Sprintf("%s/%s", network.GatewayIP, cidrPrefix(network.CIDR)), "dev", bridge)
	return run(ctx, "ip", "link", "set", bridge, "up")
}

func (s *Service) applyNFT(ctx context.Context) error {
	vms, err := s.store.ListVMs(ctx)
	if err != nil {
		return err
	}
	_ = run(ctx, "nft", "delete", "table", "ip", "bap_web")
	if err := run(ctx, "nft", "add", "table", "ip", "bap_web"); err != nil {
		return err
	}
	chains := []string{
		"add chain ip bap_web input { type filter hook input priority -100; policy accept; }",
		"add chain ip bap_web prerouting { type nat hook prerouting priority dstnat; policy accept; }",
		"add chain ip bap_web postrouting { type nat hook postrouting priority srcnat; policy accept; }",
		"add chain ip bap_web forward { type filter hook forward priority filter; policy accept; }",
	}
	for _, c := range chains {
		if err := runShell(ctx, "nft '"+c+"'"); err != nil {
			return err
		}
	}
	if err := runShell(ctx, "nft add rule ip bap_web forward ct state established,related accept"); err != nil {
		return err
	}
	lan, err := defaultIF(ctx)
	if err != nil {
		return err
	}
	sharedNetworks := map[string]*model.Network{}
	for _, vm := range vms {
		if vm.State != model.VMRunning && vm.State != model.VMStarting {
			continue
		}
		netDev := vm.TapName
		if vm.NetworkMode == "shared_bridge" {
			network, ok := sharedNetworks[vm.NetworkID]
			if !ok {
				network, err = s.store.GetNetwork(ctx, vm.NetworkID)
				if err != nil {
					return err
				}
				if network == nil {
					return fmt.Errorf("network not found for VM %s", vm.Name)
				}
				sharedNetworks[vm.NetworkID] = network
				if err := runShell(ctx, fmt.Sprintf(`nft add rule ip bap_web forward iifname "%s" ip saddr != %s drop`, bridgeName(network.ID), network.CIDR)); err != nil {
					return err
				}
			}
			netDev = bridgeName(network.ID)
		} else if err := runShell(ctx, fmt.Sprintf(`nft add rule ip bap_web forward iifname "%s" ip saddr != %s drop`, netDev, vm.GuestIP)); err != nil {
			return err
		}
		rules := []string{
			fmt.Sprintf(`nft add rule ip bap_web input iifname "%s" ip saddr %s ip daddr %s tcp dport %d accept`, netDev, vm.GuestIP, vm.HostIP, s.cfg.Server.MetadataPort),
			fmt.Sprintf(`nft add rule ip bap_web prerouting iifname "%s" tcp dport %d dnat to %s:22`, lan, vm.SSHPort, vm.GuestIP),
			fmt.Sprintf(`nft add rule ip bap_web forward iifname "%s" oifname "%s" tcp dport 22 ip daddr %s accept`, lan, netDev, vm.GuestIP),
			fmt.Sprintf(`nft add rule ip bap_web postrouting ip saddr %s oifname "%s" masquerade`, vm.GuestIP, lan),
		}
		protected := s.cfg.Network.ProtectedHostCIDRs
		if len(protected) == 0 {
			protected = []string{"127.0.0.0/8", "169.254.169.254/32"}
		}
		for _, cidr := range protected {
			rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s ip daddr %s drop`, vm.GuestIP, cidr))
		}
		ingressRules, err := s.store.ListIngressRules(ctx, vm.ID)
		if err != nil {
			return err
		}
		for _, rule := range ingressRules {
			rules = append(rules,
				fmt.Sprintf(`nft add rule ip bap_web prerouting iifname "%s" %s dport %d dnat to %s:%d`, lan, rule.Protocol, rule.HostPort, vm.GuestIP, rule.GuestPort),
				fmt.Sprintf(`nft add rule ip bap_web forward iifname "%s" oifname "%s" %s dport %d ip daddr %s accept`, lan, netDev, rule.Protocol, rule.GuestPort, vm.GuestIP),
			)
		}
		egressRules, err := s.egressNFTRules(ctx, vm, lan)
		if err != nil {
			return err
		}
		rules = append(rules, egressRules...)
		for _, rule := range rules {
			if err := runShell(ctx, rule); err != nil {
				return err
			}
		}
	}
	return s.applyFirewalldMetadata(ctx, vms)
}

func (s *Service) applyFirewalldMetadata(ctx context.Context, vms []model.VM) error {
	if commandOK(ctx, "firewall-cmd", "--state") != nil {
		return nil
	}
	for _, vm := range vms {
		if vm.State != model.VMRunning && vm.State != model.VMStarting {
			continue
		}
		rule := fmt.Sprintf(`rule family="ipv4" source address="%s" destination address="%s" port port="%d" protocol="tcp" accept`, vm.GuestIP, vm.HostIP, s.cfg.Server.MetadataPort)
		if err := run(ctx, "firewall-cmd", "--add-rich-rule", rule); err != nil && !strings.Contains(err.Error(), "ALREADY_ENABLED") {
			return err
		}
	}
	return nil
}

func (s *Service) egressNFTRules(ctx context.Context, vm model.VM, lan string) ([]string, error) {
	policyMode := vm.EgressMode
	var tcpPorts, udpPorts, cidrs string
	if vm.EgressPolicyID != "" {
		policy, err := s.store.GetEgressPolicy(ctx, vm.EgressPolicyID)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			return nil, fmt.Errorf("egress policy not found for VM %s", vm.Name)
		}
		policyMode = policy.Mode
		tcpPorts = policy.TCPPorts
		udpPorts = policy.UDPPorts
		cidrs = policy.CIDRs
	}
	rules := []string{}
	switch policyMode {
	case "allow_all", "":
		rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s oifname "%s" accept`, vm.GuestIP, lan))
	case "deny_all":
		rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s oifname "%s" drop`, vm.GuestIP, lan))
	case "restricted":
		for _, port := range splitCSV(tcpPorts) {
			rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s oifname "%s" tcp dport %s accept`, vm.GuestIP, lan, port))
		}
		for _, port := range splitCSV(udpPorts) {
			rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s oifname "%s" udp dport %s accept`, vm.GuestIP, lan, port))
		}
		for _, cidr := range splitCSV(cidrs) {
			rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s oifname "%s" ip daddr %s accept`, vm.GuestIP, lan, cidr))
		}
		rules = append(rules, fmt.Sprintf(`nft add rule ip bap_web forward ip saddr %s oifname "%s" drop`, vm.GuestIP, lan))
	default:
		return nil, fmt.Errorf("unsupported egress mode %q", policyMode)
	}
	return rules, nil
}

func (s *Service) startFirecracker(ctx context.Context, vm *model.VM) error {
	chrootRoot := s.chrootRoot(vm)
	jailDir := filepath.Join(s.cfg.Paths.JailerBaseDir, "firecracker", vm.Name)
	_ = run(ctx, "pkill", "-9", "-f", fmt.Sprintf("firecracker.*--id.*%s", vm.Name))
	_ = run(ctx, "pkill", "-9", "-f", fmt.Sprintf("jailer.*--id.*%s", vm.Name))
	_ = run(ctx, "umount", filepath.Join(chrootRoot, "var/lib/microvms/kernels"))
	_ = run(ctx, "umount", filepath.Join(chrootRoot, "var/lib/microvms", vm.Name))
	_ = os.RemoveAll(jailDir)
	if err := os.MkdirAll(s.cfg.Paths.LogDir, 0o755); err != nil {
		return err
	}
	logPath := filepath.Join(s.cfg.Paths.LogDir, vm.Name+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd := exec.Command(s.cfg.Paths.JailerBin,
		"--id", vm.Name,
		"--exec-file", s.cfg.Paths.FirecrackerBin,
		"--uid", "0", "--gid", "0",
		"--chroot-base-dir", s.cfg.Paths.JailerBaseDir,
		"--",
		"--api-sock", "/firecracker.socket",
		"--log-path", "/firecracker.log",
		"--level", "Debug",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	if err := s.waitSocket(ctx, vm); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(chrootRoot, "var/lib/microvms/kernels"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(chrootRoot, "var/lib/microvms", vm.Name), 0o755); err != nil {
		return err
	}
	if err := run(ctx, "mount", "--bind", s.cfg.Paths.KernelDir, filepath.Join(chrootRoot, "var/lib/microvms/kernels")); err != nil {
		return err
	}
	if err := run(ctx, "mount", "--bind", filepath.Dir(vm.RootFSPath), filepath.Join(chrootRoot, "var/lib/microvms", vm.Name)); err != nil {
		return err
	}
	if err := s.firecrackerPut(ctx, vm, "/machine-config", map[string]any{"vcpu_count": vm.VCPUCount, "mem_size_mib": vm.MemMiB, "smt": false}); err != nil {
		return err
	}
	bootArgs := s.bootArgsForVM(ctx, vm)
	if err := s.firecrackerPut(ctx, vm, "/boot-source", map[string]any{"kernel_image_path": vm.KernelPath, "boot_args": bootArgs}); err != nil {
		return err
	}
	if err := s.firecrackerPut(ctx, vm, "/drives/rootfs", map[string]any{"drive_id": "rootfs", "path_on_host": vm.RootFSPath, "is_root_device": true, "is_read_only": false}); err != nil {
		return err
	}
	if err := s.firecrackerPut(ctx, vm, "/network-interfaces/eth0", map[string]any{"iface_id": "eth0", "host_dev_name": vm.TapName}); err != nil {
		return err
	}
	return s.firecrackerPut(ctx, vm, "/actions", map[string]string{"action_type": "InstanceStart"})
}

func (s *Service) waitSocket(ctx context.Context, vm *model.VM) error {
	sock := s.socketPath(vm)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("Firecracker socket did not appear: %s", sock)
}

func (s *Service) firecrackerAction(ctx context.Context, vm *model.VM, body any) error {
	return s.firecrackerPut(ctx, vm, "/actions", body)
}

func (s *Service) firecrackerPut(ctx context.Context, vm *model.VM, path string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client := http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", s.socketPath(vm))
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("firecracker %s: %s: %s", path, resp.Status, string(rb))
	}
	return nil
}

func (s *Service) socketPath(vm *model.VM) string {
	return filepath.Join(s.chrootRoot(vm), "firecracker.socket")
}

func (s *Service) chrootRoot(vm *model.VM) string {
	return filepath.Join(s.cfg.Paths.JailerBaseDir, "firecracker", vm.Name, "root")
}

func (s *Service) AuthorizedKeys(ctx context.Context, vm *model.VM, user string) (string, error) {
	if user != "" && user != vm.DevUser {
		return "", nil
	}
	var keys []string
	if vm.SSHKeyID != "" {
		key, err := s.store.GetSSHKey(ctx, vm.SSHKeyID)
		if err != nil {
			return "", err
		}
		if key != nil {
			keys = append(keys, key.PublicKey)
		}
	} else if vm.ManagedSSHPublicKey != "" {
		keys = append(keys, vm.ManagedSSHPublicKey)
	}
	if extra := strings.TrimSpace(vm.ExtraAuthorizedKeys); extra != "" {
		keys = append(keys, extra)
	}
	now := time.Now().UTC()
	s.terminalMu.Lock()
	filtered := s.terminalKeys[:0]
	for _, key := range s.terminalKeys {
		if key.ExpiresAt.After(now) {
			filtered = append(filtered, key)
			if key.VMID == vm.ID && key.User == vm.DevUser {
				keys = append(keys, key.PublicKey)
			}
		}
	}
	s.terminalKeys = filtered
	s.terminalMu.Unlock()
	return strings.TrimSpace(strings.Join(keys, "\n")) + "\n", nil
}

const (
	defaultVMExecTimeoutSeconds = 60
	maxVMExecTimeoutSeconds     = 900
	maxVMExecOutputBytes        = 1 << 20
	maxVMExecStdinBytes         = 1 << 20
)

var vmExecEnvNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (s *Service) ExecuteVMCommand(ctx context.Context, vmID string, req VMExecRequest) (*VMExecResult, error) {
	req, err := normalizeVMExecRequest(req)
	if err != nil {
		return nil, err
	}
	vm, err := s.store.GetVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, NotFound("VM not found")
	}
	if vm.State != model.VMRunning {
		return nil, Unprocessable("VM must be running to execute commands", map[string]string{"state": string(vm.State)})
	}
	return s.executeVMCommand(ctx, vm, req)
}

func (s *Service) StartVMExecJob(ctx context.Context, vmID string, req VMExecRequest, actor string) (*model.VMExecJob, error) {
	req, err := normalizeVMExecRequest(req)
	if err != nil {
		return nil, err
	}
	vm, err := s.store.GetVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, NotFound("VM not found")
	}
	if vm.State != model.VMRunning {
		return nil, Unprocessable("VM must be running to execute commands", map[string]string{"state": string(vm.State)})
	}
	envJSON, err := json.Marshal(req.Env)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	job := model.VMExecJob{
		ID:             random.Hex(8),
		VMID:           vm.ID,
		Status:         "queued",
		Command:        req.Command,
		CWD:            req.CWD,
		EnvJSON:        string(envJSON),
		PTY:            req.PTY,
		TimeoutSeconds: req.TimeoutSeconds,
		ExitCode:       -1,
		LogPath:        filepath.Join(s.cfg.Paths.LogDir, "vm-exec-"+random.Hex(8)+".log"),
		CreatedBy:      actor,
		CreatedAt:      now,
	}
	if err := s.store.CreateVMExecJob(ctx, job); err != nil {
		return nil, err
	}
	go s.runVMExecJob(job.ID, vm.ID, req)
	return &job, nil
}

func (s *Service) CancelVMExecJob(ctx context.Context, vmID, jobID string) (*model.VMExecJob, error) {
	job, err := s.store.GetVMExecJob(ctx, vmID, jobID)
	if err != nil {
		return nil, err
	}
	if job == nil {
		return nil, NotFound("exec job not found")
	}
	switch job.Status {
	case "succeeded", "failed", "canceled":
		return job, nil
	}
	s.execMu.Lock()
	cancel := s.execCancels[jobID]
	s.execMu.Unlock()
	if cancel != nil {
		cancel()
	}
	now := time.Now().UTC()
	job.Status = "canceled"
	job.Error = "canceled"
	job.CompletedAt = &now
	if err := s.store.UpdateVMExecJob(ctx, *job); err != nil {
		return nil, err
	}
	return job, nil
}

func (s *Service) runVMExecJob(jobID, vmID string, req VMExecRequest) {
	ctx, cancel := context.WithCancel(context.Background())
	s.execMu.Lock()
	s.execCancels[jobID] = cancel
	s.execMu.Unlock()
	defer func() {
		cancel()
		s.execMu.Lock()
		delete(s.execCancels, jobID)
		s.execMu.Unlock()
	}()
	job, err := s.store.GetVMExecJob(ctx, vmID, jobID)
	if err != nil || job == nil {
		return
	}
	if job.Status == "canceled" {
		s.writeVMExecJobLog(*job)
		return
	}
	started := time.Now().UTC()
	job.Status = "running"
	job.StartedAt = &started
	_ = s.store.UpdateVMExecJob(ctx, *job)
	result, err := s.ExecuteVMCommand(ctx, vmID, req)
	completed := time.Now().UTC()
	latest, getErr := s.store.GetVMExecJob(context.Background(), vmID, jobID)
	if getErr == nil && latest != nil && latest.Status == "canceled" {
		s.writeVMExecJobLog(*latest)
		return
	}
	if result != nil {
		job.Stdout = result.Stdout
		job.Stderr = result.Stderr
		job.ExitCode = result.ExitCode
		job.TimedOut = result.TimedOut
		job.Truncated = result.Truncated
	}
	job.CompletedAt = &completed
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
	} else if result != nil && result.TimedOut {
		job.Status = "failed"
		job.Error = "command timed out"
	} else if result != nil && result.ExitCode != 0 {
		job.Status = "failed"
		job.Error = fmt.Sprintf("command exited with status %d", result.ExitCode)
	} else {
		job.Status = "succeeded"
		job.Error = ""
	}
	_ = s.store.UpdateVMExecJob(context.Background(), *job)
	s.writeVMExecJobLog(*job)
}

func (s *Service) writeVMExecJobLog(job model.VMExecJob) {
	if job.LogPath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(job.LogPath), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(job.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "job=%s\nvm=%s\nstatus=%s\nexit_code=%d\ntimed_out=%t\ntruncated=%t\ncommand=%s\n\n[stdout]\n%s\n\n[stderr]\n%s\n",
		job.ID, job.VMID, job.Status, job.ExitCode, job.TimedOut, job.Truncated, job.Command, job.Stdout, job.Stderr)
	if job.Error != "" {
		_, _ = fmt.Fprintf(f, "\n[error]\n%s\n", job.Error)
	}
}

func (s *Service) executeVMCommand(ctx context.Context, vm *model.VM, req VMExecRequest) (*VMExecResult, error) {
	started := time.Now().UTC()
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	client, cleanup, err := s.sshClientForVM(vm)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	if req.PTY {
		_ = session.RequestPty("xterm-256color", 40, 120, ssh.TerminalModes{})
	}
	if req.Stdin != "" {
		stdin, err := session.StdinPipe()
		if err != nil {
			return nil, err
		}
		go func() {
			_, _ = io.WriteString(stdin, req.Stdin)
			_ = stdin.Close()
		}()
	}
	stdout := &limitedBuffer{limit: maxVMExecOutputBytes}
	stderr := &limitedBuffer{limit: maxVMExecOutputBytes}
	session.Stdout = stdout
	session.Stderr = stderr
	done := make(chan error, 1)
	go func() {
		done <- session.Run(buildRemoteExecCommand(req))
	}()
	timedOut := false
	var runErr error
	select {
	case <-execCtx.Done():
		timedOut = true
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		runErr = <-done
	case runErr = <-done:
	}
	finished := time.Now().UTC()
	return &VMExecResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ExitCode:   exitCode(runErr, timedOut),
		StartedAt:  started,
		FinishedAt: finished,
		TimedOut:   timedOut,
		Truncated:  stdout.Truncated() || stderr.Truncated(),
	}, nil
}

func (s *Service) sshClientForVM(vm *model.VM) (*ssh.Client, func(), error) {
	signer, cleanup, err := s.newEphemeralTerminalSigner(vm)
	if err != nil {
		return nil, cleanup, err
	}
	cfg := &ssh.ClientConfig{
		User:            vm.DevUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", vm.GuestIP), cfg)
	if err != nil && vm.ManagedSSHPrivateKeyPath != "" {
		cleanup()
		client, err = s.legacySSHClient(vm)
		return client, func() {}, err
	}
	return client, cleanup, err
}

func normalizeVMExecRequest(req VMExecRequest) (VMExecRequest, error) {
	req.Command = strings.TrimSpace(req.Command)
	req.CWD = strings.TrimSpace(req.CWD)
	if req.Command == "" {
		return req, Invalid("Command is required", map[string]string{"command": "required"})
	}
	if strings.ContainsRune(req.Command, 0) {
		return req, Invalid("Command is invalid", map[string]string{"command": "must not contain NUL bytes"})
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = defaultVMExecTimeoutSeconds
	}
	if req.TimeoutSeconds < 1 || req.TimeoutSeconds > maxVMExecTimeoutSeconds {
		return req, Invalid("Timeout is invalid", map[string]string{"timeout_seconds": fmt.Sprintf("must be between 1 and %d", maxVMExecTimeoutSeconds)})
	}
	if len(req.Stdin) > maxVMExecStdinBytes {
		return req, Invalid("Stdin is too large", map[string]string{"stdin": fmt.Sprintf("must be at most %d bytes", maxVMExecStdinBytes)})
	}
	if req.Env == nil {
		req.Env = map[string]string{}
	}
	for name, value := range req.Env {
		if !vmExecEnvNameRe.MatchString(name) {
			return req, Invalid("Environment variable name is invalid", map[string]string{"env": name})
		}
		if strings.ContainsRune(value, 0) {
			return req, Invalid("Environment variable value is invalid", map[string]string{"env": name + " must not contain NUL bytes"})
		}
	}
	return req, nil
}

func buildRemoteExecCommand(req VMExecRequest) string {
	parts := []string{}
	if req.CWD != "" {
		parts = append(parts, "cd "+shellEnv(req.CWD))
	}
	envKeys := make([]string, 0, len(req.Env))
	for key := range req.Env {
		envKeys = append(envKeys, key)
	}
	sort.Strings(envKeys)
	envParts := []string{}
	for _, key := range envKeys {
		envParts = append(envParts, key+"="+shellEnv(req.Env[key]))
	}
	command := "sh -lc " + shellEnv(req.Command)
	if len(envParts) > 0 {
		command = "env " + strings.Join(envParts, " ") + " " + command
	}
	parts = append(parts, command)
	return strings.Join(parts, " && ")
}

func exitCode(err error, timedOut bool) int {
	if timedOut {
		return -1
	}
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus()
	}
	return -1
}

type limitedBuffer struct {
	mu        sync.Mutex
	limit     int
	buf       bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *limitedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (s *Service) SSHTerminal(ctx context.Context, vm *model.VM, conn *websocket.Conn, size TerminalSize) error {
	size = normalizeTerminalSize(size)
	client, cleanup, err := s.sshClientForVM(vm)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()
	_ = session.RequestPty("xterm-256color", size.Rows, size.Cols, ssh.TerminalModes{})
	if err := session.Shell(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	errCh := make(chan error, 5)
	outputCh := make(chan []byte, 64)
	var outputWG sync.WaitGroup
	outputWG.Add(2)
	go func() {
		defer outputWG.Done()
		readerToTerminalOutput(stdout, outputCh, done, errCh)
	}()
	go func() {
		defer outputWG.Done()
		readerToTerminalOutput(stderr, outputCh, done, errCh)
	}()
	go func() {
		outputWG.Wait()
		close(outputCh)
	}()
	go terminalOutputToWS(conn, outputCh, done, errCh)
	go wsToWriter(conn, stdin, session, done, errCh)
	go func() {
		if err := session.Wait(); err != nil {
			sendTerminalResult(done, errCh, err)
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Service) newEphemeralTerminalSigner(vm *model.VM) (ssh.Signer, func(), error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, nil, err
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	expires := time.Now().UTC().Add(2 * time.Minute)
	s.terminalMu.Lock()
	s.terminalKeys = append(s.terminalKeys, terminalKey{VMID: vm.ID, User: vm.DevUser, PublicKey: publicKey, ExpiresAt: expires})
	s.terminalMu.Unlock()
	cleanup := func() {
		s.terminalMu.Lock()
		out := s.terminalKeys[:0]
		for _, key := range s.terminalKeys {
			if !(key.VMID == vm.ID && key.User == vm.DevUser && key.PublicKey == publicKey) {
				out = append(out, key)
			}
		}
		s.terminalKeys = out
		s.terminalMu.Unlock()
	}
	return signer, cleanup, nil
}

func (s *Service) verifyEphemeralSSH(ctx context.Context, vm *model.VM) error {
	signer, cleanup, err := s.newEphemeralTerminalSigner(vm)
	if err != nil {
		return err
	}
	defer cleanup()
	cfg := &ssh.ClientConfig{
		User:            vm.DevUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", vm.GuestIP), cfg)
		if err != nil {
			done <- err
			return
		}
		defer client.Close()
		session, err := client.NewSession()
		if err != nil {
			done <- err
			return
		}
		defer session.Close()
		done <- session.Run("true")
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (s *Service) legacySSHClient(vm *model.VM) (*ssh.Client, error) {
	key, err := os.ReadFile(vm.ManagedSSHPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            vm.DevUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:22", vm.GuestIP), cfg)
}

func normalizeTerminalSize(size TerminalSize) TerminalSize {
	if size.Rows < 8 || size.Rows > 200 {
		size.Rows = 40
	}
	if size.Cols < 20 || size.Cols > 400 {
		size.Cols = 120
	}
	return size
}

func parseTerminalResizeMessage(msg []byte) (TerminalSize, bool) {
	var ctrl terminalControlMessage
	if err := json.Unmarshal(msg, &ctrl); err != nil || ctrl.Type != "resize" {
		return TerminalSize{}, false
	}
	size := normalizeTerminalSize(TerminalSize{Rows: ctrl.Rows, Cols: ctrl.Cols})
	return size, true
}

func wsToWriter(conn *websocket.Conn, w io.Writer, resizer terminalResizer, done <-chan struct{}, errCh chan<- error) {
	for {
		msgType, msg, err := conn.ReadMessage()
		if err != nil {
			sendTerminalResult(done, errCh, err)
			return
		}
		if msgType == websocket.TextMessage {
			if size, ok := parseTerminalResizeMessage(msg); ok {
				if err := resizer.WindowChange(size.Rows, size.Cols); err != nil {
					sendTerminalResult(done, errCh, err)
					return
				}
				continue
			}
		}
		if _, err := w.Write(msg); err != nil {
			sendTerminalResult(done, errCh, err)
			return
		}
	}
}

func readerToTerminalOutput(r io.Reader, out chan<- []byte, done <-chan struct{}, errCh chan<- error) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case out <- chunk:
			case <-done:
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				sendTerminalResult(done, errCh, err)
			}
			return
		}
	}
}

func terminalOutputToWS(conn websocketMessageWriter, out <-chan []byte, done <-chan struct{}, errCh chan<- error) {
	for {
		select {
		case <-done:
			return
		case msg, ok := <-out:
			if !ok {
				sendTerminalResult(done, errCh, nil)
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				sendTerminalResult(done, errCh, err)
				return
			}
		}
	}
}

func sendTerminalResult(done <-chan struct{}, errCh chan<- error, err error) {
	select {
	case errCh <- err:
	case <-done:
	}
}

func (s *Service) validateSharedNetwork(ctx context.Context, cidr, gatewayIP string) (string, string, error) {
	cidr = strings.TrimSpace(cidr)
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", Invalid("Shared network CIDR is invalid", map[string]string{"cidr": err.Error()})
	}
	base := ip.To4()
	ones, bits := ipnet.Mask.Size()
	if base == nil || bits != 32 || ones > 30 {
		return "", "", Invalid("Shared network CIDR is invalid", map[string]string{"cidr": "must be an IPv4 CIDR with at least two usable host addresses"})
	}
	if !cidrWithin(s.cfg.Network.VMCIDR, ipnet) {
		return "", "", Invalid("Shared network CIDR is outside the configured VM range", map[string]string{"cidr": "must be inside configured vm_cidr " + s.cfg.Network.VMCIDR})
	}
	if conflict, err := s.findCIDROverlap(ctx, ipnet, ""); err != nil {
		return "", "", err
	} else if conflict != nil {
		return "", "", conflictError(fmt.Sprintf("Shared network CIDR %s overlaps %s %s", ipnet.String(), conflict.SubjectName, conflict.SubjectCIDR), "cidr")
	}
	start := ipToUint32(ipnet.IP.To4())
	size := uint32(1) << uint32(32-ones)
	gateway := net.ParseIP(strings.TrimSpace(gatewayIP)).To4()
	if gateway == nil {
		gateway = uint32ToIP(start + 1)
	}
	gatewayValue := ipToUint32(gateway)
	if !ipnet.Contains(gateway) || gatewayValue == start || gatewayValue == start+size-1 {
		return "", "", Invalid("Shared network gateway_ip is invalid", map[string]string{"gateway_ip": "must be a usable IP inside the shared network"})
	}
	return ipnet.String(), gateway.String(), nil
}

func validateEgressPolicy(mode, tcpPorts, udpPorts, cidrs string) (string, string, string, error) {
	switch mode {
	case "allow_all", "deny_all":
		return "", "", "", nil
	case "restricted":
	default:
		return "", "", "", fmt.Errorf("mode must be allow_all, deny_all, or restricted")
	}
	tcp, err := normalizePorts(tcpPorts)
	if err != nil {
		return "", "", "", fmt.Errorf("tcp_ports: %w", err)
	}
	udp, err := normalizePorts(udpPorts)
	if err != nil {
		return "", "", "", fmt.Errorf("udp_ports: %w", err)
	}
	normalizedCIDRs, err := normalizeCIDRs(cidrs)
	if err != nil {
		return "", "", "", err
	}
	if tcp == "" && udp == "" && normalizedCIDRs == "" {
		return "", "", "", fmt.Errorf("restricted policies require at least one allowed port or CIDR")
	}
	return tcp, udp, normalizedCIDRs, nil
}

func normalizePorts(s string) (string, error) {
	var out []string
	seen := map[int]bool{}
	for _, part := range splitCSV(s) {
		port, err := strconv.Atoi(part)
		if err != nil {
			return "", err
		}
		if port < 1 || port > 65535 {
			return "", fmt.Errorf("port %d outside 1-65535", port)
		}
		if !seen[port] {
			out = append(out, strconv.Itoa(port))
			seen[port] = true
		}
	}
	return strings.Join(out, ","), nil
}

func normalizeCIDRs(s string) (string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range splitCSV(s) {
		ip, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			parsed := net.ParseIP(part)
			if parsed == nil || parsed.To4() == nil {
				return "", fmt.Errorf("invalid cidr %q", part)
			}
			part = parsed.To4().String() + "/32"
		} else if ip.To4() == nil {
			return "", fmt.Errorf("only IPv4 CIDRs are supported")
		} else {
			part = ipnet.String()
		}
		if !seen[part] {
			out = append(out, part)
			seen[part] = true
		}
	}
	return strings.Join(out, ","), nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func cidrWithin(parentCIDR string, child *net.IPNet) bool {
	_, parent, err := net.ParseCIDR(parentCIDR)
	if err != nil {
		return false
	}
	childIP := child.IP.To4()
	parentIP := parent.IP.To4()
	if childIP == nil || parentIP == nil {
		return false
	}
	ones, bits := child.Mask.Size()
	if bits != 32 {
		return false
	}
	start := ipToUint32(childIP)
	size := uint32(1) << uint32(32-ones)
	return parent.Contains(uint32ToIP(start)) && parent.Contains(uint32ToIP(start+size-1))
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func bridgeName(id string) string {
	name := "br-bap-" + strings.ToLower(id)
	if len(name) > 15 {
		return name[:15]
	}
	return name
}

func cidrPrefix(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "24"
	}
	ones, _ := ipnet.Mask.Size()
	return strconv.Itoa(ones)
}

func linkExists(ctx context.Context, name string) bool {
	return run(ctx, "ip", "link", "show", "dev", name) == nil
}

func hostLinks(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "ip", "-o", "link", "show")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	links := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if at := strings.Index(name, "@"); at >= 0 {
			name = name[:at]
		}
		if name != "" {
			links = append(links, name)
		}
	}
	return links, nil
}

func cleanupTap(ctx context.Context, name string) error {
	var errs []string
	ignore := func(label string, err error) {
		if cleanupOK(err) {
			return
		}
		errs = append(errs, label+": "+err.Error())
	}
	ignore("detach", run(ctx, "ip", "link", "set", "dev", name, "nomaster"))
	ignore("flush", run(ctx, "ip", "addr", "flush", "dev", name))
	ignore("down", run(ctx, "ip", "link", "set", name, "down"))
	ignore("delete", deleteTapDevice(ctx, name))
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func deleteTapDevice(ctx context.Context, name string) error {
	var last error
	for i := 0; i < 8; i++ {
		last = run(ctx, "ip", "tuntap", "del", "dev", name, "mode", "tap")
		if cleanupOK(last) {
			return nil
		}
		if last == nil || !strings.Contains(last.Error(), "Device or resource busy") {
			break
		}
		_ = run(ctx, "ip", "link", "set", "dev", name, "nomaster")
		_ = run(ctx, "ip", "link", "set", name, "down")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	linkErr := run(ctx, "ip", "link", "delete", name)
	if cleanupOK(linkErr) {
		return nil
	}
	if last != nil {
		return fmt.Errorf("%v; fallback link delete: %w", last, linkErr)
	}
	return linkErr
}

func cleanupBridge(ctx context.Context, name string) error {
	var errs []string
	ignore := func(label string, err error) {
		if cleanupOK(err) {
			return
		}
		errs = append(errs, label+": "+err.Error())
	}
	ignore("flush", run(ctx, "ip", "addr", "flush", "dev", name))
	ignore("down", run(ctx, "ip", "link", "set", name, "down"))
	ignore("delete", run(ctx, "ip", "link", "del", name, "type", "bridge"))
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func cleanupOK(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "Cannot find device") ||
		strings.Contains(msg, "No such device") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not mounted") ||
		strings.Contains(msg, "not a mountpoint") ||
		strings.Contains(msg, "no mount point specified") ||
		strings.Contains(msg, "Invalid argument")
}

func lifecycleErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func parseRange(s string) (int, int, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	a, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	b, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, err
	}
	if a > b {
		return 0, 0, fmt.Errorf("invalid range %q", s)
	}
	return a, b, nil
}

func portOpen(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

func requireFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	return nil
}

func requireExecutable(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}

func commandOK(ctx context.Context, name string, args ...string) error {
	return run(ctx, name, args...)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runShell(ctx context.Context, command string) error {
	cmd := exec.CommandContext(ctx, "bash", "-lc", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultIF(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "route", "show", "default")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("default route interface not found")
}
