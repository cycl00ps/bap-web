package model

import (
	"net"
	"regexp"
	"strings"
	"time"
)

type VMState string

const (
	VMStopped  VMState = "stopped"
	VMRunning  VMState = "running"
	VMStarting VMState = "starting"
	VMStopping VMState = "stopping"
	VMError    VMState = "error"
)

type VM struct {
	ID                       string     `json:"id"`
	Name                     string     `json:"name"`
	State                    VMState    `json:"state"`
	VCPUCount                int        `json:"vcpu_count"`
	MemMiB                   int        `json:"mem_mib"`
	SSHPort                  int        `json:"ssh_port"`
	TapName                  string     `json:"tap_name"`
	HostIP                   string     `json:"host_ip"`
	GuestIP                  string     `json:"guest_ip"`
	CIDR                     int        `json:"cidr"`
	KernelPath               string     `json:"kernel_path"`
	KernelID                 string     `json:"kernel_id"`
	RootFSPath               string     `json:"rootfs_path"`
	BaseRootFSPath           string     `json:"base_rootfs_path"`
	BaseImageID              string     `json:"base_image_id"`
	RootFSSizeMiB            int        `json:"rootfs_size_mib"`
	DevUser                  string     `json:"dev_user"`
	SSHKeyID                 string     `json:"ssh_key_id"`
	ManagedSSHPublicKey      string     `json:"managed_ssh_public_key"`
	ManagedSSHPrivateKeyPath string     `json:"managed_ssh_private_key_path"`
	ExtraAuthorizedKeys      string     `json:"extra_authorized_keys"`
	RepoURL                  string     `json:"repo_url"`
	GitRef                   string     `json:"git_ref"`
	EgressMode               string     `json:"egress_mode"`
	EgressPolicyID           string     `json:"egress_policy_id"`
	NetworkMode              string     `json:"network_mode"`
	NetworkID                string     `json:"network_id"`
	LastError                string     `json:"last_error"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
	LastStartedAt            *time.Time `json:"last_started_at,omitempty"`
	LastStoppedAt            *time.Time `json:"last_stopped_at,omitempty"`
}

type SSHKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	PublicKey   string     `json:"public_key"`
	Fingerprint string     `json:"fingerprint"`
	KeyType     string     `json:"key_type"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

type Network struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	GatewayIP string    `json:"gateway_ip"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type IngressRule struct {
	ID          string    `json:"id"`
	VMID        string    `json:"vm_id"`
	Protocol    string    `json:"protocol"`
	HostPort    int       `json:"host_port"`
	GuestPort   int       `json:"guest_port"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type EgressPolicy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	TCPPorts  string    `json:"tcp_ports"`
	UDPPorts  string    `json:"udp_ports"`
	CIDRs     string    `json:"cidrs"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BaseImage struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Status         string    `json:"status"`
	Filesystem     string    `json:"filesystem"`
	Path           string    `json:"path"`
	VirtualSizeMiB int       `json:"virtual_size_mib"`
	DiskSizeBytes  int64     `json:"disk_size_bytes"`
	Checksum       string    `json:"checksum"`
	Packages       string    `json:"packages"`
	Hooks          string    `json:"hooks"`
	Provenance     string    `json:"provenance"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type ImageBuildJob struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	Name          string     `json:"name"`
	Filesystem    string     `json:"filesystem"`
	SizeMiB       int        `json:"size_mib"`
	Packages      string     `json:"packages"`
	Hooks         string     `json:"hooks"`
	LogPath       string     `json:"log_path"`
	ResultImageID string     `json:"result_image_id"`
	Error         string     `json:"error"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

type ImageHook struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	SourceType     string     `json:"source_type"`
	Status         string     `json:"status"`
	ContentPath    string     `json:"content_path"`
	GitURL         string     `json:"git_url"`
	GitRef         string     `json:"git_ref"`
	GitPath        string     `json:"git_path"`
	ResolvedCommit string     `json:"resolved_commit"`
	Checksum       string     `json:"checksum"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

type Kernel struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Architecture string     `json:"architecture"`
	Status       string     `json:"status"`
	SourceType   string     `json:"source_type"`
	Path         string     `json:"path"`
	ConfigPath   string     `json:"config_path"`
	Checksum     string     `json:"checksum"`
	BootArgs     string     `json:"boot_args"`
	Provenance   string     `json:"provenance"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastTestedAt *time.Time `json:"last_tested_at,omitempty"`
}

type KernelTestJob struct {
	ID            string     `json:"id"`
	KernelID      string     `json:"kernel_id"`
	Status        string     `json:"status"`
	LogPath       string     `json:"log_path"`
	BaseImageID   string     `json:"base_image_id"`
	UnameResult   string     `json:"uname_result"`
	KernelRelease string     `json:"kernel_release,omitempty"`
	GatewayOK     *bool      `json:"gateway_ok,omitempty"`
	ResultSummary string     `json:"result_summary,omitempty"`
	Error         string     `json:"error"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

var kernelReleaseRe = regexp.MustCompile(`^[0-9]+[.][0-9]+([.][0-9]+)?[-+._A-Za-z0-9]*$`)

func EnrichKernelTestJob(job KernelTestJob) KernelTestJob {
	release, gatewayOK, summary := ParseKernelTestResult(job.UnameResult)
	job.KernelRelease = release
	job.GatewayOK = gatewayOK
	job.ResultSummary = summary
	return job
}

func ParseKernelTestResult(output string) (string, *bool, string) {
	clean := CleanKernelTestOutput(output)
	fields := strings.Fields(clean)
	release := ""
	gatewayOK := (*bool)(nil)
	for _, field := range fields {
		token := strings.Trim(field, `'"`)
		switch token {
		case "gateway-ok":
			ok := true
			gatewayOK = &ok
			continue
		case "gateway-failed":
			ok := false
			gatewayOK = &ok
			continue
		}
		if release == "" && looksLikeKernelRelease(token) {
			release = token
		}
	}
	parts := []string{}
	if release != "" {
		parts = append(parts, release)
	}
	if gatewayOK != nil {
		if *gatewayOK {
			parts = append(parts, "gateway OK")
		} else {
			parts = append(parts, "gateway failed")
		}
	}
	return release, gatewayOK, strings.Join(parts, ", ")
}

func CleanKernelTestOutput(output string) string {
	output = strings.ReplaceAll(strings.TrimSpace(output), "\r\n", "\n")
	output = strings.ReplaceAll(output, "\r", "\n")
	if output == "" {
		return ""
	}
	release, gatewayOK := "", ""
	for _, field := range strings.Fields(output) {
		token := strings.Trim(field, `'"`)
		if token == "gateway-ok" || token == "gateway-failed" {
			gatewayOK = token
			continue
		}
		if release == "" && looksLikeKernelRelease(token) {
			release = token
		}
	}
	parts := []string{}
	if release != "" {
		parts = append(parts, release)
	}
	if gatewayOK != "" {
		parts = append(parts, gatewayOK)
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	cleanLines := []string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Warning: Permanently added ") {
			continue
		}
		cleanLines = append(cleanLines, line)
	}
	return strings.Join(cleanLines, "\n")
}

func looksLikeKernelRelease(token string) bool {
	if token == "" || net.ParseIP(token) != nil {
		return false
	}
	return kernelReleaseRe.MatchString(token)
}

type KernelDiscoveryJob struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	SourceURL    string     `json:"source_url"`
	CIPrefix     string     `json:"ci_prefix"`
	Architecture string     `json:"architecture"`
	ItemCount    int        `json:"item_count"`
	Error        string     `json:"error"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

type KernelDiscoveryItem struct {
	ID                string    `json:"id"`
	JobID             string    `json:"job_id"`
	Version           string    `json:"version"`
	Variant           string    `json:"variant"`
	Architecture      string    `json:"architecture"`
	CIPrefix          string    `json:"ci_prefix"`
	KernelKey         string    `json:"kernel_key"`
	ConfigKey         string    `json:"config_key"`
	KernelURL         string    `json:"kernel_url"`
	ConfigURL         string    `json:"config_url"`
	AlreadyRegistered bool      `json:"already_registered"`
	CreatedAt         time.Time `json:"created_at"`
}

type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	IsAdmin    bool       `json:"is_admin"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type VMExecJob struct {
	ID             string     `json:"id"`
	VMID           string     `json:"vm_id"`
	Status         string     `json:"status"`
	Command        string     `json:"command"`
	CWD            string     `json:"cwd"`
	EnvJSON        string     `json:"env_json"`
	PTY            bool       `json:"pty"`
	TimeoutSeconds int        `json:"timeout_seconds"`
	Stdout         string     `json:"stdout"`
	Stderr         string     `json:"stderr"`
	ExitCode       int        `json:"exit_code"`
	TimedOut       bool       `json:"timed_out"`
	Truncated      bool       `json:"truncated"`
	LogPath        string     `json:"log_path"`
	Error          string     `json:"error"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

type User struct {
	ID           string
	Username     string
	PasswordHash []byte
	IsAdmin      bool
	CreatedAt    time.Time
}

type Session struct {
	ID         string
	UserID     string
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}
