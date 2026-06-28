package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Paths    PathsConfig    `yaml:"paths"`
	Network  NetworkConfig  `yaml:"network"`
	Security SecurityConfig `yaml:"security"`
	Images   ImageConfig    `yaml:"images"`
	Kernels  KernelConfig   `yaml:"kernels"`
}

type ServerConfig struct {
	BindAddress         string   `yaml:"bind_address"`
	Port                int      `yaml:"port"`
	MetadataBindAddress string   `yaml:"metadata_bind_address"`
	MetadataPort        int      `yaml:"metadata_port"`
	StaticDir           string   `yaml:"static_dir"`
	TrustedHosts        []string `yaml:"trusted_hosts"`
	AllowedOrigins      []string `yaml:"allowed_origins"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type PathsConfig struct {
	StateDir       string `yaml:"state_dir"`
	LogDir         string `yaml:"log_dir"`
	KeyDir         string `yaml:"key_dir"`
	RuntimeDir     string `yaml:"runtime_dir"`
	ImageDir       string `yaml:"image_dir"`
	KernelDir      string `yaml:"kernel_dir"`
	KernelImage    string `yaml:"kernel_image"`
	BaseImageDir   string `yaml:"base_image_dir"`
	BaseRootFS     string `yaml:"base_rootfs"`
	JailerBaseDir  string `yaml:"jailer_base_dir"`
	FirecrackerBin string `yaml:"firecracker_bin"`
	JailerBin      string `yaml:"jailer_bin"`
}

type NetworkConfig struct {
	Backend            string   `yaml:"backend"`
	VMCIDR             string   `yaml:"vm_cidr"`
	SSHPortRange       string   `yaml:"ssh_port_range"`
	DefaultNetworkMode string   `yaml:"default_network_mode"`
	ProtectedHostCIDRs []string `yaml:"protected_host_cidrs"`
}

type SecurityConfig struct {
	SessionIdleTimeout     Duration `yaml:"session_idle_timeout"`
	SessionAbsoluteTimeout Duration `yaml:"session_absolute_timeout"`
	TerminalRecording      string   `yaml:"terminal_recording"`
}

type ImageConfig struct {
	BuildDir        string   `yaml:"build_dir"`
	HookDir         string   `yaml:"hook_dir"`
	MaxBaseImageMiB int      `yaml:"max_base_image_mib"`
	MaxVMRootFSMiB  int      `yaml:"max_vm_rootfs_mib"`
	MaxHookBytes    int64    `yaml:"max_hook_bytes"`
	MaxPackages     int      `yaml:"max_packages"`
	BuildTimeout    Duration `yaml:"build_timeout"`
	AllowedGitHosts []string `yaml:"allowed_git_hosts"`
}

type KernelConfig struct {
	MaxKernelBytes       int64    `yaml:"max_kernel_bytes"`
	TestTimeout          Duration `yaml:"test_timeout"`
	CIScanTimeout        Duration `yaml:"ci_scan_timeout"`
	CIImportTimeout      Duration `yaml:"ci_import_timeout"`
	FirecrackerCIBaseURL string   `yaml:"firecracker_ci_base_url"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, cfg); err != nil {
			return nil, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			BindAddress:         "127.0.0.1",
			Port:                8080,
			MetadataBindAddress: "0.0.0.0",
			MetadataPort:        18080,
			StaticDir:           "/usr/local/share/bap-web/static",
		},
		Database: DatabaseConfig{Driver: "sqlite", DSN: "/var/lib/bap-web/bap-web.db"},
		Paths: PathsConfig{
			StateDir:       "/var/lib/bap-web",
			LogDir:         "/var/log/bap-web",
			KeyDir:         "/var/lib/bap-web/keys",
			RuntimeDir:     "/var/lib/bap-web/runtime",
			ImageDir:       "/var/lib/microvms",
			KernelDir:      "/var/lib/microvms/kernels",
			KernelImage:    "/var/lib/microvms/kernels/vmlinux-5.10.bin",
			BaseImageDir:   "/var/lib/microvms/base",
			BaseRootFS:     "/var/lib/microvms/base/base-rootfs.ext4",
			JailerBaseDir:  "/srv/jailer",
			FirecrackerBin: "/usr/local/bin/firecracker",
			JailerBin:      "/usr/local/bin/jailer",
		},
		Network: NetworkConfig{
			Backend:            "nftables",
			VMCIDR:             "172.31.0.0/16",
			SSHPortRange:       "20000-29999",
			DefaultNetworkMode: "routed_ptp",
			ProtectedHostCIDRs: []string{"127.0.0.0/8", "169.254.169.254/32"},
		},
		Security: SecurityConfig{
			SessionIdleTimeout:     Duration{30 * time.Minute},
			SessionAbsoluteTimeout: Duration{12 * time.Hour},
			TerminalRecording:      "metadata",
		},
		Images: ImageConfig{
			BuildDir:        "/var/lib/bap-web/image-builds",
			HookDir:         "/var/lib/bap-web/image-hooks",
			MaxBaseImageMiB: 32768,
			MaxVMRootFSMiB:  65536,
			MaxHookBytes:    256 * 1024,
			MaxPackages:     100,
			BuildTimeout:    Duration{45 * time.Minute},
		},
		Kernels: KernelConfig{
			MaxKernelBytes:       512 * 1024 * 1024,
			TestTimeout:          Duration{5 * time.Minute},
			CIScanTimeout:        Duration{15 * time.Second},
			CIImportTimeout:      Duration{2 * time.Minute},
			FirecrackerCIBaseURL: "https://s3.amazonaws.com/spec.ccfc.min",
		},
	}
}

func (c *Config) Validate() error {
	if c.Server.BindAddress == "" || c.Server.Port == 0 {
		return fmt.Errorf("server bind_address and port are required")
	}
	if c.Server.MetadataBindAddress == "" {
		c.Server.MetadataBindAddress = "0.0.0.0"
	}
	if c.Server.MetadataPort == 0 {
		c.Server.MetadataPort = 18080
	}
	if c.Database.Driver == "" || c.Database.DSN == "" {
		return fmt.Errorf("database driver and dsn are required")
	}
	if c.Database.Driver != "sqlite" {
		return fmt.Errorf("only sqlite is implemented in v1, got %q", c.Database.Driver)
	}
	if c.Network.DefaultNetworkMode == "" {
		c.Network.DefaultNetworkMode = "routed_ptp"
	}
	if c.Images.BuildDir == "" {
		c.Images.BuildDir = c.Paths.StateDir + "/image-builds"
	}
	if c.Images.HookDir == "" {
		c.Images.HookDir = c.Paths.StateDir + "/image-hooks"
	}
	if c.Images.MaxBaseImageMiB == 0 {
		c.Images.MaxBaseImageMiB = 32768
	}
	if c.Images.MaxVMRootFSMiB == 0 {
		c.Images.MaxVMRootFSMiB = 65536
	}
	if c.Images.MaxHookBytes == 0 {
		c.Images.MaxHookBytes = 256 * 1024
	}
	if c.Images.MaxPackages == 0 {
		c.Images.MaxPackages = 100
	}
	if c.Images.BuildTimeout.Duration == 0 {
		c.Images.BuildTimeout.Duration = 45 * time.Minute
	}
	if c.Kernels.MaxKernelBytes == 0 {
		c.Kernels.MaxKernelBytes = 512 * 1024 * 1024
	}
	if c.Kernels.TestTimeout.Duration == 0 {
		c.Kernels.TestTimeout.Duration = 5 * time.Minute
	}
	if c.Kernels.CIScanTimeout.Duration == 0 {
		c.Kernels.CIScanTimeout.Duration = 15 * time.Second
	}
	if c.Kernels.CIImportTimeout.Duration == 0 {
		c.Kernels.CIImportTimeout.Duration = 2 * time.Minute
	}
	if c.Kernels.FirecrackerCIBaseURL == "" {
		c.Kernels.FirecrackerCIBaseURL = "https://s3.amazonaws.com/spec.ccfc.min"
	}
	return nil
}

func (s ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", s.BindAddress, s.Port)
}
