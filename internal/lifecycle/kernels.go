package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"bap-web/internal/model"
	"bap-web/internal/random"
	"bap-web/internal/sshkeys"
)

const (
	kernelStatusPending  = "pending"
	kernelStatusActive   = "active"
	kernelStatusFailed   = "failed"
	kernelStatusArchived = "archived"

	kernelSourceConfigured    = "configured"
	kernelSourceFirecrackerCI = "firecracker-ci"
	kernelSourceUpload        = "upload"
)

const defaultKernelBootArgs = "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw clocksource=tsc tsc=reliable"

type RegisterKernelRequest struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Path          string `json:"path"`
	ConfigPath    string `json:"config_path"`
	Status        string `json:"status"`
	BootArgs      string `json:"boot_args"`
	SourceType    string `json:"source_type"`
	Provenance    string `json:"provenance"`
	TrustExisting bool   `json:"-"`
}

type ImportFirecrackerCIKernelRequest struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	CIPrefix   string `json:"ci_prefix"`
	ArtifactID string `json:"artifact_id"`
}

type UploadKernelRequest struct {
	Name         string
	Version      string
	KernelName   string
	KernelReader io.Reader
	ConfigName   string
	ConfigReader io.Reader
}

type KernelUpdateRequest struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	BootArgs string `json:"boot_args"`
}

type DiscoverFirecrackerCIKernelsRequest struct {
	CIPrefix string `json:"ci_prefix"`
}

type s3ListBucketResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

func (s *Service) EnsureDefaultKernel(ctx context.Context) error {
	if strings.TrimSpace(s.cfg.Paths.KernelImage) == "" {
		return nil
	}
	if _, err := os.Stat(s.cfg.Paths.KernelImage); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	existing, err := s.store.GetKernelByPath(ctx, s.cfg.Paths.KernelImage)
	if err != nil || existing != nil {
		if existing != nil {
			if backfillErr := s.store.BackfillVMKernelID(ctx, existing.ID, existing.Path); backfillErr != nil {
				return backfillErr
			}
		}
		return err
	}
	kernel, err := s.RegisterKernel(ctx, RegisterKernelRequest{
		Name:          "default-kernel-5-10",
		Version:       inferKernelVersion(s.cfg.Paths.KernelImage),
		Path:          s.cfg.Paths.KernelImage,
		Status:        kernelStatusActive,
		BootArgs:      defaultKernelBootArgs,
		SourceType:    kernelSourceConfigured,
		Provenance:    "configured paths.kernel_image",
		TrustExisting: true,
	}, "system")
	if err != nil {
		return err
	}
	return s.store.BackfillVMKernelID(ctx, kernel.ID, kernel.Path)
}

func (s *Service) RegisterKernel(ctx context.Context, req RegisterKernelRequest, actor string) (*model.Kernel, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !nameRe.MatchString(req.Name) {
		return nil, Invalid("Kernel name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	path, err := s.validateKernelPath(req.Path)
	if err != nil {
		return nil, Invalid("Kernel path is invalid", map[string]string{"path": err.Error()})
	}
	if err := requireFile(path); err != nil {
		return nil, Invalid("Kernel path is invalid", map[string]string{"path": err.Error()})
	}
	if err := secureExistingPath(path); err != nil {
		return nil, Invalid("Kernel path is unsafe", map[string]string{"path": err.Error()})
	}
	if !req.TrustExisting {
		if err := s.validateKernelFile(ctx, path); err != nil {
			return nil, err
		}
	}
	configPath := ""
	if strings.TrimSpace(req.ConfigPath) != "" {
		configPath, err = s.validateKernelPath(req.ConfigPath)
		if err != nil {
			return nil, Invalid("Kernel config path is invalid", map[string]string{"config_path": err.Error()})
		}
		if err := requireFile(configPath); err != nil {
			return nil, Invalid("Kernel config path is invalid", map[string]string{"config_path": err.Error()})
		}
	}
	status := defaultImageString(strings.TrimSpace(req.Status), kernelStatusPending)
	if !validKernelStatus(status) {
		return nil, Invalid("Kernel status is invalid", map[string]string{"status": "must be pending, active, failed, or archived"})
	}
	sourceType := defaultImageString(strings.TrimSpace(req.SourceType), kernelSourceUpload)
	if sourceType != kernelSourceConfigured && sourceType != kernelSourceFirecrackerCI && sourceType != kernelSourceUpload {
		return nil, Invalid("Kernel source_type is invalid", map[string]string{"source_type": "must be configured, firecracker-ci, or upload"})
	}
	checksum, err := fileSHA256(path)
	if err != nil {
		return nil, err
	}
	arch := detectKernelArchitecture(ctx, path)
	if arch == "" {
		arch = hostArchitecture()
	}
	now := time.Now().UTC()
	kernel := model.Kernel{
		ID:           random.Hex(8),
		Name:         req.Name,
		Version:      strings.TrimSpace(req.Version),
		Architecture: arch,
		Status:       status,
		SourceType:   sourceType,
		Path:         path,
		ConfigPath:   configPath,
		Checksum:     checksum,
		BootArgs:     defaultImageString(strings.TrimSpace(req.BootArgs), defaultKernelBootArgs),
		Provenance:   strings.TrimSpace(req.Provenance),
		CreatedBy:    actor,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.store.CreateKernel(ctx, kernel); err != nil {
		return nil, err
	}
	return &kernel, nil
}

func (s *Service) UploadKernel(ctx context.Context, req UploadKernelRequest, actor string) (*model.Kernel, error) {
	if req.KernelReader == nil {
		return nil, Invalid("Kernel file is required", map[string]string{"kernel": "required"})
	}
	id := random.Hex(8)
	dir := filepath.Join(s.cfg.Paths.KernelDir, sanitizePathPart(req.Name)+"-"+id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kernelPath := filepath.Join(dir, defaultImageString(cleanKernelFilename(req.KernelName), "vmlinux"))
	if err := writeLimitedFile(kernelPath, req.KernelReader, s.cfg.Kernels.MaxKernelBytes, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, Invalid("Kernel upload is invalid", map[string]string{"kernel": err.Error()})
	}
	configPath := ""
	if req.ConfigReader != nil {
		configPath = filepath.Join(dir, defaultImageString(cleanKernelFilename(req.ConfigName), "kernel.config"))
		if err := writeLimitedFile(configPath, req.ConfigReader, 4*1024*1024, 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return nil, Invalid("Kernel config upload is invalid", map[string]string{"config": err.Error()})
		}
	}
	kernel, err := s.RegisterKernel(ctx, RegisterKernelRequest{
		Name:       req.Name,
		Version:    req.Version,
		Path:       kernelPath,
		ConfigPath: configPath,
		Status:     kernelStatusPending,
		BootArgs:   defaultKernelBootArgs,
		SourceType: kernelSourceUpload,
		Provenance: "admin upload",
	}, actor)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return kernel, nil
}

func (s *Service) ImportFirecrackerCIKernel(ctx context.Context, req ImportFirecrackerCIKernelRequest, actor string) (*model.Kernel, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Kernels.CIImportTimeout.Duration)
	defer cancel()
	if artifactID := strings.TrimSpace(req.ArtifactID); artifactID != "" {
		item, err := s.store.GetKernelDiscoveryItem(ctx, artifactID)
		if err != nil {
			return nil, err
		}
		if item == nil {
			return nil, NotFound("kernel discovery artifact not found")
		}
		if item.AlreadyRegistered {
			return nil, ConflictFields("Kernel artifact is already registered", map[string]string{"artifact_id": "already registered"})
		}
		if existing, err := s.findKernelByProvenance(ctx, item.KernelURL); err != nil {
			return nil, err
		} else if existing != nil {
			_ = s.store.MarkKernelDiscoveryItemRegistered(ctx, item.ID, true)
			return nil, ConflictFields("Kernel artifact is already registered", map[string]string{"artifact_id": "already registered"})
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = kernelCIName(item.Version)
		}
		kernel, err := s.importFirecrackerCIKernelByKeys(ctx, name, item.Version, item.KernelKey, item.ConfigKey, actor)
		if err != nil {
			return nil, err
		}
		_ = s.store.MarkKernelDiscoveryItemRegistered(context.Background(), item.ID, true)
		return kernel, nil
	}
	version := strings.TrimSpace(req.Version)
	if version == "" {
		return nil, Invalid("Kernel version is required", map[string]string{"version": "required"})
	}
	if !validFirecrackerKernelVersion(version) {
		return nil, Invalid("Kernel version is unsupported", map[string]string{"version": "use a Firecracker CI 5.10, 5.10-no-acpi, or 6.1 kernel"})
	}
	prefix, err := normalizeFirecrackerCIPrefix(req.CIPrefix)
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix, err = s.latestFirecrackerCIPrefix(ctx)
		if err != nil {
			return nil, err
		}
	}
	arch := hostArchitecture()
	kernelKey := prefix + arch + "/vmlinux-" + version
	configKey := kernelKey + ".config"
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = kernelCIName(version)
	}
	return s.importFirecrackerCIKernelByKeys(ctx, name, version, kernelKey, configKey, actor)
}

func (s *Service) importFirecrackerCIKernelByKeys(ctx context.Context, name, version, kernelKey, configKey, actor string) (*model.Kernel, error) {
	id := random.Hex(8)
	if name == "" {
		name = kernelCIName(version)
	}
	dir := filepath.Join(s.cfg.Paths.KernelDir, sanitizePathPart(name)+"-"+id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	kernelPath := filepath.Join(dir, "vmlinux-"+version)
	configPath := filepath.Join(dir, "vmlinux-"+version+".config")
	if err := s.downloadFirecrackerCIObject(ctx, kernelKey, kernelPath, s.cfg.Kernels.MaxKernelBytes); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if configKey == "" {
		configPath = ""
	} else if err := s.downloadFirecrackerCIObject(ctx, configKey, configPath, 4*1024*1024); err != nil {
		_ = os.Remove(configPath)
		configPath = ""
	}
	kernel, err := s.RegisterKernel(ctx, RegisterKernelRequest{
		Name:       name,
		Version:    version,
		Path:       kernelPath,
		ConfigPath: configPath,
		Status:     kernelStatusPending,
		BootArgs:   defaultKernelBootArgs,
		SourceType: kernelSourceFirecrackerCI,
		Provenance: s.firecrackerCIURL(kernelKey),
	}, actor)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return kernel, nil
}

func (s *Service) StartKernelDiscovery(ctx context.Context, req DiscoverFirecrackerCIKernelsRequest, actor string) (*model.KernelDiscoveryJob, error) {
	prefix, err := normalizeFirecrackerCIPrefix(req.CIPrefix)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	job := model.KernelDiscoveryJob{
		ID:           random.Hex(8),
		Status:       jobStatusQueued,
		SourceURL:    strings.TrimRight(s.cfg.Kernels.FirecrackerCIBaseURL, "/"),
		CIPrefix:     prefix,
		Architecture: hostArchitecture(),
		CreatedBy:    actor,
		CreatedAt:    now,
	}
	if err := s.store.CreateKernelDiscoveryJob(ctx, job); err != nil {
		return nil, err
	}
	go s.runKernelDiscovery(job.ID)
	return &job, nil
}

func (s *Service) runKernelDiscovery(jobID string) {
	s.kernelDiscoveryMu.Lock()
	defer s.kernelDiscoveryMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Kernels.CIScanTimeout.Duration)
	defer cancel()
	job, err := s.store.GetKernelDiscoveryJob(ctx, jobID)
	if err != nil || job == nil {
		return
	}
	started := time.Now().UTC()
	job.Status = jobStatusRunning
	job.StartedAt = &started
	_ = s.store.UpdateKernelDiscoveryJob(ctx, *job)
	err = s.executeKernelDiscovery(ctx, job)
	completed := time.Now().UTC()
	job.CompletedAt = &completed
	if err != nil {
		job.Status = jobStatusFailed
		job.Error = err.Error()
		_ = s.store.UpdateKernelDiscoveryJob(context.Background(), *job)
		return
	}
	job.Status = jobStatusSucceeded
	_ = s.store.UpdateKernelDiscoveryJob(context.Background(), *job)
}

func (s *Service) executeKernelDiscovery(ctx context.Context, job *model.KernelDiscoveryJob) error {
	prefix := strings.TrimSpace(job.CIPrefix)
	var err error
	if prefix == "" {
		prefix, err = s.latestFirecrackerCIPrefix(ctx)
		if err != nil {
			return err
		}
		job.CIPrefix = prefix
		if err := s.store.UpdateKernelDiscoveryJob(ctx, *job); err != nil {
			return err
		}
	}
	objectPrefix := prefix + job.Architecture + "/"
	keys, err := s.listFirecrackerCIKeys(ctx, objectPrefix)
	if err != nil {
		return err
	}
	items, err := s.discoveryItemsFromKeys(ctx, job.ID, prefix, job.Architecture, keys)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("no supported kernels found in %s for %s", prefix, job.Architecture)
	}
	job.ItemCount = len(items)
	if err := s.store.ReplaceKernelDiscoveryItems(ctx, job.ID, items); err != nil {
		return err
	}
	return nil
}

func (s *Service) discoveryItemsFromKeys(ctx context.Context, jobID, prefix, arch string, keys []string) ([]model.KernelDiscoveryItem, error) {
	kernels, err := s.store.ListKernels(ctx)
	if err != nil {
		return nil, err
	}
	registered := map[string]bool{}
	for _, kernel := range kernels {
		if strings.TrimSpace(kernel.Provenance) != "" {
			registered[kernel.Provenance] = true
		}
	}
	configs := map[string]string{}
	for _, key := range keys {
		if strings.HasSuffix(key, ".config") {
			configs[strings.TrimSuffix(key, ".config")] = key
		}
	}
	now := time.Now().UTC()
	items := []model.KernelDiscoveryItem{}
	seen := map[string]bool{}
	for _, key := range keys {
		if !supportedFirecrackerCIKernelKey(key) {
			continue
		}
		version := strings.TrimPrefix(filepath.Base(key), "vmlinux-")
		url := s.firecrackerCIURL(key)
		if seen[url] {
			continue
		}
		seen[url] = true
		configKey := configs[key]
		configURL := ""
		if configKey != "" {
			configURL = s.firecrackerCIURL(configKey)
		}
		items = append(items, model.KernelDiscoveryItem{
			ID:                random.Hex(8),
			JobID:             jobID,
			Version:           version,
			Variant:           kernelVariant(version),
			Architecture:      arch,
			CIPrefix:          prefix,
			KernelKey:         key,
			ConfigKey:         configKey,
			KernelURL:         url,
			ConfigURL:         configURL,
			AlreadyRegistered: registered[url],
			CreatedAt:         now,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return compareKernelVersions(items[i].Version, items[j].Version) > 0
	})
	return items, nil
}

func (s *Service) UpdateKernel(ctx context.Context, id string, req KernelUpdateRequest) (*model.Kernel, error) {
	kernel, err := s.store.GetKernel(ctx, id)
	if err != nil {
		return nil, err
	}
	if kernel == nil {
		return nil, NotFound("kernel not found")
	}
	if strings.TrimSpace(req.Name) != "" {
		if !nameRe.MatchString(strings.TrimSpace(req.Name)) {
			return nil, Invalid("Kernel name is invalid", map[string]string{"name": "must match " + nameRe.String()})
		}
		kernel.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.Status) != "" {
		if !validKernelStatus(strings.TrimSpace(req.Status)) {
			return nil, Invalid("Kernel status is invalid", map[string]string{"status": "must be pending, active, failed, or archived"})
		}
		kernel.Status = strings.TrimSpace(req.Status)
	}
	if strings.TrimSpace(req.BootArgs) != "" {
		kernel.BootArgs = strings.TrimSpace(req.BootArgs)
	}
	if err := s.store.UpdateKernel(ctx, *kernel); err != nil {
		return nil, err
	}
	return s.store.GetKernel(ctx, id)
}

func (s *Service) DeleteKernel(ctx context.Context, id string) error {
	kernel, err := s.store.GetKernel(ctx, id)
	if err != nil {
		return err
	}
	if kernel == nil {
		return NotFound("kernel not found")
	}
	if err := s.store.DeleteKernel(ctx, id); err != nil {
		return err
	}
	if kernel.SourceType != kernelSourceConfigured && kernel.Path != "" {
		if err := os.RemoveAll(filepath.Dir(kernel.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Service) StartKernelTest(ctx context.Context, kernelID, actor string) (*model.KernelTestJob, error) {
	kernel, err := s.store.GetKernel(ctx, kernelID)
	if err != nil {
		return nil, err
	}
	if kernel == nil {
		return nil, NotFound("kernel not found")
	}
	baseImage, err := s.store.DefaultBaseImage(ctx)
	if err != nil {
		return nil, err
	}
	if baseImage == nil {
		return nil, NotFound("base image not found")
	}
	now := time.Now().UTC()
	job := model.KernelTestJob{
		ID:          random.Hex(8),
		KernelID:    kernel.ID,
		Status:      jobStatusQueued,
		LogPath:     filepath.Join(s.cfg.Paths.LogDir, "kernel-test-"+random.Hex(8)+".log"),
		BaseImageID: baseImage.ID,
		CreatedBy:   actor,
		CreatedAt:   now,
	}
	if err := s.store.CreateKernelTestJob(ctx, job); err != nil {
		return nil, err
	}
	go s.runKernelTest(job.ID)
	return &job, nil
}

func (s *Service) runKernelTest(jobID string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Kernels.TestTimeout.Duration)
	defer cancel()
	job, err := s.store.GetKernelTestJob(ctx, jobID)
	if err != nil || job == nil {
		return
	}
	started := time.Now().UTC()
	job.Status = jobStatusRunning
	job.StartedAt = &started
	_ = s.store.UpdateKernelTestJob(ctx, *job)
	err = s.executeKernelTest(ctx, job)
	completed := time.Now().UTC()
	job.CompletedAt = &completed
	if err != nil {
		job.Status = jobStatusFailed
		job.Error = err.Error()
		if kernel, getErr := s.store.GetKernel(context.Background(), job.KernelID); getErr == nil && kernel != nil {
			kernel.Status = kernelStatusFailed
			_ = s.store.UpdateKernel(context.Background(), *kernel)
		}
		_ = s.store.UpdateKernelTestJob(context.Background(), *job)
		return
	}
	job.Status = jobStatusSucceeded
	_ = s.store.UpdateKernelTestJob(context.Background(), *job)
	if kernel, getErr := s.store.GetKernel(context.Background(), job.KernelID); getErr == nil && kernel != nil {
		kernel.Status = kernelStatusActive
		kernel.LastTestedAt = &completed
		_ = s.store.UpdateKernel(context.Background(), *kernel)
	}
}

func (s *Service) executeKernelTest(ctx context.Context, job *model.KernelTestJob) error {
	if err := os.MkdirAll(filepath.Dir(job.LogPath), 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(job.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logf := func(format string, args ...any) {
		_, _ = fmt.Fprintf(logFile, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", args...)
	}
	kernel, err := s.store.GetKernel(ctx, job.KernelID)
	if err != nil {
		return err
	}
	if kernel == nil {
		return NotFound("kernel not found")
	}
	baseImage, err := s.store.GetBaseImage(ctx, job.BaseImageID)
	if err != nil {
		return err
	}
	if baseImage == nil {
		return NotFound("base image not found")
	}
	key, err := sshkeys.Generate("kernel-test-"+job.ID, "kernel-test")
	if err != nil {
		return err
	}
	name := "kt" + job.ID[:10]
	logf("creating test VM %s using kernel %s", name, kernel.Name)
	vm, err := s.CreateVM(ctx, CreateRequest{
		Name:                name,
		VCPUCount:           1,
		MemMiB:              512,
		DevUser:             "dev",
		ExtraAuthorizedKeys: key.Key.PublicKey,
		GitRef:              "HEAD",
		EgressMode:          "allow_all",
		NetworkMode:         "routed_ptp",
		BaseImageID:         baseImage.ID,
		RootFSSizeMiB:       baseImage.VirtualSizeMiB,
		KernelID:            kernel.ID,
		AllowPendingKernel:  true,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := s.DeleteVM(context.Background(), vm.ID); err != nil {
			logf("cleanup failed: %v", err)
		}
	}()
	logf("starting test VM %s", vm.ID)
	if err := s.StartVM(ctx, vm.ID); err != nil {
		return err
	}
	privatePath := filepath.Join(s.cfg.Paths.RuntimeDir, "kernel-test-"+job.ID)
	if err := os.WriteFile(privatePath, []byte(key.PrivateKey), 0o600); err != nil {
		return err
	}
	defer os.Remove(privatePath)
	out, err := waitForKernelTestSSH(ctx, privatePath, vm.DevUser, vm.GuestIP, vm.HostIP)
	if err != nil {
		return err
	}
	job.UnameResult = model.CleanKernelTestOutput(out)
	_ = s.store.UpdateKernelTestJob(context.Background(), *job)
	logf("test command output: %s", strings.TrimSpace(out))
	return nil
}

func (s *Service) resolveKernelForVM(ctx context.Context, requestedID string, allowPending bool) (*model.Kernel, error) {
	var kernel *model.Kernel
	var err error
	if requestedID != "" {
		kernel, err = s.store.GetKernel(ctx, requestedID)
	} else {
		kernel, err = s.store.DefaultKernel(ctx)
	}
	if err != nil {
		return nil, err
	}
	if kernel == nil {
		return nil, NotFound("kernel not found")
	}
	if kernel.Status != kernelStatusActive && !(allowPending && (kernel.Status == kernelStatusPending || kernel.Status == kernelStatusFailed)) {
		return nil, Unprocessable("Kernel is not active", map[string]string{"kernel_id": "select an active tested kernel"})
	}
	if err := requireFile(kernel.Path); err != nil {
		return nil, Invalid("Kernel file is unavailable", map[string]string{"kernel_id": err.Error()})
	}
	return kernel, nil
}

func (s *Service) bootArgsForVM(ctx context.Context, vm *model.VM) string {
	if vm.KernelID != "" {
		if kernel, err := s.store.GetKernel(ctx, vm.KernelID); err == nil && kernel != nil && strings.TrimSpace(kernel.BootArgs) != "" {
			return kernel.BootArgs
		}
	}
	return defaultKernelBootArgs
}

func (s *Service) validateKernelPath(path string) (string, error) {
	clean, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	base, err := filepath.EvalSymlinks(s.cfg.Paths.KernelDir)
	if err != nil {
		return "", err
	}
	if !pathWithin(clean, base) {
		return "", fmt.Errorf("must be inside %s", base)
	}
	return clean, nil
}

func (s *Service) validateKernelFile(ctx context.Context, path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Size() <= 0 || st.Size() > s.cfg.Kernels.MaxKernelBytes {
		return Invalid("Kernel size is invalid", map[string]string{"kernel": fmt.Sprintf("must be between 1 and %d bytes", s.cfg.Kernels.MaxKernelBytes)})
	}
	arch := detectKernelArchitecture(ctx, path)
	if arch == "" {
		return Invalid("Kernel architecture could not be detected", map[string]string{"kernel": "must be an uncompressed x86_64 or aarch64 kernel image"})
	}
	if arch != hostArchitecture() {
		return Invalid("Kernel architecture does not match host", map[string]string{"kernel": "expected " + hostArchitecture() + ", got " + arch})
	}
	return nil
}

func detectKernelArchitecture(ctx context.Context, path string) string {
	out, err := exec.CommandContext(ctx, "file", "-b", path).Output()
	if err != nil {
		return ""
	}
	text := strings.ToLower(string(out))
	switch {
	case strings.Contains(text, "x86-64") || strings.Contains(text, "x86_64"):
		return "x86_64"
	case strings.Contains(text, "aarch64") || strings.Contains(text, "arm64"):
		return "aarch64"
	default:
		return ""
	}
}

func hostArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func validKernelStatus(status string) bool {
	switch status {
	case kernelStatusPending, kernelStatusActive, kernelStatusFailed, kernelStatusArchived:
		return true
	default:
		return false
	}
}

func validFirecrackerKernelVersion(version string) bool {
	if strings.Contains(version, "/") || strings.Contains(version, "\\") || strings.Contains(version, "..") {
		return false
	}
	if strings.HasSuffix(version, "-no-acpi") {
		base := strings.TrimSuffix(version, "-no-acpi")
		return validKernelVersionNumbers(base, 5, 10)
	}
	return validKernelVersionNumbers(version, 5, 10) || validKernelVersionNumbers(version, 6, 1)
}

func validKernelVersionNumbers(version string, major, minor int) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	gotMajor, err := strconv.Atoi(parts[0])
	if err != nil || gotMajor != major {
		return false
	}
	gotMinor, err := strconv.Atoi(parts[1])
	if err != nil || gotMinor != minor {
		return false
	}
	patch, err := strconv.Atoi(parts[2])
	return err == nil && patch >= 0
}

func supportedFirecrackerCIKernelKey(key string) bool {
	if strings.Contains(key, "/debug/") || strings.HasSuffix(key, ".config") || strings.HasSuffix(key, ".gz") {
		return false
	}
	base := filepath.Base(key)
	if !strings.HasPrefix(base, "vmlinux-") {
		return false
	}
	return validFirecrackerKernelVersion(strings.TrimPrefix(base, "vmlinux-"))
}

func kernelVariant(version string) string {
	if strings.HasSuffix(version, "-no-acpi") {
		return "no-acpi"
	}
	return "standard"
}

func compareKernelVersions(a, b string) int {
	majorA, minorA, patchA, noACPIA := parseKernelVersionRank(a)
	majorB, minorB, patchB, noACPIB := parseKernelVersionRank(b)
	for _, pair := range [][2]int{{majorA, majorB}, {minorA, minorB}, {patchA, patchB}} {
		if pair[0] > pair[1] {
			return 1
		}
		if pair[0] < pair[1] {
			return -1
		}
	}
	if noACPIA == noACPIB {
		return strings.Compare(a, b)
	}
	if !noACPIA && noACPIB {
		return 1
	}
	return -1
}

func parseKernelVersionRank(version string) (int, int, int, bool) {
	noACPI := strings.HasSuffix(version, "-no-acpi")
	version = strings.TrimSuffix(version, "-no-acpi")
	parts := strings.Split(version, ".")
	nums := []int{0, 0, 0}
	for i := 0; i < len(parts) && i < len(nums); i++ {
		n, _ := strconv.Atoi(parts[i])
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], noACPI
}

func kernelCIName(version string) string {
	return "fc-" + strings.ReplaceAll(strings.TrimSuffix(version, "-no-acpi"), ".", "-") + strings.TrimPrefix(version, strings.TrimSuffix(version, "-no-acpi"))
}

func inferKernelVersion(path string) string {
	base := filepath.Base(path)
	base = strings.TrimPrefix(base, "vmlinux-")
	base = strings.TrimSuffix(base, ".bin")
	if base == "" || base == filepath.Base(path) {
		return ""
	}
	return base
}

func sanitizePathPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "kernel"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	clean := strings.Trim(b.String(), ".-")
	if clean == "" {
		return "kernel"
	}
	return clean
}

func normalizeFirecrackerCIPrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", nil
	}
	if !strings.HasPrefix(prefix, "firecracker-ci/") || strings.Contains(prefix, "..") {
		return "", Invalid("CI prefix is invalid", map[string]string{"ci_prefix": "must be a firecracker-ci prefix"})
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix, nil
}

func cleanKernelFilename(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == "/" || name == "" {
		return ""
	}
	return sanitizePathPart(name)
}

func writeLimitedFile(path string, r io.Reader, limit int64, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("file exceeds %d bytes", limit)
	}
	return nil
}

func (s *Service) latestFirecrackerCIPrefix(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Kernels.FirecrackerCIBaseURL+"?list-type=2&prefix=firecracker-ci/&delimiter=/", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Firecracker CI listing returned %s", resp.Status)
	}
	var result s3ListBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	var prefixes []string
	for _, prefix := range result.CommonPrefixes {
		if _, _, ok := firecrackerReleasePrefixVersion(prefix.Prefix); ok {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}
	if len(prefixes) == 0 {
		return "", fmt.Errorf("no stable Firecracker CI release prefixes found")
	}
	sort.Slice(prefixes, func(i, j int) bool {
		majorI, minorI, _ := firecrackerReleasePrefixVersion(prefixes[i])
		majorJ, minorJ, _ := firecrackerReleasePrefixVersion(prefixes[j])
		if majorI != majorJ {
			return majorI < majorJ
		}
		return minorI < minorJ
	})
	return prefixes[len(prefixes)-1], nil
}

func (s *Service) listFirecrackerCIKeys(ctx context.Context, prefix string) ([]string, error) {
	token := ""
	keys := []string{}
	for {
		u, err := url.Parse(strings.TrimRight(s.cfg.Kernels.FirecrackerCIBaseURL, "/"))
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("list-type", "2")
		q.Set("prefix", prefix)
		if token != "" {
			q.Set("continuation-token", token)
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("Firecracker CI object listing returned %s", resp.Status)
		}
		var result s3ListBucketResult
		err = xml.NewDecoder(resp.Body).Decode(&result)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, content := range result.Contents {
			if content.Key != "" {
				keys = append(keys, content.Key)
			}
		}
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return keys, nil
		}
		token = result.NextContinuationToken
	}
}

func firecrackerReleasePrefixVersion(prefix string) (int, int, bool) {
	name := strings.TrimSuffix(strings.TrimPrefix(prefix, "firecracker-ci/"), "/")
	if !strings.HasPrefix(name, "v") {
		return 0, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(name, "v"), ".")
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func (s *Service) firecrackerCIURL(key string) string {
	return strings.TrimRight(s.cfg.Kernels.FirecrackerCIBaseURL, "/") + "/" + key
}

func (s *Service) findKernelByProvenance(ctx context.Context, provenance string) (*model.Kernel, error) {
	kernels, err := s.store.ListKernels(ctx)
	if err != nil {
		return nil, err
	}
	for _, kernel := range kernels {
		if kernel.Provenance == provenance {
			return &kernel, nil
		}
	}
	return nil, nil
}

func (s *Service) downloadFirecrackerCIObject(ctx context.Context, key, dst string, limit int64) error {
	parsed, err := url.Parse(s.firecrackerCIURL(key))
	if err != nil {
		return err
	}
	base, err := url.Parse(strings.TrimRight(s.cfg.Kernels.FirecrackerCIBaseURL, "/"))
	if err != nil {
		return err
	}
	if parsed.Scheme != base.Scheme || parsed.Host != base.Host || parsed.Scheme == "" || parsed.Host == "" {
		return Invalid("Firecracker CI URL is invalid", map[string]string{"ci_prefix": "must resolve under configured Firecracker CI base URL"})
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return Invalid("Firecracker CI URL is invalid", map[string]string{"ci_prefix": "must use https unless testing against localhost"})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s returned %s", key, resp.Status)
	}
	if err := writeLimitedFile(dst, resp.Body, limit, 0o600); err != nil {
		return err
	}
	sum, err := sha256File(dst)
	if err != nil {
		return err
	}
	_ = sum
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func waitForKernelTestSSH(ctx context.Context, privateKeyPath, user, guestIP, hostIP string) (string, error) {
	deadline := time.Now().Add(90 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(ctx, "ssh",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
			"-o", "ConnectTimeout=3",
			"-i", privateKeyPath,
			user+"@"+guestIP,
			"uname -r; ping -c 1 -W 2 "+hostIP+" >/dev/null && echo gateway-ok",
		)
		out, err := cmd.CombinedOutput()
		last = strings.TrimSpace(string(out))
		if err == nil {
			return model.CleanKernelTestOutput(last), nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if last != "" {
		return "", fmt.Errorf("SSH smoke did not succeed: %s", last)
	}
	return "", fmt.Errorf("SSH smoke did not succeed")
}
