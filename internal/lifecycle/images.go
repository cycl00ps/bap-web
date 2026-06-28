package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"bap-web/internal/model"
	"bap-web/internal/random"
)

const (
	imageStatusActive     = "active"
	imageStatusDeprecated = "deprecated"
	imageStatusArchived   = "archived"

	jobStatusQueued    = "queued"
	jobStatusRunning   = "running"
	jobStatusSucceeded = "succeeded"
	jobStatusFailed    = "failed"

	hookStatusActive = "active"
)

var packageNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+:-]{0,127}$`)

type RegisterBaseImageRequest struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Status     string `json:"status"`
	Filesystem string `json:"filesystem"`
	Provenance string `json:"provenance"`
}

type BuildBaseImageRequest struct {
	Name       string   `json:"name"`
	Filesystem string   `json:"filesystem"`
	SizeMiB    int      `json:"size_mib"`
	Packages   []string `json:"packages"`
	HookIDs    []string `json:"hook_ids"`
}

type ImageHookRequest struct {
	Name       string `json:"name"`
	SourceType string `json:"source_type"`
	Content    string `json:"content"`
	GitURL     string `json:"git_url"`
	GitRef     string `json:"git_ref"`
	GitPath    string `json:"git_path"`
}

func (s *Service) EnsureDefaultBaseImage(ctx context.Context) error {
	if strings.TrimSpace(s.cfg.Paths.BaseRootFS) == "" {
		return nil
	}
	if _, err := os.Stat(s.cfg.Paths.BaseRootFS); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	existing, err := s.store.GetBaseImageByPath(ctx, s.cfg.Paths.BaseRootFS)
	if err != nil || existing != nil {
		return err
	}
	_, err = s.RegisterBaseImage(ctx, RegisterBaseImageRequest{
		Name:       "default-base-rootfs",
		Path:       s.cfg.Paths.BaseRootFS,
		Status:     imageStatusActive,
		Provenance: "configured paths.base_rootfs",
	}, "system")
	return err
}

func (s *Service) RegisterBaseImage(ctx context.Context, req RegisterBaseImageRequest, actor string) (*model.BaseImage, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !nameRe.MatchString(req.Name) {
		return nil, Invalid("Base image name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	path, err := s.validateImagePath(req.Path)
	if err != nil {
		return nil, Invalid("Base image path is invalid", map[string]string{"path": err.Error()})
	}
	if err := requireFile(path); err != nil {
		return nil, Invalid("Base image path is invalid", map[string]string{"path": err.Error()})
	}
	if err := secureExistingPath(path); err != nil {
		return nil, Invalid("Base image path is unsafe", map[string]string{"path": err.Error()})
	}
	fs := strings.TrimSpace(req.Filesystem)
	if fs == "" {
		fs = detectFilesystem(ctx, path)
	}
	if fs == "" {
		fs = "unknown"
	}
	if fs != "unknown" && fs != "ext4" && fs != "xfs" {
		return nil, Invalid("Base image filesystem is unsupported", map[string]string{"filesystem": "must be ext4, xfs, or unknown"})
	}
	status := defaultImageString(strings.TrimSpace(req.Status), imageStatusActive)
	if !validImageStatus(status) {
		return nil, Invalid("Base image status is invalid", map[string]string{"status": "must be active, deprecated, or archived"})
	}
	virtualMiB, diskBytes, err := imageSizes(path)
	if err != nil {
		return nil, err
	}
	if virtualMiB <= 0 || virtualMiB > s.cfg.Images.MaxBaseImageMiB {
		return nil, Invalid("Base image size is invalid", map[string]string{"path": fmt.Sprintf("virtual size must be between 1 and %d MiB", s.cfg.Images.MaxBaseImageMiB)})
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	image := model.BaseImage{
		ID:             random.Hex(8),
		Name:           req.Name,
		Status:         status,
		Filesystem:     fs,
		Path:           path,
		VirtualSizeMiB: virtualMiB,
		DiskSizeBytes:  diskBytes,
		Checksum:       sum,
		Provenance:     strings.TrimSpace(req.Provenance),
		CreatedBy:      actor,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.store.CreateBaseImage(ctx, image); err != nil {
		return nil, err
	}
	return &image, nil
}

func (s *Service) UpdateBaseImageStatus(ctx context.Context, id, status string) (*model.BaseImage, error) {
	image, err := s.store.GetBaseImage(ctx, id)
	if err != nil {
		return nil, err
	}
	if image == nil {
		return nil, NotFound("base image not found")
	}
	status = strings.TrimSpace(status)
	if !validImageStatus(status) {
		return nil, Invalid("Base image status is invalid", map[string]string{"status": "must be active, deprecated, or archived"})
	}
	image.Status = status
	if err := s.store.UpdateBaseImage(ctx, *image); err != nil {
		return nil, err
	}
	return s.store.GetBaseImage(ctx, id)
}

func (s *Service) DeleteBaseImage(ctx context.Context, id string) error {
	image, err := s.store.GetBaseImage(ctx, id)
	if err != nil {
		return err
	}
	if image == nil {
		return NotFound("base image not found")
	}
	if err := s.store.DeleteBaseImage(ctx, id); err != nil {
		return err
	}
	if strings.HasPrefix(image.Provenance, "managed build job ") && image.Path != "" {
		if err := os.Remove(image.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Remove(filepath.Dir(image.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Service) CreateImageHook(ctx context.Context, req ImageHookRequest, actor string) (*model.ImageHook, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !nameRe.MatchString(req.Name) {
		return nil, Invalid("Image hook name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	sourceType := strings.TrimSpace(req.SourceType)
	if sourceType == "" {
		sourceType = "upload"
	}
	now := time.Now().UTC()
	hook := model.ImageHook{
		ID:         random.Hex(8),
		Name:       req.Name,
		SourceType: sourceType,
		Status:     hookStatusActive,
		CreatedBy:  actor,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	switch sourceType {
	case "upload":
		content := strings.TrimSpace(req.Content)
		if content == "" {
			return nil, Invalid("Image hook content is required", map[string]string{"content": "required"})
		}
		if int64(len(content)) > s.cfg.Images.MaxHookBytes {
			return nil, Invalid("Image hook is too large", map[string]string{"content": fmt.Sprintf("must be at most %d bytes", s.cfg.Images.MaxHookBytes)})
		}
		if err := os.MkdirAll(s.cfg.Images.HookDir, 0o700); err != nil {
			return nil, err
		}
		path := filepath.Join(s.cfg.Images.HookDir, hook.ID+".sh")
		if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
			return nil, err
		}
		hook.ContentPath = path
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		hook.Checksum = sum
	case "git":
		if err := s.validateGitHook(req); err != nil {
			return nil, err
		}
		hook.GitURL = strings.TrimSpace(req.GitURL)
		hook.GitRef = defaultImageString(strings.TrimSpace(req.GitRef), "HEAD")
		hook.GitPath = cleanRelativePath(req.GitPath)
	default:
		return nil, Invalid("Image hook source_type is invalid", map[string]string{"source_type": "must be upload or git"})
	}
	if err := s.store.CreateImageHook(ctx, hook); err != nil {
		return nil, err
	}
	return &hook, nil
}

func (s *Service) DeleteImageHook(ctx context.Context, id string) error {
	hook, err := s.store.GetImageHook(ctx, id)
	if err != nil {
		return err
	}
	if hook == nil {
		return NotFound("image hook not found")
	}
	if hook.ContentPath != "" {
		_ = os.Remove(hook.ContentPath)
	}
	return s.store.DeleteImageHook(ctx, id)
}

func (s *Service) StartImageBuild(ctx context.Context, req BuildBaseImageRequest, actor string) (*model.ImageBuildJob, error) {
	req.Name = strings.TrimSpace(req.Name)
	if !nameRe.MatchString(req.Name) {
		return nil, Invalid("Base image name is invalid", map[string]string{"name": "must match " + nameRe.String()})
	}
	fs := strings.TrimSpace(req.Filesystem)
	if fs == "" {
		fs = "ext4"
	}
	if fs != "ext4" && fs != "xfs" {
		return nil, Invalid("Filesystem is unsupported", map[string]string{"filesystem": "must be ext4 or xfs"})
	}
	if req.SizeMiB <= 0 || req.SizeMiB > s.cfg.Images.MaxBaseImageMiB {
		return nil, Invalid("Base image size is invalid", map[string]string{"size_mib": fmt.Sprintf("must be between 1 and %d", s.cfg.Images.MaxBaseImageMiB)})
	}
	packages, err := normalizePackages(req.Packages, s.cfg.Images.MaxPackages)
	if err != nil {
		return nil, err
	}
	hooks, err := s.loadHooks(ctx, req.HookIDs)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.cfg.Images.BuildDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.cfg.Paths.LogDir, 0o700); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	job := model.ImageBuildJob{
		ID:         random.Hex(8),
		Status:     jobStatusQueued,
		Name:       req.Name,
		Filesystem: fs,
		SizeMiB:    req.SizeMiB,
		Packages:   strings.Join(packages, ","),
		Hooks:      strings.Join(req.HookIDs, ","),
		LogPath:    filepath.Join(s.cfg.Paths.LogDir, "image-build-"+random.Hex(8)+".log"),
		CreatedBy:  actor,
		CreatedAt:  now,
	}
	if err := s.store.CreateImageBuildJob(ctx, job); err != nil {
		return nil, err
	}
	go s.runImageBuild(job.ID, packages, hooks)
	return &job, nil
}

func (s *Service) runImageBuild(jobID string, packages []string, hooks []model.ImageHook) {
	s.imageBuildMu.Lock()
	defer s.imageBuildMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Images.BuildTimeout.Duration)
	defer cancel()
	job, err := s.store.GetImageBuildJob(ctx, jobID)
	if err != nil || job == nil {
		return
	}
	started := time.Now().UTC()
	job.Status = jobStatusRunning
	job.StartedAt = &started
	_ = s.store.UpdateImageBuildJob(ctx, *job)
	err = s.buildBaseImage(ctx, job, packages, hooks)
	completed := time.Now().UTC()
	job.CompletedAt = &completed
	if err != nil {
		job.Status = jobStatusFailed
		job.Error = err.Error()
		_ = s.store.UpdateImageBuildJob(context.Background(), *job)
		return
	}
	job.Status = jobStatusSucceeded
	_ = s.store.UpdateImageBuildJob(context.Background(), *job)
}

func (s *Service) buildBaseImage(ctx context.Context, job *model.ImageBuildJob, packages []string, hooks []model.ImageHook) error {
	logFile, err := os.OpenFile(job.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logf := func(format string, args ...any) {
		_, _ = fmt.Fprintf(logFile, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", args...)
	}
	buildRoot := filepath.Join(s.cfg.Images.BuildDir, job.ID)
	mountRoot := filepath.Join(buildRoot, "mnt")
	imageDir := filepath.Join(s.cfg.Paths.BaseImageDir, job.Name+"-"+job.ID)
	ext := ".ext4"
	if job.Filesystem == "xfs" {
		ext = ".xfs"
	}
	imagePath := filepath.Join(imageDir, "rootfs"+ext)
	if err := os.MkdirAll(mountRoot, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(imageDir, 0o700); err != nil {
		return err
	}
	mounted := false
	devBinds := []string{}
	pseudoMounts := []string{}
	cleanup := func() {
		for i := len(devBinds) - 1; i >= 0; i-- {
			_ = run(context.Background(), "umount", devBinds[i])
		}
		for i := len(pseudoMounts) - 1; i >= 0; i-- {
			_ = run(context.Background(), "umount", pseudoMounts[i])
		}
		if mounted {
			_ = run(context.Background(), "umount", mountRoot)
		}
		_ = os.RemoveAll(buildRoot)
	}
	defer cleanup()
	logf("creating sparse %s image at %s", job.Filesystem, imagePath)
	f, err := os.OpenFile(imagePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(int64(job.SizeMiB) * 1024 * 1024); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if job.Filesystem == "xfs" {
		if err := runLogged(ctx, logFile, "mkfs.xfs", "-f", imagePath); err != nil {
			return err
		}
	} else if err := runLogged(ctx, logFile, "mkfs.ext4", "-q", imagePath); err != nil {
		return err
	}
	if err := runLogged(ctx, logFile, "mount", "-o", "loop", imagePath, mountRoot); err != nil {
		return err
	}
	mounted = true
	args := []string{"install", "--installroot=" + mountRoot, "--releasever=10", "--setopt=install_weak_deps=False", "-y"}
	args = append(args, baseRootFSPackages()...)
	args = append(args, packages...)
	logf("installing packages")
	if err := runLogged(ctx, logFile, "dnf", args...); err != nil {
		return err
	}
	if binds, err := bindMinimalDevices(ctx, mountRoot); err != nil {
		return err
	} else {
		devBinds = binds
	}
	if mounts, err := mountBuildPseudoFilesystems(ctx, mountRoot); err != nil {
		return err
	} else {
		pseudoMounts = mounts
	}
	if err := writeAndRunChrootScript(ctx, logFile, mountRoot, "bap-image-configure.sh", baseConfigureScript()); err != nil {
		return err
	}
	for _, hook := range hooks {
		if err := s.runBuildHook(ctx, logFile, mountRoot, buildRoot, hook); err != nil {
			return err
		}
		now := time.Now().UTC()
		hook.LastUsedAt = &now
		_ = s.store.UpdateImageHook(context.Background(), hook)
	}
	logf("cleaning package cache")
	_ = runLogged(ctx, logFile, "dnf", "--installroot="+mountRoot, "clean", "all")
	for i := len(devBinds) - 1; i >= 0; i-- {
		_ = run(context.Background(), "umount", devBinds[i])
	}
	devBinds = nil
	for i := len(pseudoMounts) - 1; i >= 0; i-- {
		_ = run(context.Background(), "umount", pseudoMounts[i])
	}
	pseudoMounts = nil
	if err := runLogged(ctx, logFile, "umount", mountRoot); err != nil {
		return err
	}
	mounted = false
	sum, err := fileSHA256(imagePath)
	if err != nil {
		return err
	}
	virtualMiB, diskBytes, err := imageSizes(imagePath)
	if err != nil {
		return err
	}
	image := model.BaseImage{
		ID:             random.Hex(8),
		Name:           job.Name,
		Status:         imageStatusActive,
		Filesystem:     job.Filesystem,
		Path:           imagePath,
		VirtualSizeMiB: virtualMiB,
		DiskSizeBytes:  diskBytes,
		Checksum:       sum,
		Packages:       job.Packages,
		Hooks:          job.Hooks,
		Provenance:     "managed build job " + job.ID,
		CreatedBy:      job.CreatedBy,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := s.store.CreateBaseImage(context.Background(), image); err != nil {
		return err
	}
	job.ResultImageID = image.ID
	logf("image created: %s checksum=%s", image.Path, image.Checksum)
	return nil
}

func (s *Service) runBuildHook(ctx context.Context, logFile *os.File, mountRoot, buildRoot string, hook model.ImageHook) error {
	switch hook.SourceType {
	case "upload":
		if hook.ContentPath == "" {
			return fmt.Errorf("hook %s has no content path", hook.Name)
		}
		content, err := os.ReadFile(hook.ContentPath)
		if err != nil {
			return err
		}
		return writeAndRunChrootScript(ctx, logFile, mountRoot, hook.ID+".sh", string(content))
	case "git":
		repoDir := filepath.Join(buildRoot, "git-"+hook.ID)
		if err := runLogged(ctx, logFile, "git", "clone", "--depth", "1", "--branch", hook.GitRef, hook.GitURL, repoDir); err != nil {
			_ = os.RemoveAll(repoDir)
			if cloneErr := runLogged(ctx, logFile, "git", "clone", hook.GitURL, repoDir); cloneErr != nil {
				return fmt.Errorf("clone hook repository: %w", cloneErr)
			}
			if checkoutErr := runLogged(ctx, logFile, "git", "-C", repoDir, "checkout", hook.GitRef); checkoutErr != nil {
				return fmt.Errorf("checkout hook ref: %w", checkoutErr)
			}
		}
		commitOut, _ := exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "HEAD").Output()
		hook.ResolvedCommit = strings.TrimSpace(string(commitOut))
		hostHookPath := filepath.Join(repoDir, hook.GitPath)
		cleanRepo, _ := filepath.EvalSymlinks(repoDir)
		cleanHook, err := filepath.EvalSymlinks(hostHookPath)
		if err != nil {
			return err
		}
		if !pathWithin(cleanHook, cleanRepo) {
			return fmt.Errorf("git hook path escapes repository")
		}
		sum, err := fileSHA256(cleanHook)
		if err != nil {
			return err
		}
		hook.Checksum = sum
		_ = s.store.UpdateImageHook(context.Background(), hook)
		content, err := os.ReadFile(cleanHook)
		if err != nil {
			return err
		}
		if int64(len(content)) > s.cfg.Images.MaxHookBytes {
			return Invalid("Image hook is too large", map[string]string{"hook_ids": fmt.Sprintf("hook %s exceeds %d bytes", hook.Name, s.cfg.Images.MaxHookBytes)})
		}
		return writeAndRunChrootScript(ctx, logFile, mountRoot, hook.ID+".sh", string(content))
	default:
		return fmt.Errorf("unsupported hook source_type %q", hook.SourceType)
	}
}

func (s *Service) loadHooks(ctx context.Context, ids []string) ([]model.ImageHook, error) {
	out := []model.ImageHook{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		hook, err := s.store.GetImageHook(ctx, id)
		if err != nil {
			return nil, err
		}
		if hook == nil {
			return nil, NotFound("image hook not found")
		}
		if hook.Status != hookStatusActive {
			return nil, Unprocessable("Image hook is not active", map[string]string{"hook_ids": "remove inactive hook " + hook.Name})
		}
		out = append(out, *hook)
	}
	return out, nil
}

func (s *Service) validateGitHook(req ImageHookRequest) error {
	parsed, err := url.Parse(strings.TrimSpace(req.GitURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return Invalid("Git URL is invalid", map[string]string{"git_url": "must be an absolute http(s) URL"})
	}
	if parsed.User != nil {
		return Invalid("Git URL credentials are not supported", map[string]string{"git_url": "must not include credentials"})
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return Invalid("Git URL scheme is unsupported", map[string]string{"git_url": "must use https or http"})
	}
	if len(s.cfg.Images.AllowedGitHosts) > 0 {
		allowed := false
		for _, host := range s.cfg.Images.AllowedGitHosts {
			if strings.EqualFold(parsed.Hostname(), host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Invalid("Git host is not allowed", map[string]string{"git_url": "host is not in allowed_git_hosts"})
		}
	}
	if cleanRelativePath(req.GitPath) == "" {
		return Invalid("Git hook path is invalid", map[string]string{"git_path": "required"})
	}
	return nil
}

func (s *Service) validateImagePath(path string) (string, error) {
	clean, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	base, err := filepath.EvalSymlinks(s.cfg.Paths.BaseImageDir)
	if err != nil {
		return "", err
	}
	if !pathWithin(clean, base) {
		return "", fmt.Errorf("must be inside %s", base)
	}
	return clean, nil
}

func validImageStatus(status string) bool {
	switch status {
	case imageStatusActive, imageStatusDeprecated, imageStatusArchived:
		return true
	default:
		return false
	}
}

func defaultImageString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func normalizePackages(packages []string, limit int) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, pkg := range packages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if !packageNameRe.MatchString(pkg) {
			return nil, Invalid("Package name is invalid", map[string]string{"packages": "invalid package " + pkg})
		}
		if !seen[pkg] {
			out = append(out, pkg)
			seen[pkg] = true
		}
	}
	if len(out) > limit {
		return nil, Invalid("Too many packages requested", map[string]string{"packages": fmt.Sprintf("must include at most %d packages", limit)})
	}
	return out, nil
}

func fileSHA256(path string) (string, error) {
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

func imageSizes(path string) (int, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	virtualMiB := int((st.Size() + 1024*1024 - 1) / (1024 * 1024))
	diskBytes := st.Size()
	if stat, ok := st.Sys().(*syscall.Stat_t); ok && stat.Blocks > 0 {
		diskBytes = stat.Blocks * 512
	}
	return virtualMiB, diskBytes, nil
}

func detectFilesystem(ctx context.Context, path string) string {
	out, err := exec.CommandContext(ctx, "blkid", "-o", "value", "-s", "TYPE", path).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func secureExistingPath(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode()&0o002 != 0 {
		return fmt.Errorf("file must not be world-writable")
	}
	dir := filepath.Dir(path)
	for {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if info.Mode()&0o002 != 0 {
			return fmt.Errorf("directory %s must not be world-writable", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func pathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func cleanRelativePath(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || filepath.IsAbs(path) || strings.HasPrefix(path, ".."+string(filepath.Separator)) || path == ".." {
		return ""
	}
	return path
}

func runLogged(ctx context.Context, logFile *os.File, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(logFile, "%s %s failed: %v\n", name, strings.Join(redactArgs(args), " "), err)
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func redactArgs(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
			out[i] = "[redacted]"
		} else {
			out[i] = arg
		}
	}
	return out
}

func bindMinimalDevices(ctx context.Context, mountRoot string) ([]string, error) {
	devDir := filepath.Join(mountRoot, "dev")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		return nil, err
	}
	devices := []string{"null", "zero", "random", "urandom"}
	mounts := []string{}
	for _, dev := range devices {
		target := filepath.Join(devDir, dev)
		if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				return mounts, err
			}
		}
		if err := run(ctx, "mount", "--bind", filepath.Join("/dev", dev), target); err != nil {
			return mounts, err
		}
		mounts = append(mounts, target)
	}
	return mounts, nil
}

func mountBuildPseudoFilesystems(ctx context.Context, mountRoot string) ([]string, error) {
	mounts := []struct {
		fsType string
		source string
		target string
	}{
		{fsType: "proc", source: "proc", target: "proc"},
		{fsType: "sysfs", source: "sysfs", target: "sys"},
	}
	mounted := []string{}
	for _, mount := range mounts {
		target := filepath.Join(mountRoot, mount.target)
		if err := os.MkdirAll(target, 0o755); err != nil {
			for i := len(mounted) - 1; i >= 0; i-- {
				_ = run(context.Background(), "umount", mounted[i])
			}
			return mounted, err
		}
		if err := run(ctx, "mount", "-t", mount.fsType, mount.source, target); err != nil {
			for i := len(mounted) - 1; i >= 0; i-- {
				_ = run(context.Background(), "umount", mounted[i])
			}
			return mounted, err
		}
		mounted = append(mounted, target)
	}
	return mounted, nil
}

func writeAndRunChrootScript(ctx context.Context, logFile *os.File, mountRoot, name, content string) error {
	target := filepath.Join(mountRoot, "tmp", name)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if int64(len(content)) > 1024*1024 {
		return fmt.Errorf("script %s is too large", name)
	}
	if err := os.WriteFile(target, []byte(content), 0o700); err != nil {
		return err
	}
	return runLogged(ctx, logFile, "chroot", mountRoot, "/bin/bash", "/tmp/"+name)
}

func baseRootFSPackages() []string {
	return []string{
		"almalinux-release", "systemd", "openssh-server", "iproute", "iputils", "sudo", "bash",
		"coreutils", "procps-ng", "passwd", "vim", "tar", "libstdc++", "curl", "git", "NetworkManager",
	}
}

func baseConfigureScript() string {
	return `set -euo pipefail
useradd -m -s /bin/bash dev 2>/dev/null || true
usermod -aG wheel dev
passwd -l root || true
mkdir -p /etc/sudoers.d /etc/bootstrap.d /etc/NetworkManager/system-connections
echo '%wheel ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/wheel
chmod 0440 /etc/sudoers.d/wheel
sed -i -e 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' -e 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
cat >/usr/local/sbin/project-bootstrap.sh <<'BOOT'
#!/usr/bin/env bash
set -euo pipefail
SENTINEL="/var/lib/first-run.done"
[[ -f "$SENTINEL" ]] && exit 0
[[ -f /etc/project.env ]] || { echo "Missing /etc/project.env"; exit 1; }
source /etc/project.env
DEV_USER="${DEV_USER:-dev}"
WORK_DIR="${WORK_DIR:-/work}"
PROJECT="${PROJECT:-project}"
id "$DEV_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$DEV_USER"
install -d -m 0700 -o "$DEV_USER" -g "$DEV_USER" "/home/$DEV_USER/.ssh"
if [[ -n "${DEV_SSH_KEY:-}" ]]; then
  printf '%s\n' "$DEV_SSH_KEY" >"/home/$DEV_USER/.ssh/authorized_keys"
  chmod 0600 "/home/$DEV_USER/.ssh/authorized_keys"
fi
chown -R "$DEV_USER:$DEV_USER" "/home/$DEV_USER/.ssh"
install -d -m 0755 -o "$DEV_USER" -g "$DEV_USER" "$WORK_DIR"
if [[ -n "${REPO_URL:-}" ]]; then
  if [[ ! -d "$WORK_DIR/$PROJECT/.git" ]]; then
    sudo -u "$DEV_USER" git clone "$REPO_URL" "$WORK_DIR/$PROJECT"
  fi
  cd "$WORK_DIR/$PROJECT"
  sudo -u "$DEV_USER" git fetch --all --prune || true
  sudo -u "$DEV_USER" git checkout -f "${GIT_REF:-HEAD}" || true
fi
for f in /etc/bootstrap.d/*.sh; do
  [[ -f "$f" && -x "$f" ]] && "$f" || true
done
touch "$SENTINEL"
BOOT
chmod +x /usr/local/sbin/project-bootstrap.sh
cat >/etc/systemd/system/project-bootstrap.service <<'UNIT'
[Unit]
Description=Project bootstrap (first-run)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/project-bootstrap.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl enable NetworkManager
systemctl enable sshd
systemctl enable project-bootstrap.service
echo microvm >/etc/hostname
`
}

func (s *Service) resolveBaseImageForVM(ctx context.Context, requestedID string, requestedSizeMiB int) (*model.BaseImage, int, error) {
	var image *model.BaseImage
	var err error
	if requestedID != "" {
		image, err = s.store.GetBaseImage(ctx, requestedID)
	} else {
		image, err = s.store.DefaultBaseImage(ctx)
	}
	if err != nil {
		return nil, 0, err
	}
	if image == nil {
		return nil, 0, NotFound("base image not found")
	}
	if image.Status != imageStatusActive {
		return nil, 0, Unprocessable("Base image is not active", map[string]string{"base_image_id": "select an active base image"})
	}
	if err := requireFile(image.Path); err != nil {
		return nil, 0, Invalid("Base image file is unavailable", map[string]string{"base_image_id": err.Error()})
	}
	baseSize := image.VirtualSizeMiB
	if baseSize <= 0 {
		baseSize, _, err = imageSizes(image.Path)
		if err != nil {
			return nil, 0, err
		}
	}
	sizeMiB := requestedSizeMiB
	if sizeMiB == 0 {
		sizeMiB = baseSize
	}
	if sizeMiB < baseSize {
		return nil, 0, Invalid("VM rootfs size is too small", map[string]string{"rootfs_size_mib": fmt.Sprintf("must be at least selected base image size %d MiB", baseSize)})
	}
	if sizeMiB > s.cfg.Images.MaxVMRootFSMiB {
		return nil, 0, Invalid("VM rootfs size is too large", map[string]string{"rootfs_size_mib": fmt.Sprintf("must be at most %d MiB", s.cfg.Images.MaxVMRootFSMiB)})
	}
	return image, sizeMiB, nil
}

func (s *Service) prepareRootFSImage(ctx context.Context, vm *model.VM) error {
	if err := os.MkdirAll(filepath.Dir(vm.RootFSPath), 0o755); err != nil {
		return err
	}
	previousSize := int64(0)
	if _, err := os.Stat(vm.RootFSPath); errors.Is(err, os.ErrNotExist) {
		if err := run(ctx, "cp", "--reflink=auto", "--sparse=always", vm.BaseRootFSPath, vm.RootFSPath); err != nil {
			return err
		}
	} else if err == nil {
		if st, statErr := os.Stat(vm.RootFSPath); statErr == nil {
			previousSize = st.Size()
		}
	}
	if vm.RootFSSizeMiB > 0 {
		targetSize := int64(vm.RootFSSizeMiB) * 1024 * 1024
		if previousSize == 0 {
			if st, err := os.Stat(vm.RootFSPath); err == nil {
				previousSize = st.Size()
			}
		}
		if err := os.Truncate(vm.RootFSPath, targetSize); err != nil {
			return err
		}
		if targetSize > previousSize && vm.BaseImageID != "" {
			if image, err := s.store.GetBaseImage(ctx, vm.BaseImageID); err == nil && image != nil && image.Filesystem == "ext4" {
				if err := run(ctx, "resize2fs", vm.RootFSPath); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Service) resizeMountedRootFS(ctx context.Context, vm *model.VM, mountRoot string) error {
	if vm.RootFSSizeMiB <= 0 {
		return nil
	}
	fs := "unknown"
	if vm.BaseImageID != "" {
		if image, err := s.store.GetBaseImage(ctx, vm.BaseImageID); err == nil && image != nil {
			fs = image.Filesystem
		}
	}
	switch fs {
	case "xfs":
		return run(ctx, "xfs_growfs", mountRoot)
	default:
		return nil
	}
}

func splitCommaList(s string) []string {
	out := []string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parsePackageForm(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' ' })
	out := []string{}
	for _, field := range fields {
		if strings.TrimSpace(field) != "" {
			out = append(out, strings.TrimSpace(field))
		}
	}
	return out
}

func parseHookIDs(value string) []string {
	return splitCommaList(value)
}
