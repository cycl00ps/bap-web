package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-web/internal/config"
	"bap-web/internal/lifecycle"
	"bap-web/internal/model"
	"bap-web/internal/random"
	"bap-web/internal/sshkeys"
	"bap-web/internal/store"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*.html static/*
var webFS embed.FS

type App struct {
	cfg       *config.Config
	store     *store.Store
	lifecycle *lifecycle.Service
	tpl       *template.Template
	upgrader  websocket.Upgrader
	metadata  *http.Server
}

type requestUser struct {
	ID       string
	Username string
	IsAdmin  bool
	CSRF     string
}

type contextKey string

const userKey contextKey = "user"

func New(cfg *config.Config) (*App, error) {
	if err := ensureDirs(cfg); err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.Database.Driver, cfg.Database.DSN)
	if err != nil {
		return nil, err
	}
	tpl, err := template.ParseFS(webFS, "templates/*.html")
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	a := &App{
		cfg:       cfg,
		store:     st,
		lifecycle: lifecycle.New(cfg, st),
		tpl:       tpl,
	}
	a.upgrader = websocket.Upgrader{
		CheckOrigin: a.checkWSOrigin,
	}
	if err := a.lifecycle.Reconcile(context.Background()); err != nil {
		log.Printf("startup reconcile: %v", err)
	}
	a.startMetadataServer()
	if err := a.lifecycle.MigrateSSHAccess(context.Background()); err != nil {
		log.Printf("ssh access migration: %v", err)
	}
	if err := a.lifecycle.EnsureDefaultBaseImage(context.Background()); err != nil {
		log.Printf("base image migration: %v", err)
	}
	if err := a.lifecycle.EnsureDefaultKernel(context.Background()); err != nil {
		log.Printf("kernel migration: %v", err)
	}
	if cfg.Database.Driver == "sqlite" {
		if err := os.Chmod(cfg.Database.DSN, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("chmod sqlite database: %v", err)
		}
	}
	return a, nil
}

func (a *App) Close() {
	if a.metadata != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.metadata.Shutdown(ctx)
		cancel()
	}
	_ = a.store.Close()
}

func ensureDirs(cfg *config.Config) error {
	for _, dir := range []string{cfg.Paths.StateDir, cfg.Paths.LogDir, cfg.Paths.KeyDir, cfg.Paths.RuntimeDir, cfg.Paths.ImageDir, cfg.Paths.KernelDir, cfg.Paths.BaseImageDir, cfg.Images.BuildDir, cfg.Images.HookDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/", a.static)
	mux.HandleFunc("GET /setup", a.setupGet)
	mux.HandleFunc("POST /setup", a.setupPost)
	mux.HandleFunc("GET /login", a.loginGet)
	mux.HandleFunc("POST /login", a.loginPost)
	mux.HandleFunc("POST /logout", a.requireAuth(a.logoutPost))
	mux.HandleFunc("GET /", a.requireAuth(a.dashboard))
	mux.HandleFunc("GET /ssh-keys", a.requireAuth(a.sshKeysPage))
	mux.HandleFunc("GET /images", a.requireAuth(a.requireAdmin(a.imagesPage)))
	mux.HandleFunc("GET /kernels", a.requireAuth(a.requireAdmin(a.kernelsPage)))
	mux.HandleFunc("POST /ui/ssh-keys/generate", a.requireAuth(a.uiSSHKeyGenerate))
	mux.HandleFunc("POST /ui/ssh-keys/import", a.requireAuth(a.uiSSHKeyImport))
	mux.HandleFunc("POST /ui/ssh-keys/{id}/delete", a.requireAuth(a.uiSSHKeyDelete))
	mux.HandleFunc("POST /ui/base-images/register", a.requireAuth(a.requireAdmin(a.uiBaseImageRegister)))
	mux.HandleFunc("POST /ui/base-images/build", a.requireAuth(a.requireAdmin(a.uiBaseImageBuild)))
	mux.HandleFunc("POST /ui/base-images/{id}/action", a.requireAuth(a.requireAdmin(a.uiBaseImageAction)))
	mux.HandleFunc("POST /ui/base-images/{id}/status", a.requireAuth(a.requireAdmin(a.uiBaseImageStatus)))
	mux.HandleFunc("POST /ui/base-images/{id}/delete", a.requireAuth(a.requireAdmin(a.uiBaseImageDelete)))
	mux.HandleFunc("GET /ui/image-build-jobs/{id}/logs", a.requireAuth(a.requireAdmin(a.uiImageBuildJobLogs)))
	mux.HandleFunc("POST /ui/image-hooks", a.requireAuth(a.requireAdmin(a.uiImageHookCreate)))
	mux.HandleFunc("POST /ui/image-hooks/{id}/delete", a.requireAuth(a.requireAdmin(a.uiImageHookDelete)))
	mux.HandleFunc("POST /ui/kernels/import-firecracker-ci", a.requireAuth(a.requireAdmin(a.uiKernelImportFirecrackerCI)))
	mux.HandleFunc("POST /ui/kernels/firecracker-ci/scan", a.requireAuth(a.requireAdmin(a.uiKernelFirecrackerCIScan)))
	mux.HandleFunc("POST /ui/kernels/upload", a.requireAuth(a.requireAdmin(a.uiKernelUpload)))
	mux.HandleFunc("POST /ui/kernels/{id}/test", a.requireAuth(a.requireAdmin(a.uiKernelTest)))
	mux.HandleFunc("POST /ui/kernels/{id}/status", a.requireAuth(a.requireAdmin(a.uiKernelStatus)))
	mux.HandleFunc("POST /ui/kernels/{id}/delete", a.requireAuth(a.requireAdmin(a.uiKernelDelete)))
	mux.HandleFunc("GET /ui/kernel-test-jobs/{id}/logs", a.requireAuth(a.requireAdmin(a.uiKernelTestJobLogs)))
	mux.HandleFunc("GET /ui/vms-table", a.requireAuth(a.vmsTable))
	mux.HandleFunc("POST /ui/vms", a.requireAuth(a.vmCreateForm))
	mux.HandleFunc("POST /ui/vms/{id}/action", a.requireAuth(a.vmActionForm))
	mux.HandleFunc("POST /ui/vms/{id}/start", a.requireAuth(a.vmStartForm))
	mux.HandleFunc("POST /ui/vms/{id}/stop", a.requireAuth(a.vmStopForm))
	mux.HandleFunc("POST /ui/vms/{id}/restart", a.requireAuth(a.vmRestartForm))
	mux.HandleFunc("POST /ui/vms/{id}/delete", a.requireAuth(a.vmDeleteForm))
	mux.HandleFunc("POST /ui/vms/{id}/resources", a.requireAuth(a.vmResourcesForm))
	mux.HandleFunc("POST /ui/vms/{id}/ingress-rules", a.requireAuth(a.vmIngressRuleForm))
	mux.HandleFunc("POST /ui/vms/{id}/ingress-rules/{rule_id}/delete", a.requireAuth(a.vmIngressRuleDeleteForm))
	mux.HandleFunc("POST /ui/vms/{id}/egress-policy", a.requireAuth(a.vmEgressPolicyForm))
	mux.HandleFunc("POST /ui/networks", a.requireAuth(a.uiNetworkCreate))
	mux.HandleFunc("POST /ui/networks/{id}/delete", a.requireAuth(a.uiNetworkDelete))
	mux.HandleFunc("POST /ui/egress-policies", a.requireAuth(a.uiEgressPolicyCreate))
	mux.HandleFunc("POST /ui/egress-policies/{id}/delete", a.requireAuth(a.uiEgressPolicyDelete))
	mux.HandleFunc("POST /ui/host/orphans/cleanup", a.requireAuth(a.uiHostOrphansCleanup))
	mux.HandleFunc("GET /vms/{id}", a.requireAuth(a.vmDetail))
	mux.HandleFunc("GET /api/health", a.apiHealth)
	mux.HandleFunc("GET /api/session", a.requireAuth(a.apiSession))
	mux.HandleFunc("GET /api/tokens", a.requireAuth(a.requireAdmin(a.apiTokenList)))
	mux.HandleFunc("POST /api/tokens", a.requireAuth(a.requireAdmin(a.apiTokenCreate)))
	mux.HandleFunc("DELETE /api/tokens/{id}", a.requireAuth(a.requireAdmin(a.apiTokenRevoke)))
	mux.HandleFunc("GET /api/host/status", a.requireAuth(a.apiHostStatus))
	mux.HandleFunc("GET /api/host/orphans", a.requireAuth(a.apiHostOrphans))
	mux.HandleFunc("POST /api/host/orphans/cleanup", a.requireAuth(a.apiHostOrphansCleanup))
	mux.HandleFunc("GET /api/ssh-keys", a.requireAuth(a.apiSSHKeyList))
	mux.HandleFunc("POST /api/ssh-keys/generate", a.requireAuth(a.apiSSHKeyGenerate))
	mux.HandleFunc("POST /api/ssh-keys/import", a.requireAuth(a.apiSSHKeyImport))
	mux.HandleFunc("GET /api/ssh-keys/{id}", a.requireAuth(a.apiSSHKeyGet))
	mux.HandleFunc("DELETE /api/ssh-keys/{id}", a.requireAuth(a.apiSSHKeyDelete))
	mux.HandleFunc("GET /api/base-images", a.requireAuth(a.apiBaseImageList))
	mux.HandleFunc("POST /api/base-images/register", a.requireAuth(a.requireAdmin(a.apiBaseImageRegister)))
	mux.HandleFunc("POST /api/base-images/build", a.requireAuth(a.requireAdmin(a.apiBaseImageBuild)))
	mux.HandleFunc("PATCH /api/base-images/{id}", a.requireAuth(a.requireAdmin(a.apiBaseImageUpdate)))
	mux.HandleFunc("DELETE /api/base-images/{id}", a.requireAuth(a.requireAdmin(a.apiBaseImageDelete)))
	mux.HandleFunc("GET /api/image-build-jobs/{id}", a.requireAuth(a.requireAdmin(a.apiImageBuildJobGet)))
	mux.HandleFunc("GET /api/image-build-jobs/{id}/logs", a.requireAuth(a.requireAdmin(a.apiImageBuildJobLogs)))
	mux.HandleFunc("GET /api/image-hooks", a.requireAuth(a.requireAdmin(a.apiImageHookList)))
	mux.HandleFunc("POST /api/image-hooks", a.requireAuth(a.requireAdmin(a.apiImageHookCreate)))
	mux.HandleFunc("DELETE /api/image-hooks/{id}", a.requireAuth(a.requireAdmin(a.apiImageHookDelete)))
	mux.HandleFunc("GET /api/kernels", a.requireAuth(a.apiKernelList))
	mux.HandleFunc("POST /api/kernels/firecracker-ci/scan", a.requireAuth(a.requireAdmin(a.apiKernelFirecrackerCIScan)))
	mux.HandleFunc("GET /api/kernels/firecracker-ci/scan-jobs", a.requireAuth(a.requireAdmin(a.apiKernelDiscoveryJobList)))
	mux.HandleFunc("GET /api/kernels/firecracker-ci/scan-jobs/{id}", a.requireAuth(a.requireAdmin(a.apiKernelDiscoveryJobGet)))
	mux.HandleFunc("GET /api/kernels/firecracker-ci/items", a.requireAuth(a.requireAdmin(a.apiKernelDiscoveryItemList)))
	mux.HandleFunc("POST /api/kernels/import-firecracker-ci", a.requireAuth(a.requireAdmin(a.apiKernelImportFirecrackerCI)))
	mux.HandleFunc("POST /api/kernels/upload", a.requireAuth(a.requireAdmin(a.apiKernelUpload)))
	mux.HandleFunc("PATCH /api/kernels/{id}", a.requireAuth(a.requireAdmin(a.apiKernelUpdate)))
	mux.HandleFunc("DELETE /api/kernels/{id}", a.requireAuth(a.requireAdmin(a.apiKernelDelete)))
	mux.HandleFunc("POST /api/kernels/{id}/test", a.requireAuth(a.requireAdmin(a.apiKernelTest)))
	mux.HandleFunc("GET /api/kernel-test-jobs/{id}", a.requireAuth(a.requireAdmin(a.apiKernelTestJobGet)))
	mux.HandleFunc("GET /api/kernel-test-jobs/{id}/logs", a.requireAuth(a.requireAdmin(a.apiKernelTestJobLogs)))
	mux.HandleFunc("GET /api/vms", a.requireAuth(a.apiVMList))
	mux.HandleFunc("POST /api/vms", a.requireAuth(a.apiVMCreate))
	mux.HandleFunc("GET /api/vms/{id}", a.requireAuth(a.apiVMGet))
	mux.HandleFunc("POST /api/vms/{id}/start", a.requireAuth(a.apiVMStart))
	mux.HandleFunc("POST /api/vms/{id}/stop", a.requireAuth(a.apiVMStop))
	mux.HandleFunc("POST /api/vms/{id}/restart", a.requireAuth(a.apiVMRestart))
	mux.HandleFunc("PUT /api/vms/{id}/resources", a.requireAuth(a.apiVMResources))
	mux.HandleFunc("GET /api/vms/{id}/logs", a.requireAuth(a.apiVMLogs))
	mux.HandleFunc("POST /api/vms/{id}/exec", a.requireAuth(a.apiVMExec))
	mux.HandleFunc("GET /api/vms/{id}/exec-jobs", a.requireAuth(a.apiVMExecJobList))
	mux.HandleFunc("POST /api/vms/{id}/exec-jobs", a.requireAuth(a.apiVMExecJobCreate))
	mux.HandleFunc("GET /api/vms/{id}/exec-jobs/{job_id}", a.requireAuth(a.apiVMExecJobGet))
	mux.HandleFunc("GET /api/vms/{id}/exec-jobs/{job_id}/logs", a.requireAuth(a.apiVMExecJobLogs))
	mux.HandleFunc("POST /api/vms/{id}/exec-jobs/{job_id}/cancel", a.requireAuth(a.apiVMExecJobCancel))
	mux.HandleFunc("GET /api/vms/{id}/network", a.requireAuth(a.apiVMNetwork))
	mux.HandleFunc("POST /api/vms/{id}/ingress-rules", a.requireAuth(a.apiIngressRuleCreate))
	mux.HandleFunc("DELETE /api/vms/{id}/ingress-rules/{rule_id}", a.requireAuth(a.apiIngressRuleDelete))
	mux.HandleFunc("PUT /api/vms/{id}/egress-policy", a.requireAuth(a.apiVMEgressPolicy))
	mux.HandleFunc("DELETE /api/vms/{id}", a.requireAuth(a.apiVMDelete))
	mux.HandleFunc("GET /api/networks", a.requireAuth(a.apiNetworkList))
	mux.HandleFunc("POST /api/networks", a.requireAuth(a.apiNetworkCreate))
	mux.HandleFunc("DELETE /api/networks/{id}", a.requireAuth(a.apiNetworkDelete))
	mux.HandleFunc("GET /api/egress-policies", a.requireAuth(a.apiEgressPolicyList))
	mux.HandleFunc("POST /api/egress-policies", a.requireAuth(a.apiEgressPolicyCreate))
	mux.HandleFunc("DELETE /api/egress-policies/{id}", a.requireAuth(a.apiEgressPolicyDelete))
	mux.HandleFunc("GET /ws/vms/{id}/terminal", a.requireAuth(a.wsTerminal))
	return a.securityHeaders(a.hostGuard(a.requestID(mux)))
}

func (a *App) startMetadataServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metadata/v1/authorized-keys", a.metadataAuthorizedKeys)
	addr := fmt.Sprintf("%s:%d", a.cfg.Server.MetadataBindAddress, a.cfg.Server.MetadataPort)
	a.metadata = &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("bap-web metadata listening on http://%s", addr)
		if err := a.metadata.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metadata server: %v", err)
		}
	}()
}

func (a *App) metadataAuthorizedKeys(w http.ResponseWriter, r *http.Request) {
	vmID := strings.TrimSpace(r.URL.Query().Get("vm_id"))
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	if vmID == "" {
		http.NotFound(w, r)
		return
	}
	vm, err := a.store.GetVM(r.Context(), vmID)
	if err != nil || vm == nil {
		http.NotFound(w, r)
		return
	}
	if sourceIP(r) != vm.GuestIP {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	keys, err := a.lifecycle.AuthorizedKeys(r.Context(), vm, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(keys))
}

func (a *App) static(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/static/")
	if path == "" || strings.Contains(path, "..") {
		http.NotFound(w, r)
		return
	}
	if a.cfg.Server.StaticDir != "" {
		full := filepath.Join(a.cfg.Server.StaticDir, path)
		if st, err := os.Stat(full); err == nil && !st.IsDir() {
			http.ServeFile(w, r, full)
			return
		}
	}
	http.FileServer(http.FS(webFS)).ServeHTTP(w, r)
}

func (a *App) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = random.Hex(8)
		}
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey("request_id"), rid)))
	})
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (a *App) hostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(a.cfg.Server.TrustedHosts) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		host := r.Host
		for _, allowed := range a.cfg.Server.TrustedHosts {
			if strings.EqualFold(host, allowed) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "untrusted host", http.StatusBadRequest)
	})
}

func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		has, err := a.store.HasUsers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !has {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if secret := bearerToken(r); secret != "" {
			u, ok, err := a.currentTokenUser(r.Context(), secret)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					a.writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "invalid bearer token", nil)
				} else {
					http.Error(w, "invalid bearer token", http.StatusUnauthorized)
				}
				return
			}
			next(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
			return
		}
		u, sess, ok := a.currentUser(r)
		if !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				a.writeAPIError(w, r, http.StatusUnauthorized, "unauthorized", "authentication required", nil)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		if isStateChanging(r.Method) {
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.FormValue("csrf")
			}
			if token == "" || token != sess.CSRFToken {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					a.writeAPIError(w, r, http.StatusForbidden, "forbidden", "invalid csrf token", nil)
				} else {
					http.Error(w, "invalid csrf token", http.StatusForbidden)
				}
				return
			}
		}
		_ = a.store.TouchSession(r.Context(), sess.ID, time.Now().Add(a.cfg.Security.SessionIdleTimeout.Duration))
		ru := &requestUser{ID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin, CSRF: sess.CSRFToken}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, ru)))
	}
}

func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	typ, value, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(typ, "Bearer") {
		return ""
	}
	return strings.TrimSpace(value)
}

func hashAPIToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (a *App) currentTokenUser(ctx context.Context, secret string) (*requestUser, bool, error) {
	token, err := a.store.GetAPITokenByHash(ctx, hashAPIToken(secret))
	if err != nil || token == nil {
		return nil, false, err
	}
	now := time.Now().UTC()
	if token.RevokedAt != nil || (token.ExpiresAt != nil && now.After(*token.ExpiresAt)) {
		return nil, false, nil
	}
	_ = a.store.TouchAPIToken(ctx, token.ID)
	return &requestUser{ID: token.ID, Username: "token:" + token.Name, IsAdmin: token.IsAdmin}, true, nil
}

func (a *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !current(r).IsAdmin {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				a.writeAPIError(w, r, http.StatusForbidden, "forbidden", "admin privileges required", nil)
			} else {
				http.Error(w, "admin privileges required", http.StatusForbidden)
			}
			return
		}
		next(w, r)
	}
}

func isStateChanging(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (a *App) currentUser(r *http.Request) (*model.User, *model.Session, bool) {
	c, err := r.Cookie("bap_web_session")
	if err != nil || c.Value == "" {
		return nil, nil, false
	}
	sess, err := a.store.SessionByID(r.Context(), c.Value)
	if err != nil || sess == nil {
		return nil, nil, false
	}
	now := time.Now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > a.cfg.Security.SessionAbsoluteTimeout.Duration {
		_ = a.store.DeleteSession(r.Context(), sess.ID)
		return nil, nil, false
	}
	u, err := a.store.UserByID(r.Context(), sess.UserID)
	if err != nil || u == nil {
		return nil, nil, false
	}
	return u, sess, true
}

func current(r *http.Request) *requestUser {
	if u, ok := r.Context().Value(userKey).(*requestUser); ok {
		return u
	}
	return &requestUser{}
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (a *App) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type apiErrorBody struct {
	Error apiErrorDetail `json:"error"`
}

type apiErrorDetail struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
}

func (a *App) apiError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, fields := classifyError(err)
	a.writeAPIError(w, r, status, code, err.Error(), fields)
}

func (a *App) writeAPIError(w http.ResponseWriter, r *http.Request, status int, code, message string, fields map[string]string) {
	if code == "" {
		code = "internal"
	}
	if message == "" {
		message = http.StatusText(status)
	}
	a.json(w, status, apiErrorBody{Error: apiErrorDetail{
		Code:      code,
		Message:   message,
		Fields:    fields,
		RequestID: reqID(r),
	}})
}

func classifyError(err error) (int, string, map[string]string) {
	if err == nil {
		return http.StatusInternalServerError, "internal", nil
	}
	var domain *lifecycle.DomainError
	if errors.As(err, &domain) {
		switch domain.Code {
		case lifecycle.CodeInvalid:
			return http.StatusBadRequest, string(domain.Code), domain.Fields
		case lifecycle.CodeNotFound:
			return http.StatusNotFound, string(domain.Code), domain.Fields
		case lifecycle.CodeConflict:
			return http.StatusConflict, string(domain.Code), domain.Fields
		case lifecycle.CodeUnusable:
			return http.StatusUnprocessableEntity, string(domain.Code), domain.Fields
		default:
			return http.StatusInternalServerError, string(domain.Code), domain.Fields
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist"):
		return http.StatusNotFound, "not_found", nil
	case strings.Contains(msg, "unique constraint") || strings.Contains(msg, "already exists") || strings.Contains(msg, "already in use") || strings.Contains(msg, "assigned to"):
		return http.StatusConflict, "conflict", nil
	case strings.Contains(msg, "required") || strings.Contains(msg, "must ") || strings.Contains(msg, "invalid") || strings.Contains(msg, "outside"):
		return http.StatusBadRequest, "invalid", nil
	default:
		return http.StatusInternalServerError, "internal", nil
	}
}

func (a *App) setupGet(w http.ResponseWriter, r *http.Request) {
	has, err := a.store.HasUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if has {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	a.render(w, "setup.html", map[string]any{"Title": "Setup"})
}

func (a *App) setupPost(w http.ResponseWriter, r *http.Request) {
	has, err := a.store.HasUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if has {
		http.Error(w, "setup already complete", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || len(password) < 12 {
		http.Error(w, "username and password of at least 12 characters required", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	u := model.User{ID: random.Hex(16), Username: username, PasswordHash: hash, IsAdmin: true, CreatedAt: time.Now().UTC()}
	if err := a.store.CreateUser(r.Context(), u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = a.store.Audit(r.Context(), username, sourceIP(r), "setup_admin", "user:"+u.ID, "success", reqID(r), "initial admin created")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) loginGet(w http.ResponseWriter, r *http.Request) {
	has, _ := a.store.HasUsers(r.Context())
	if !has {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	a.render(w, "login.html", map[string]any{"Title": "Login"})
}

func (a *App) loginPost(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	u, err := a.store.UserByUsername(r.Context(), username)
	if err != nil || u == nil || bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)) != nil {
		_ = a.store.Audit(r.Context(), username, sourceIP(r), "login", "user:"+username, "failure", reqID(r), "invalid credentials")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	now := time.Now().UTC()
	sess := model.Session{
		ID:         random.Hex(32),
		UserID:     u.ID,
		CSRFToken:  random.Hex(32),
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(a.cfg.Security.SessionIdleTimeout.Duration),
	}
	if err := a.store.CreateSession(r.Context(), sess); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "bap_web_session",
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	_ = a.store.Audit(r.Context(), u.Username, sourceIP(r), "login", "user:"+u.ID, "success", reqID(r), "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) logoutPost(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("bap_web_session"); err == nil {
		_ = a.store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "bap_web_session", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	data, err := a.dashboardData(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, "dashboard.html", data)
}

func (a *App) dashboardData(r *http.Request) (map[string]any, error) {
	vms, err := a.store.ListVMs(r.Context())
	if err != nil {
		return nil, err
	}
	keys, err := a.store.ListSSHKeys(r.Context())
	if err != nil {
		return nil, err
	}
	networks, err := a.store.ListNetworks(r.Context())
	if err != nil {
		return nil, err
	}
	policies, err := a.store.ListEgressPolicies(r.Context())
	if err != nil {
		return nil, err
	}
	baseImages, err := a.store.ListBaseImages(r.Context())
	if err != nil {
		return nil, err
	}
	kernels, err := a.store.ListKernels(r.Context())
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"Title":          "BAP Web",
		"User":           current(r),
		"VMs":            vms,
		"SSHKeys":        keys,
		"Networks":       networks,
		"EgressPolicies": policies,
		"BaseImages":     baseImages,
		"Kernels":        kernels,
		"HostStatus":     a.lifecycle.HostStatus(r.Context()),
		"CreateVMForm":   defaultCreateVMRequest(keys, baseImages, kernels),
	}, nil
}

func defaultCreateVMRequest(keys []model.SSHKey, baseImages []model.BaseImage, kernels []model.Kernel) CreateVMRequest {
	req := CreateVMRequest{
		VCPUCount:   2,
		MemMiB:      2048,
		DevUser:     "dev",
		GitRef:      "HEAD",
		EgressMode:  "allow_all",
		NetworkMode: "routed_ptp",
	}
	if len(keys) > 0 {
		req.SSHKeyID = keys[0].ID
	}
	for _, image := range baseImages {
		if image.Status == "active" {
			req.BaseImageID = image.ID
			req.RootFSSizeMiB = image.VirtualSizeMiB
			break
		}
	}
	for _, kernel := range kernels {
		if kernel.Status == "active" {
			req.KernelID = kernel.ID
			break
		}
	}
	return req
}

func (a *App) renderDashboardError(w http.ResponseWriter, r *http.Request, err error) {
	data, dataErr := a.dashboardData(r)
	if dataErr != nil {
		http.Error(w, dataErr.Error(), http.StatusInternalServerError)
		return
	}
	data["DashboardError"] = err.Error()
	a.render(w, "dashboard.html", data)
}

func (a *App) sshKeysPage(w http.ResponseWriter, r *http.Request) {
	a.renderSSHKeysPage(w, r, nil)
}

func (a *App) renderSSHKeysPage(w http.ResponseWriter, r *http.Request, data map[string]any) {
	keys, err := a.store.ListSSHKeys(r.Context())
	if err != nil {
		keys = nil
		if data == nil {
			data = map[string]any{}
		}
		data["Error"] = err.Error()
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = "SSH Keys"
	data["User"] = current(r)
	data["SSHKeys"] = keys
	a.render(w, "ssh_keys.html", data)
}

func (a *App) uiSSHKeyGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	generated, err := sshkeys.Generate(r.FormValue("name"), current(r).Username)
	if err != nil {
		a.renderSSHKeysPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	if err := a.store.CreateSSHKey(r.Context(), generated.Key); err != nil {
		a.renderSSHKeysPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ssh_key_generate", "ssh-key:"+generated.Key.ID, "success", reqID(r), "")
	a.renderSSHKeysPage(w, r, map[string]any{"CreatedKey": generated.Key, "PrivateKey": generated.PrivateKey})
}

func (a *App) uiSSHKeyImport(w http.ResponseWriter, r *http.Request) {
	key, err := sshkeys.Import(r.FormValue("name"), r.FormValue("public_key"), current(r).Username)
	if err != nil {
		a.renderSSHKeysPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	if err := a.store.CreateSSHKey(r.Context(), *key); err != nil {
		a.renderSSHKeysPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ssh_key_import", "ssh-key:"+key.ID, "success", reqID(r), "")
	http.Redirect(w, r, "/ssh-keys", http.StatusSeeOther)
}

func (a *App) uiSSHKeyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.DeleteSSHKey(r.Context(), id); err != nil {
		a.renderSSHKeysPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ssh_key_delete", "ssh-key:"+id, "success", reqID(r), "")
	http.Redirect(w, r, "/ssh-keys", http.StatusSeeOther)
}

func (a *App) imagesPage(w http.ResponseWriter, r *http.Request) {
	a.renderImagesPage(w, r, nil)
}

func (a *App) renderImagesPage(w http.ResponseWriter, r *http.Request, data map[string]any) {
	images, err := a.store.ListBaseImages(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jobs, err := a.store.ListImageBuildJobs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hooks, err := a.store.ListImageHooks(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = "Images"
	data["User"] = current(r)
	data["BaseImages"] = images
	data["ImageBuildJobs"] = jobs
	data["ImageHooks"] = hooks
	data["OpenBuildJobID"] = r.URL.Query().Get("build_job")
	a.render(w, "images.html", data)
}

func (a *App) uiBaseImageRegister(w http.ResponseWriter, r *http.Request) {
	req := lifecycle.RegisterBaseImageRequest{
		Name:       r.FormValue("name"),
		Path:       r.FormValue("path"),
		Status:     defaultString(r.FormValue("status"), "active"),
		Filesystem: r.FormValue("filesystem"),
		Provenance: r.FormValue("provenance"),
	}
	image, err := a.lifecycle.RegisterBaseImage(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "base-image"
	if image != nil {
		target = "base-image:" + image.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_register", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (a *App) uiBaseImageBuild(w http.ResponseWriter, r *http.Request) {
	req := lifecycle.BuildBaseImageRequest{
		Name:       r.FormValue("name"),
		Filesystem: defaultString(r.FormValue("filesystem"), "ext4"),
		SizeMiB:    atoiDefault(r.FormValue("size_mib"), 0),
		Packages:   parseListField(r.FormValue("packages")),
		HookIDs:    r.Form["hook_ids"],
	}
	job, err := a.lifecycle.StartImageBuild(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "image-build-job"
	if job != nil {
		target = "image-build-job:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_build", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/images?build_job="+job.ID+"#build-job-"+job.ID, http.StatusSeeOther)
}

func (a *App) uiImageBuildJobLogs(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetImageBuildJob(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if job == nil {
		http.NotFound(w, r)
		return
	}
	_, lines, err := tailFile(job.LogPath, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	poll := job.Status == "queued" || job.Status == "running"
	a.render(w, "image_build_log.html", map[string]any{
		"Job":     job,
		"LogPath": job.LogPath,
		"Lines":   lines,
		"Poll":    poll,
	})
}

func (a *App) uiBaseImageAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	action := strings.TrimSpace(r.FormValue("action"))
	operation := "base_image_status"
	var err error
	switch action {
	case "make_active":
		_, err = a.lifecycle.UpdateBaseImageStatus(r.Context(), id, "active")
	case "mark_deprecated":
		_, err = a.lifecycle.UpdateBaseImageStatus(r.Context(), id, "deprecated")
	case "archive":
		_, err = a.lifecycle.UpdateBaseImageStatus(r.Context(), id, "archived")
	case "delete":
		operation = "base_image_delete"
		err = a.lifecycle.DeleteBaseImage(r.Context(), id)
	default:
		err = lifecycle.Invalid("Base image action is invalid", map[string]string{"action": "select a valid action"})
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), operation, "base-image:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (a *App) uiBaseImageStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	image, err := a.lifecycle.UpdateBaseImageStatus(r.Context(), id, r.FormValue("status"))
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_status", "base-image:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	_ = image
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (a *App) uiBaseImageDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteBaseImage(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_delete", "base-image:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (a *App) uiImageHookCreate(w http.ResponseWriter, r *http.Request) {
	req := lifecycle.ImageHookRequest{
		Name:       r.FormValue("name"),
		SourceType: r.FormValue("source_type"),
		Content:    r.FormValue("content"),
		GitURL:     r.FormValue("git_url"),
		GitRef:     r.FormValue("git_ref"),
		GitPath:    r.FormValue("git_path"),
	}
	hook, err := a.lifecycle.CreateImageHook(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "image-hook"
	if hook != nil {
		target = "image-hook:" + hook.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "image_hook_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (a *App) uiImageHookDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteImageHook(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "image_hook_delete", "image-hook:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderImagesPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/images", http.StatusSeeOther)
}

func (a *App) kernelsPage(w http.ResponseWriter, r *http.Request) {
	a.renderKernelsPage(w, r, nil)
}

func (a *App) renderKernelsPage(w http.ResponseWriter, r *http.Request, data map[string]any) {
	kernels, err := a.store.ListKernels(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jobs, err := a.store.ListKernelTestJobs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	discoveryJobs, err := a.store.ListKernelDiscoveryJobs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	openDiscoveryJobID := r.URL.Query().Get("discovery_job")
	discoveryJobID := openDiscoveryJobID
	if discoveryJobID == "" {
		if latest, err := a.store.LatestKernelDiscoveryJob(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		} else if latest != nil {
			discoveryJobID = latest.ID
		}
	}
	discoveryItems, err := a.store.ListKernelDiscoveryItems(r.Context(), discoveryJobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	activeDiscoveryJob := kernelDiscoveryJobByID(discoveryJobs, discoveryJobID)
	pollDiscoveryJobID := ""
	if activeDiscoveryJob != nil && (activeDiscoveryJob.Status == "queued" || activeDiscoveryJob.Status == "running") {
		pollDiscoveryJobID = activeDiscoveryJob.ID
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = "Kernels"
	data["User"] = current(r)
	data["Kernels"] = kernels
	data["KernelTestJobs"] = kernelTestJobViews(jobs, kernels)
	data["KernelDiscoveryJobs"] = discoveryJobs
	data["KernelDiscoveryItems"] = discoveryItems
	data["OpenDiscoveryJobID"] = openDiscoveryJobID
	data["DiscoveryJobID"] = discoveryJobID
	data["ActiveDiscoveryJob"] = activeDiscoveryJob
	data["PollDiscoveryJobID"] = pollDiscoveryJobID
	data["FirecrackerCIBaseURL"] = strings.TrimRight(a.cfg.Kernels.FirecrackerCIBaseURL, "/")
	data["OpenKernelTestJobID"] = r.URL.Query().Get("test_job")
	a.render(w, "kernels.html", data)
}

type kernelTestJobView struct {
	model.KernelTestJob
	KernelName        string
	GatewayLabel      string
	GatewayStateClass string
	CreatedAtText     string
}

func kernelTestJobViews(jobs []model.KernelTestJob, kernels []model.Kernel) []kernelTestJobView {
	kernelNames := map[string]string{}
	for _, kernel := range kernels {
		kernelNames[kernel.ID] = kernel.Name
	}
	views := make([]kernelTestJobView, 0, len(jobs))
	for _, job := range jobs {
		enriched := model.EnrichKernelTestJob(job)
		kernelName := kernelNames[job.KernelID]
		if kernelName == "" {
			kernelName = job.KernelID
		}
		gatewayLabel := "unknown"
		gatewayClass := "unknown"
		if enriched.GatewayOK != nil {
			if *enriched.GatewayOK {
				gatewayLabel = "ok"
				gatewayClass = "succeeded"
			} else {
				gatewayLabel = "failed"
				gatewayClass = "failed"
			}
		}
		views = append(views, kernelTestJobView{
			KernelTestJob:     enriched,
			KernelName:        kernelName,
			GatewayLabel:      gatewayLabel,
			GatewayStateClass: gatewayClass,
			CreatedAtText:     job.CreatedAt.Local().Format("2006-01-02 15:04:05"),
		})
	}
	return views
}

func kernelDiscoveryJobByID(jobs []model.KernelDiscoveryJob, id string) *model.KernelDiscoveryJob {
	if id == "" {
		return nil
	}
	for i := range jobs {
		if jobs[i].ID == id {
			return &jobs[i]
		}
	}
	return nil
}

func (a *App) uiKernelImportFirecrackerCI(w http.ResponseWriter, r *http.Request) {
	req := lifecycle.ImportFirecrackerCIKernelRequest{
		Name:       r.FormValue("name"),
		Version:    r.FormValue("version"),
		CIPrefix:   r.FormValue("ci_prefix"),
		ArtifactID: r.FormValue("artifact_id"),
	}
	kernel, err := a.lifecycle.ImportFirecrackerCIKernel(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "kernel"
	if kernel != nil {
		target = "kernel:" + kernel.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_import_firecracker_ci", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderKernelsPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/kernels", http.StatusSeeOther)
}

func (a *App) uiKernelFirecrackerCIScan(w http.ResponseWriter, r *http.Request) {
	req := lifecycle.DiscoverFirecrackerCIKernelsRequest{CIPrefix: r.FormValue("ci_prefix")}
	job, err := a.lifecycle.StartKernelDiscovery(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "kernel-discovery"
	if job != nil {
		target = "kernel-discovery:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_discovery_scan", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderKernelsPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/kernels?discovery_job="+job.ID+"#kernel-discovery", http.StatusSeeOther)
}

func (a *App) uiKernelUpload(w http.ResponseWriter, r *http.Request) {
	kernel, err := a.uploadKernelFromRequest(r)
	outcome := "success"
	target := "kernel"
	if kernel != nil {
		target = "kernel:" + kernel.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_upload", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderKernelsPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/kernels", http.StatusSeeOther)
}

func (a *App) uiKernelTest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := a.lifecycle.StartKernelTest(r.Context(), id, current(r).Username)
	outcome := "success"
	target := "kernel:" + id
	if job != nil {
		target = "kernel-test-job:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_test", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderKernelsPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/kernels?test_job="+job.ID+"#kernel-test-job-"+job.ID, http.StatusSeeOther)
}

func (a *App) uiKernelStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, err := a.lifecycle.UpdateKernel(r.Context(), id, lifecycle.KernelUpdateRequest{Status: r.FormValue("status"), BootArgs: r.FormValue("boot_args")})
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_update", "kernel:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderKernelsPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/kernels", http.StatusSeeOther)
}

func (a *App) uiKernelDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteKernel(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_delete", "kernel:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderKernelsPage(w, r, map[string]any{"Error": err.Error()})
		return
	}
	http.Redirect(w, r, "/kernels", http.StatusSeeOther)
}

func (a *App) uiKernelTestJobLogs(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetKernelTestJob(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if job == nil {
		http.NotFound(w, r)
		return
	}
	_, lines, err := tailFile(job.LogPath, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enriched := model.EnrichKernelTestJob(*job)
	poll := job.Status == "queued" || job.Status == "running"
	a.render(w, "kernel_test_log.html", map[string]any{
		"Job":     enriched,
		"LogPath": job.LogPath,
		"Lines":   lines,
		"Poll":    poll,
	})
}

func (a *App) vmsTable(w http.ResponseWriter, r *http.Request) {
	vms, err := a.store.ListVMs(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, "vms_table.html", map[string]any{"User": current(r), "VMs": vms})
}

func (a *App) vmsTableError(w http.ResponseWriter, r *http.Request, err error) {
	vms, dataErr := a.store.ListVMs(r.Context())
	if dataErr != nil {
		http.Error(w, dataErr.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, "vms_table.html", map[string]any{"User": current(r), "VMs": vms, "TableError": err.Error()})
}

func (a *App) vmDetail(w http.ResponseWriter, r *http.Request) {
	data, err := a.vmDetailData(r, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if data == nil {
		http.NotFound(w, r)
		return
	}
	a.render(w, "vm_detail.html", data)
}

func (a *App) vmDetailData(r *http.Request, id string) (map[string]any, error) {
	vm, err := a.store.GetVM(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, nil
	}
	var key *model.SSHKey
	if vm.SSHKeyID != "" {
		key, _ = a.store.GetSSHKey(r.Context(), vm.SSHKeyID)
	}
	ingressRules, err := a.store.ListIngressRules(r.Context(), vm.ID)
	if err != nil {
		return nil, err
	}
	networks, err := a.store.ListNetworks(r.Context())
	if err != nil {
		return nil, err
	}
	policies, err := a.store.ListEgressPolicies(r.Context())
	if err != nil {
		return nil, err
	}
	var network *model.Network
	if vm.NetworkID != "" {
		network, _ = a.store.GetNetwork(r.Context(), vm.NetworkID)
	}
	var policy *model.EgressPolicy
	if vm.EgressPolicyID != "" {
		policy, _ = a.store.GetEgressPolicy(r.Context(), vm.EgressPolicyID)
	}
	logPath, logLines, err := a.lifecycle.VMLogs(r.Context(), vm, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"Title":          vm.Name,
		"User":           current(r),
		"VM":             vm,
		"SSHKey":         key,
		"IngressRules":   ingressRules,
		"Networks":       networks,
		"Network":        network,
		"EgressPolicies": policies,
		"EgressPolicy":   policy,
		"LogPath":        logPath,
		"LogLines":       logLines,
	}, nil
}

func (a *App) renderVMDetailError(w http.ResponseWriter, r *http.Request, id string, err error) {
	data, dataErr := a.vmDetailData(r, id)
	if dataErr != nil {
		http.Error(w, dataErr.Error(), http.StatusInternalServerError)
		return
	}
	if data == nil {
		http.NotFound(w, r)
		return
	}
	data["DetailError"] = err.Error()
	a.render(w, "vm_detail.html", data)
}

func (a *App) vmCreateForm(w http.ResponseWriter, r *http.Request) {
	req := createVMRequestFromForm(r)
	vm, err := a.lifecycle.CreateVM(r.Context(), req.toLifecycle())
	if err != nil {
		outcome := "failure"
		_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_create", "vm:"+req.Name, outcome, reqID(r), errorString(err))
		a.renderCreateVMForm(w, r, req, err, "")
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_create", "vm:"+vm.ID, "success", reqID(r), "")
	w.Header().Set("HX-Trigger", "vmsChanged")
	a.renderCreateVMForm(w, r, CreateVMRequest{}, nil, "VM "+vm.Name+" created.")
}

func (a *App) renderCreateVMForm(w http.ResponseWriter, r *http.Request, form CreateVMRequest, formErr error, success string) {
	data, err := a.dashboardData(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if form.Name != "" || form.SSHKeyID != "" || form.ExtraAuthorizedKeys != "" || form.NetworkID != "" || form.BaseImageID != "" || form.KernelID != "" || form.VCPUCount != 0 || form.MemMiB != 0 || form.RootFSSizeMiB != 0 {
		data["CreateVMForm"] = form
	}
	if formErr != nil {
		_, _, fields := classifyError(formErr)
		data["CreateVMError"] = formErr.Error()
		data["CreateVMFields"] = fields
	}
	if success != "" {
		data["CreateVMSuccess"] = success
	}
	a.render(w, "new_vm_form.html", data)
}

func (a *App) vmStartForm(w http.ResponseWriter, r *http.Request) {
	a.vmAction(w, r, "start")
}

func (a *App) vmStopForm(w http.ResponseWriter, r *http.Request) {
	a.vmAction(w, r, "stop")
}

func (a *App) vmRestartForm(w http.ResponseWriter, r *http.Request) {
	a.vmAction(w, r, "restart")
}

func (a *App) vmDeleteForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteVM(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_delete", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		if r.URL.Query().Get("redirect") == "detail" {
			a.renderVMDetailError(w, r, id, err)
			return
		}
		a.vmsTableError(w, r, err)
		return
	}
	if r.URL.Query().Get("redirect") == "detail" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.vmsTable(w, r)
}

func (a *App) vmActionForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	action := strings.TrimSpace(r.FormValue("action"))
	operation := "vm_" + action
	var err error
	switch action {
	case "start":
		err = a.lifecycle.StartVM(r.Context(), id)
	case "stop":
		err = a.lifecycle.StopVM(r.Context(), id)
	case "restart":
		_, err = a.lifecycle.RestartVM(r.Context(), id, 0, 0)
	case "delete":
		operation = "vm_delete"
		err = a.lifecycle.DeleteVM(r.Context(), id)
	default:
		operation = "vm_action"
		err = lifecycle.Invalid("VM action is invalid", map[string]string{"action": "select a valid action"})
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), operation, "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		if r.URL.Query().Get("redirect") == "detail" {
			a.renderVMDetailError(w, r, id, err)
			return
		}
		a.vmsTableError(w, r, err)
		return
	}
	if r.URL.Query().Get("redirect") == "detail" {
		if action == "delete" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/vms/"+id, http.StatusSeeOther)
		return
	}
	a.vmsTable(w, r)
}

func (a *App) vmResourcesForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	restart := r.FormValue("restart") == "true" || r.FormValue("restart") == "on"
	vm, err := a.lifecycle.UpdateResources(r.Context(), id, atoiDefault(r.FormValue("vcpu_count"), 0), atoiDefault(r.FormValue("mem_mib"), 0), restart)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_resources_update", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderVMDetailError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/vms/"+vm.ID+"#resources", http.StatusSeeOther)
}

func (a *App) vmIngressRuleForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rule, err := a.lifecycle.AddIngressRule(r.Context(), id, r.FormValue("protocol"), atoiDefault(r.FormValue("host_port"), 0), atoiDefault(r.FormValue("guest_port"), 0), r.FormValue("description"))
	outcome := "success"
	target := "vm:" + id
	if rule != nil {
		target = "ingress-rule:" + rule.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ingress_rule_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderVMDetailError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/vms/"+id+"#networking", http.StatusSeeOther)
}

func (a *App) vmIngressRuleDeleteForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ruleID := r.PathValue("rule_id")
	err := a.lifecycle.DeleteIngressRule(r.Context(), id, ruleID)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ingress_rule_delete", "ingress-rule:"+ruleID, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderVMDetailError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/vms/"+id+"#networking", http.StatusSeeOther)
}

func (a *App) vmEgressPolicyForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	vm, err := a.lifecycle.SetVMEgressPolicy(r.Context(), id, r.FormValue("egress_mode"), r.FormValue("egress_policy_id"))
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "egress_policy_assign", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderVMDetailError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/vms/"+vm.ID+"#networking", http.StatusSeeOther)
}

func (a *App) uiNetworkCreate(w http.ResponseWriter, r *http.Request) {
	network, err := a.lifecycle.CreateNetwork(r.Context(), r.FormValue("name"), r.FormValue("cidr"), r.FormValue("gateway_ip"))
	outcome := "success"
	target := "network"
	if network != nil {
		target = "network:" + network.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "network_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderDashboardError(w, r, err)
		return
	}
	http.Redirect(w, r, "/#networks", http.StatusSeeOther)
}

func (a *App) uiNetworkDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteNetwork(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "network_delete", "network:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderDashboardError(w, r, err)
		return
	}
	http.Redirect(w, r, "/#networks", http.StatusSeeOther)
}

func (a *App) uiEgressPolicyCreate(w http.ResponseWriter, r *http.Request) {
	policy, err := a.lifecycle.CreateEgressPolicy(r.Context(), r.FormValue("name"), r.FormValue("mode"), r.FormValue("tcp_ports"), r.FormValue("udp_ports"), r.FormValue("cidrs"))
	outcome := "success"
	target := "egress-policy"
	if policy != nil {
		target = "egress-policy:" + policy.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "egress_policy_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderDashboardError(w, r, err)
		return
	}
	http.Redirect(w, r, "/#egress-policies", http.StatusSeeOther)
}

func (a *App) uiEgressPolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteEgressPolicy(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "egress_policy_delete", "egress-policy:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderDashboardError(w, r, err)
		return
	}
	http.Redirect(w, r, "/#egress-policies", http.StatusSeeOther)
}

func (a *App) uiHostOrphansCleanup(w http.ResponseWriter, r *http.Request) {
	_, err := a.lifecycle.CleanupHostOrphans(r.Context())
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "host_orphans_cleanup", "host", outcome, reqID(r), errorString(err))
	if err != nil {
		a.renderDashboardError(w, r, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) vmAction(w http.ResponseWriter, r *http.Request, action string) {
	id := r.PathValue("id")
	var err error
	switch action {
	case "start":
		err = a.lifecycle.StartVM(r.Context(), id)
	case "stop":
		err = a.lifecycle.StopVM(r.Context(), id)
	case "restart":
		_, err = a.lifecycle.RestartVM(r.Context(), id, 0, 0)
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_"+action, "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		if r.URL.Query().Get("redirect") == "detail" {
			a.renderVMDetailError(w, r, id, err)
			return
		}
		a.vmsTableError(w, r, err)
		return
	}
	if r.URL.Query().Get("redirect") == "detail" {
		http.Redirect(w, r, "/vms/"+id, http.StatusSeeOther)
		return
	}
	a.vmsTable(w, r)
}

func (a *App) apiHealth(w http.ResponseWriter, r *http.Request) {
	a.json(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC()})
}

func (a *App) apiSession(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	a.json(w, http.StatusOK, map[string]any{"user": u.Username, "is_admin": u.IsAdmin, "csrf": u.CSRF})
}

type APITokenCreateRequest struct {
	Name      string `json:"name"`
	IsAdmin   *bool  `json:"is_admin"`
	ExpiresAt string `json:"expires_at"`
}

func (a *App) apiTokenList(w http.ResponseWriter, r *http.Request) {
	tokens, err := a.store.ListAPITokens(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, tokens)
}

func (a *App) apiTokenCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req APITokenCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		a.apiError(w, r, lifecycle.Invalid("Token name is required", map[string]string{"name": "required"}))
		return
	}
	admin := true
	if req.IsAdmin != nil {
		admin = *req.IsAdmin
	}
	var expiresAt *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			a.apiError(w, r, lifecycle.Invalid("Token expiry is invalid", map[string]string{"expires_at": "must be RFC3339"}))
			return
		}
		t = t.UTC()
		expiresAt = &t
	}
	secret := "bap_" + random.Hex(32)
	prefix := secret
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	token := model.APIToken{
		ID:        random.Hex(16),
		Name:      name,
		Prefix:    prefix,
		IsAdmin:   admin,
		CreatedBy: current(r).Username,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}
	if err := a.store.CreateAPIToken(r.Context(), token, hashAPIToken(secret)); err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "api_token_create", "api-token:"+token.ID, "success", reqID(r), "")
	a.json(w, http.StatusCreated, map[string]any{"token": token, "secret": secret})
}

func (a *App) apiTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.RevokeAPIToken(r.Context(), id); err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "api_token_revoke", "api-token:"+id, "success", reqID(r), "")
	a.json(w, http.StatusOK, map[string]any{"revoked": id})
}

func (a *App) apiHostStatus(w http.ResponseWriter, r *http.Request) {
	st := a.lifecycle.HostStatus(r.Context())
	a.json(w, http.StatusOK, st)
}

func (a *App) apiHostOrphans(w http.ResponseWriter, r *http.Request) {
	orphans, err := a.lifecycle.HostOrphans(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, orphans)
}

func (a *App) apiHostOrphansCleanup(w http.ResponseWriter, r *http.Request) {
	orphans, err := a.lifecycle.CleanupHostOrphans(r.Context())
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "host_orphans_cleanup", "host", outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"cleaned": orphans})
}

func (a *App) apiSSHKeyList(w http.ResponseWriter, r *http.Request) {
	keys, err := a.store.ListSSHKeys(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, keys)
}

func (a *App) apiSSHKeyGet(w http.ResponseWriter, r *http.Request) {
	key, err := a.store.GetSSHKey(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if key == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "SSH key not found", nil)
		return
	}
	a.json(w, http.StatusOK, key)
}

func (a *App) apiSSHKeyGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req SSHKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	generated, err := sshkeys.Generate(req.Name, current(r).Username)
	if err != nil {
		a.apiError(w, r, lifecycle.Invalid(err.Error(), nil))
		return
	}
	if err := a.store.CreateSSHKey(r.Context(), generated.Key); err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ssh_key_generate", "ssh-key:"+generated.Key.ID, "success", reqID(r), "")
	a.json(w, http.StatusCreated, map[string]any{"key": generated.Key, "private_key": generated.PrivateKey})
}

func (a *App) apiSSHKeyImport(w http.ResponseWriter, r *http.Request) {
	var req SSHKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	key, err := sshkeys.Import(req.Name, req.PublicKey, current(r).Username)
	if err != nil {
		a.apiError(w, r, lifecycle.Invalid(err.Error(), nil))
		return
	}
	if err := a.store.CreateSSHKey(r.Context(), *key); err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ssh_key_import", "ssh-key:"+key.ID, "success", reqID(r), "")
	a.json(w, http.StatusCreated, key)
}

func (a *App) apiSSHKeyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.DeleteSSHKey(r.Context(), id); err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ssh_key_delete", "ssh-key:"+id, "success", reqID(r), "")
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) apiBaseImageList(w http.ResponseWriter, r *http.Request) {
	images, err := a.store.ListBaseImages(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, images)
}

func (a *App) apiBaseImageRegister(w http.ResponseWriter, r *http.Request) {
	var req lifecycle.RegisterBaseImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	image, err := a.lifecycle.RegisterBaseImage(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "base-image"
	if image != nil {
		target = "base-image:" + image.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_register", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, image)
}

func (a *App) apiBaseImageBuild(w http.ResponseWriter, r *http.Request) {
	var req lifecycle.BuildBaseImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	job, err := a.lifecycle.StartImageBuild(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "image-build-job"
	if job != nil {
		target = "image-build-job:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_build", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusAccepted, job)
}

type BaseImageStatusRequest struct {
	Status string `json:"status"`
}

func (a *App) apiBaseImageUpdate(w http.ResponseWriter, r *http.Request) {
	var req BaseImageStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	image, err := a.lifecycle.UpdateBaseImageStatus(r.Context(), r.PathValue("id"), req.Status)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_status", "base-image:"+r.PathValue("id"), outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, image)
}

func (a *App) apiBaseImageDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteBaseImage(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "base_image_delete", "base-image:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) apiImageBuildJobGet(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetImageBuildJob(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "image build job not found", nil)
		return
	}
	a.json(w, http.StatusOK, job)
}

func (a *App) apiImageBuildJobLogs(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetImageBuildJob(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "image build job not found", nil)
		return
	}
	_, lines, err := tailFile(job.LogPath, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"path": job.LogPath, "lines": lines})
}

func (a *App) apiImageHookList(w http.ResponseWriter, r *http.Request) {
	hooks, err := a.store.ListImageHooks(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, hooks)
}

func (a *App) apiImageHookCreate(w http.ResponseWriter, r *http.Request) {
	var req lifecycle.ImageHookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	hook, err := a.lifecycle.CreateImageHook(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "image-hook"
	if hook != nil {
		target = "image-hook:" + hook.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "image_hook_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, hook)
}

func (a *App) apiImageHookDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteImageHook(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "image_hook_delete", "image-hook:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) apiKernelList(w http.ResponseWriter, r *http.Request) {
	kernels, err := a.store.ListKernels(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, kernels)
}

func (a *App) apiKernelFirecrackerCIScan(w http.ResponseWriter, r *http.Request) {
	var req lifecycle.DiscoverFirecrackerCIKernelsRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
			return
		}
	}
	job, err := a.lifecycle.StartKernelDiscovery(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "kernel-discovery"
	if job != nil {
		target = "kernel-discovery:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_discovery_scan", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusAccepted, job)
}

func (a *App) apiKernelDiscoveryJobList(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.ListKernelDiscoveryJobs(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, jobs)
}

func (a *App) apiKernelDiscoveryJobGet(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetKernelDiscoveryJob(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "kernel discovery job not found", nil)
		return
	}
	a.json(w, http.StatusOK, job)
}

func (a *App) apiKernelDiscoveryItemList(w http.ResponseWriter, r *http.Request) {
	items, err := a.store.ListKernelDiscoveryItems(r.Context(), r.URL.Query().Get("job_id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, items)
}

func (a *App) apiKernelImportFirecrackerCI(w http.ResponseWriter, r *http.Request) {
	var req lifecycle.ImportFirecrackerCIKernelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	kernel, err := a.lifecycle.ImportFirecrackerCIKernel(r.Context(), req, current(r).Username)
	outcome := "success"
	target := "kernel"
	if kernel != nil {
		target = "kernel:" + kernel.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_import_firecracker_ci", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, kernel)
}

func (a *App) apiKernelUpload(w http.ResponseWriter, r *http.Request) {
	kernel, err := a.uploadKernelFromRequest(r)
	outcome := "success"
	target := "kernel"
	if kernel != nil {
		target = "kernel:" + kernel.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_upload", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, kernel)
}

func (a *App) apiKernelUpdate(w http.ResponseWriter, r *http.Request) {
	var req lifecycle.KernelUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	kernel, err := a.lifecycle.UpdateKernel(r.Context(), r.PathValue("id"), req)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_update", "kernel:"+r.PathValue("id"), outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, kernel)
}

func (a *App) apiKernelDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteKernel(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_delete", "kernel:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) apiKernelTest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := a.lifecycle.StartKernelTest(r.Context(), id, current(r).Username)
	outcome := "success"
	target := "kernel:" + id
	if job != nil {
		target = "kernel-test-job:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "kernel_test", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusAccepted, model.EnrichKernelTestJob(*job))
}

func (a *App) apiKernelTestJobGet(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetKernelTestJob(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "kernel test job not found", nil)
		return
	}
	a.json(w, http.StatusOK, model.EnrichKernelTestJob(*job))
}

func (a *App) apiKernelTestJobLogs(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetKernelTestJob(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "kernel test job not found", nil)
		return
	}
	_, lines, err := tailFile(job.LogPath, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"path": job.LogPath, "lines": lines})
}

func (a *App) apiVMList(w http.ResponseWriter, r *http.Request) {
	vms, err := a.store.ListVMs(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, vms)
}

func (a *App) apiVMGet(w http.ResponseWriter, r *http.Request) {
	vm, err := a.store.GetVM(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if vm == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "VM not found", nil)
		return
	}
	a.json(w, http.StatusOK, vm)
}

func (a *App) apiVMCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	vm, err := a.lifecycle.CreateVM(r.Context(), req.toLifecycle())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_create", "vm:"+vm.ID, "success", reqID(r), "")
	a.json(w, http.StatusCreated, vm)
}

func (a *App) apiVMStart(w http.ResponseWriter, r *http.Request) {
	a.apiAction(w, r, "start")
}

func (a *App) apiVMStop(w http.ResponseWriter, r *http.Request) {
	a.apiAction(w, r, "stop")
}

func (a *App) apiVMRestart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req ResourceRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	vm, err := a.lifecycle.RestartVM(r.Context(), id, req.VCPUCount, req.MemMiB)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_restart", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, vm)
}

func (a *App) apiVMResources(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req ResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	vm, err := a.lifecycle.UpdateResources(r.Context(), id, req.VCPUCount, req.MemMiB, req.Restart)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_resources_update", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, vm)
}

func (a *App) apiVMLogs(w http.ResponseWriter, r *http.Request) {
	vm, err := a.store.GetVM(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if vm == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "VM not found", nil)
		return
	}
	path, lines, err := a.lifecycle.VMLogs(r.Context(), vm, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"path": path, "lines": lines})
}

func (a *App) apiVMExec(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req lifecycle.VMExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	result, err := a.lifecycle.ExecuteVMCommand(r.Context(), id, req)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_exec", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, result)
}

func (a *App) apiVMExecJobList(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.ListVMExecJobs(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, jobs)
}

func (a *App) apiVMExecJobCreate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req lifecycle.VMExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	job, err := a.lifecycle.StartVMExecJob(r.Context(), id, req, current(r).Username)
	outcome := "success"
	target := "vm:" + id
	if job != nil {
		target = "vm-exec-job:" + job.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_exec_job_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusAccepted, job)
}

func (a *App) apiVMExecJobGet(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetVMExecJob(r.Context(), r.PathValue("id"), r.PathValue("job_id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "exec job not found", nil)
		return
	}
	a.json(w, http.StatusOK, job)
}

func (a *App) apiVMExecJobLogs(w http.ResponseWriter, r *http.Request) {
	job, err := a.store.GetVMExecJob(r.Context(), r.PathValue("id"), r.PathValue("job_id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if job == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "exec job not found", nil)
		return
	}
	if job.LogPath == "" {
		a.json(w, http.StatusOK, map[string]any{"path": "", "lines": []string{}})
		return
	}
	_, lines, err := tailFile(job.LogPath, atoiDefault(r.URL.Query().Get("lines"), 300))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"path": job.LogPath, "lines": lines})
}

func (a *App) apiVMExecJobCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	jobID := r.PathValue("job_id")
	job, err := a.lifecycle.CancelVMExecJob(r.Context(), id, jobID)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_exec_job_cancel", "vm-exec-job:"+jobID, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, job)
}

func (a *App) apiVMNetwork(w http.ResponseWriter, r *http.Request) {
	vm, err := a.store.GetVM(r.Context(), r.PathValue("id"))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	if vm == nil {
		a.writeAPIError(w, r, http.StatusNotFound, "not_found", "VM not found", nil)
		return
	}
	ingress, err := a.store.ListIngressRules(r.Context(), vm.ID)
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	var network *model.Network
	if vm.NetworkID != "" {
		network, _ = a.store.GetNetwork(r.Context(), vm.NetworkID)
	}
	var policy *model.EgressPolicy
	if vm.EgressPolicyID != "" {
		policy, _ = a.store.GetEgressPolicy(r.Context(), vm.EgressPolicyID)
	}
	a.json(w, http.StatusOK, map[string]any{"vm": vm, "network": network, "ingress_rules": ingress, "egress_policy": policy})
}

func (a *App) apiIngressRuleCreate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req IngressRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	rule, err := a.lifecycle.AddIngressRule(r.Context(), id, req.Protocol, req.HostPort, req.GuestPort, req.Description)
	outcome := "success"
	target := "vm:" + id
	if rule != nil {
		target = "ingress-rule:" + rule.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ingress_rule_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, rule)
}

func (a *App) apiIngressRuleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ruleID := r.PathValue("rule_id")
	err := a.lifecycle.DeleteIngressRule(r.Context(), id, ruleID)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "ingress_rule_delete", "ingress-rule:"+ruleID, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"deleted": ruleID})
}

func (a *App) apiVMEgressPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req VMEgressPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	vm, err := a.lifecycle.SetVMEgressPolicy(r.Context(), id, req.Mode, req.EgressPolicyID)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "egress_policy_assign", "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, vm)
}

func (a *App) apiAction(w http.ResponseWriter, r *http.Request, action string) {
	id := r.PathValue("id")
	var err error
	switch action {
	case "start":
		err = a.lifecycle.StartVM(r.Context(), id)
	case "stop":
		err = a.lifecycle.StopVM(r.Context(), id)
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_"+action, "vm:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	vm, _ := a.store.GetVM(r.Context(), id)
	a.json(w, http.StatusOK, vm)
}

func (a *App) apiVMDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.lifecycle.DeleteVM(r.Context(), id); err != nil {
		a.apiError(w, r, err)
		return
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "vm_delete", "vm:"+id, "success", reqID(r), "")
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) apiNetworkList(w http.ResponseWriter, r *http.Request) {
	networks, err := a.store.ListNetworks(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, networks)
}

func (a *App) apiNetworkCreate(w http.ResponseWriter, r *http.Request) {
	var req NetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	network, err := a.lifecycle.CreateNetwork(r.Context(), req.Name, req.CIDR, req.GatewayIP)
	outcome := "success"
	target := "network"
	if network != nil {
		target = "network:" + network.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "network_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, network)
}

func (a *App) apiNetworkDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteNetwork(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "network_delete", "network:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) apiEgressPolicyList(w http.ResponseWriter, r *http.Request) {
	policies, err := a.store.ListEgressPolicies(r.Context())
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, policies)
}

func (a *App) apiEgressPolicyCreate(w http.ResponseWriter, r *http.Request) {
	var req EgressPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeAPIError(w, r, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	policy, err := a.lifecycle.CreateEgressPolicy(r.Context(), req.Name, req.Mode, req.TCPPorts, req.UDPPorts, req.CIDRs)
	outcome := "success"
	target := "egress-policy"
	if policy != nil {
		target = "egress-policy:" + policy.ID
	}
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "egress_policy_create", target, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusCreated, policy)
}

func (a *App) apiEgressPolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.lifecycle.DeleteEgressPolicy(r.Context(), id)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "egress_policy_delete", "egress-policy:"+id, outcome, reqID(r), errorString(err))
	if err != nil {
		a.apiError(w, r, err)
		return
	}
	a.json(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *App) wsTerminal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	vm, err := a.store.GetVM(r.Context(), id)
	if err != nil || vm == nil {
		http.NotFound(w, r)
		return
	}
	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "terminal_start", "vm:"+id, "success", reqID(r), "metadata")
	size := lifecycle.TerminalSize{
		Cols: atoiDefault(r.URL.Query().Get("cols"), 0),
		Rows: atoiDefault(r.URL.Query().Get("rows"), 0),
	}
	if err := a.lifecycle.SSHTerminal(r.Context(), vm, conn, size); err != nil && !errors.Is(err, context.Canceled) {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("\r\nterminal error: "+err.Error()+"\r\n"))
	}
	_ = a.store.Audit(r.Context(), current(r).Username, sourceIP(r), "terminal_end", "vm:"+id, "success", reqID(r), "metadata")
}

func (a *App) checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, allowed := range a.cfg.Server.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

type CreateVMRequest struct {
	Name                string `json:"name"`
	VCPUCount           int    `json:"vcpu_count"`
	MemMiB              int    `json:"mem_mib"`
	SSHPort             int    `json:"ssh_port"`
	DevUser             string `json:"dev_user"`
	SSHKeyID            string `json:"ssh_key_id"`
	ExtraAuthorizedKeys string `json:"extra_authorized_keys"`
	RepoURL             string `json:"repo_url"`
	GitRef              string `json:"git_ref"`
	EgressMode          string `json:"egress_mode"`
	EgressPolicyID      string `json:"egress_policy_id"`
	NetworkMode         string `json:"network_mode"`
	NetworkID           string `json:"network_id"`
	BaseImageID         string `json:"base_image_id"`
	RootFSSizeMiB       int    `json:"rootfs_size_mib"`
	KernelID            string `json:"kernel_id"`
}

func createVMRequestFromForm(r *http.Request) CreateVMRequest {
	return CreateVMRequest{
		Name:                r.FormValue("name"),
		VCPUCount:           atoiDefault(r.FormValue("vcpu_count"), 2),
		MemMiB:              atoiDefault(r.FormValue("mem_mib"), 2048),
		SSHPort:             atoiDefault(r.FormValue("ssh_port"), 0),
		DevUser:             defaultString(r.FormValue("dev_user"), "dev"),
		SSHKeyID:            r.FormValue("ssh_key_id"),
		ExtraAuthorizedKeys: r.FormValue("extra_authorized_keys"),
		RepoURL:             r.FormValue("repo_url"),
		GitRef:              defaultString(r.FormValue("git_ref"), "HEAD"),
		EgressMode:          defaultString(r.FormValue("egress_mode"), "allow_all"),
		EgressPolicyID:      r.FormValue("egress_policy_id"),
		NetworkMode:         defaultString(r.FormValue("network_mode"), "routed_ptp"),
		NetworkID:           r.FormValue("network_id"),
		BaseImageID:         r.FormValue("base_image_id"),
		RootFSSizeMiB:       atoiDefault(r.FormValue("rootfs_size_mib"), 0),
		KernelID:            r.FormValue("kernel_id"),
	}
}

func (r CreateVMRequest) toLifecycle() lifecycle.CreateRequest {
	return lifecycle.CreateRequest{
		Name:                r.Name,
		VCPUCount:           r.VCPUCount,
		MemMiB:              r.MemMiB,
		SSHPort:             r.SSHPort,
		DevUser:             r.DevUser,
		SSHKeyID:            r.SSHKeyID,
		ExtraAuthorizedKeys: r.ExtraAuthorizedKeys,
		RepoURL:             r.RepoURL,
		GitRef:              r.GitRef,
		EgressMode:          r.EgressMode,
		EgressPolicyID:      r.EgressPolicyID,
		NetworkMode:         r.NetworkMode,
		NetworkID:           r.NetworkID,
		BaseImageID:         r.BaseImageID,
		RootFSSizeMiB:       r.RootFSSizeMiB,
		KernelID:            r.KernelID,
	}
}

type SSHKeyRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type ResourceRequest struct {
	VCPUCount int  `json:"vcpu_count"`
	MemMiB    int  `json:"mem_mib"`
	Restart   bool `json:"restart"`
}

type NetworkRequest struct {
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`
	GatewayIP string `json:"gateway_ip"`
}

type IngressRuleRequest struct {
	Protocol    string `json:"protocol"`
	HostPort    int    `json:"host_port"`
	GuestPort   int    `json:"guest_port"`
	Description string `json:"description"`
}

type EgressPolicyRequest struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	TCPPorts string `json:"tcp_ports"`
	UDPPorts string `json:"udp_ports"`
	CIDRs    string `json:"cidrs"`
}

type VMEgressPolicyRequest struct {
	Mode           string `json:"mode"`
	EgressPolicyID string `json:"egress_policy_id"`
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	err := json.NewDecoder(r.Body).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func atoiDefault(s string, def int) int {
	var v int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &v)
	if err != nil || v == 0 {
		return def
	}
	return v
}

func defaultString(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return strings.TrimSpace(s)
}

func parseListField(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := []string{}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func (a *App) uploadKernelFromRequest(r *http.Request) (*model.Kernel, error) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		return nil, lifecycle.Invalid("Kernel upload form is invalid", map[string]string{"kernel": err.Error()})
	}
	file, header, err := r.FormFile("kernel")
	if err != nil {
		return nil, lifecycle.Invalid("Kernel file is required", map[string]string{"kernel": "required"})
	}
	defer file.Close()
	var configReader io.Reader
	configName := ""
	configFile, configHeader, err := r.FormFile("config")
	if err == nil {
		defer configFile.Close()
		configReader = configFile
		configName = configHeader.Filename
	} else if !errors.Is(err, http.ErrMissingFile) {
		return nil, lifecycle.Invalid("Kernel config upload is invalid", map[string]string{"config": err.Error()})
	}
	return a.lifecycle.UploadKernel(r.Context(), lifecycle.UploadKernelRequest{
		Name:         r.FormValue("name"),
		Version:      r.FormValue("version"),
		KernelName:   header.Filename,
		KernelReader: file,
		ConfigName:   configName,
		ConfigReader: configReader,
	}, current(r).Username)
}

func tailFile(path string, lines int) (string, []string, error) {
	if lines <= 0 || lines > 2000 {
		lines = 300
	}
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

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func reqID(r *http.Request) string {
	if v, ok := r.Context().Value(contextKey("request_id")).(string); ok {
		return v
	}
	return ""
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
