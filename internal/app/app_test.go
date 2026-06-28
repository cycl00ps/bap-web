package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"bap-web/internal/config"
	"bap-web/internal/model"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestNewParsesTemplates(t *testing.T) {
	a, _ := newTestApp(t)
	a.Close()
}

func TestTemplatesWrapDataTables(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("templates", "*.html"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no templates found")
	}
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "<table") {
				continue
			}
			prev := ""
			for j := i - 1; j >= 0; j-- {
				if strings.TrimSpace(lines[j]) != "" {
					prev = strings.TrimSpace(lines[j])
					break
				}
			}
			if !strings.Contains(prev, `class="table-wrap"`) {
				t.Fatalf("%s:%d table is not wrapped in .table-wrap", path, i+1)
			}
		}
	}
}

func TestUILayoutCSSIncludesResponsiveTableContract(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("static", "app.css"))
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	for _, want := range []string{
		".table-wrap",
		"overflow-x: auto",
		".grid > *, .split > *",
		".dashboard-grid",
		".terminal-shell",
		".settings-card summary",
		".settings-card summary::before",
		".settings-card[open] > summary::before",
		".log-details .log-view",
		"minmax(320px, 400px)",
		"minmax(280px, 360px)",
		"@media (max-width: 1180px)",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("missing CSS contract %q", want)
		}
	}
}

func TestAPIDocsMentionAgentRoutesRegisteredByApp(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "API_FOR_AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := os.ReadFile("app.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		"/api/tokens",
		"/api/vms/{id}/exec",
		"/api/vms/{id}/exec-jobs",
		"/api/vms/{id}/exec-jobs/{job_id}",
		"/api/vms/{id}/exec-jobs/{job_id}/logs",
		"/api/vms/{id}/exec-jobs/{job_id}/cancel",
	} {
		if !strings.Contains(string(doc), route) {
			t.Fatalf("API_FOR_AGENTS.md missing %s", route)
		}
		if !strings.Contains(string(app), route) {
			t.Fatalf("app route registration missing %s", route)
		}
	}
}

func TestPublicDocsRoutesServeAgentAndSwaggerDocs(t *testing.T) {
	a, _ := newTestApp(t)
	defer a.Close()

	cases := []struct {
		path     string
		contains []string
	}{
		{"/docs/agents", []string{"Agent Instructions", "/docs/agents.md", "/openapi.json"}},
		{"/docs/agents.md", []string{"BAP Web Agent Guide", "Authorization: Bearer", "Agents should not expect unauthenticated operational access"}},
		{"/llms.txt", []string{"Agent guide: /docs/agents.md", "OpenAPI specification: /openapi.json"}},
		{"/docs/api", []string{"SwaggerUIBundle", "url: \"/openapi.json\""}},
		{"/static/vendor/swagger-ui/swagger-ui-bundle.js", []string{"SwaggerUIBundle"}},
		{"/static/vendor/swagger-ui/swagger-ui.css", []string{".swagger-ui"}},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()

		a.Router().ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body = %s", tc.path, rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		for _, want := range tc.contains {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %q", tc.path, want)
			}
		}
		if !strings.HasPrefix(tc.path, "/static/") {
			for _, forbidden := range []string{"password=", "initial-admin.txt"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("%s leaks forbidden marker %q", tc.path, forbidden)
				}
			}
		}
	}
}

func TestDocsHTMLPagesPreserveAuthenticatedNavigation(t *testing.T) {
	for _, path := range []string{"/docs/agents", "/docs/api"} {
		t.Run("unauthenticated "+path, func(t *testing.T) {
			a, _ := newTestApp(t)
			defer a.Close()

			body := getPathBody(t, a, path, "")

			assertContains(t, body, `href="/docs/agents"`)
			assertNotContains(t, body, `href="/ssh-keys"`)
			assertNotContains(t, body, `href="/images"`)
			assertNotContains(t, body, `href="/kernels"`)
			assertNotContains(t, body, "Logout")
		})

		t.Run("admin "+path, func(t *testing.T) {
			a, sess := newAuthenticatedTestAppWithRole(t, true)
			defer a.Close()

			body := getPathBody(t, a, path, sess.ID)

			assertContains(t, body, `href="/docs/agents"`)
			assertContains(t, body, `href="/ssh-keys"`)
			assertContains(t, body, `href="/images"`)
			assertContains(t, body, `href="/kernels"`)
			assertContains(t, body, "admin")
			assertContains(t, body, "Logout")
		})

		t.Run("normal user "+path, func(t *testing.T) {
			a, sess := newAuthenticatedTestAppWithRole(t, false)
			defer a.Close()

			body := getPathBody(t, a, path, sess.ID)

			assertContains(t, body, `href="/docs/agents"`)
			assertContains(t, body, `href="/ssh-keys"`)
			assertNotContains(t, body, `href="/images"`)
			assertNotContains(t, body, `href="/kernels"`)
			assertContains(t, body, "user")
			assertContains(t, body, "Logout")
		})
	}
}

func TestOpenAPISpecValidAndCoversRegisteredAPIRoutes(t *testing.T) {
	a, _ := newTestApp(t)
	defer a.Close()

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rr := httptest.NewRecorder()
	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("load OpenAPI: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI: %v", err)
	}
	if doc.Components.SecuritySchemes["BearerAuth"] == nil {
		t.Fatal("OpenAPI missing BearerAuth security scheme")
	}
	if len(doc.Security) == 0 || doc.Security[0]["BearerAuth"] == nil {
		t.Fatal("OpenAPI missing global bearer auth requirement")
	}

	var raw struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}

	appSource, err := os.ReadFile("app.go")
	if err != nil {
		t.Fatal(err)
	}
	routeRe := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) (/api[^"]+)"`)
	for _, match := range routeRe.FindAllStringSubmatch(string(appSource), -1) {
		method := strings.ToLower(match[1])
		path := match[2]
		methods := raw.Paths[path]
		if methods == nil {
			t.Fatalf("OpenAPI missing path %s", path)
		}
		if methods[method] == nil {
			t.Fatalf("OpenAPI missing method %s %s", strings.ToUpper(method), path)
		}
	}
}

func TestOpenAPIOperationsHaveStableIDsAndHealthIsPublic(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("docs", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Paths map[string]map[string]struct {
			OperationID string            `json:"operationId"`
			Security    []map[string]any  `json:"security"`
			Parameters  []json.RawMessage `json:"parameters"`
			RequestBody map[string]any    `json:"requestBody"`
			Responses   map[string]any    `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(spec, &raw); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for path, methods := range raw.Paths {
		for method, op := range methods {
			if op.OperationID == "" {
				t.Fatalf("%s %s missing operationId", strings.ToUpper(method), path)
			}
			key := strings.ToUpper(method) + " " + path
			if previous := seen[op.OperationID]; previous != "" {
				t.Fatalf("duplicate operationId %q on %s and %s", op.OperationID, previous, key)
			}
			seen[op.OperationID] = key
			if len(op.Responses) == 0 {
				t.Fatalf("%s missing responses", key)
			}
		}
	}
	health := raw.Paths["/api/health"]["get"]
	if health.Security == nil || len(health.Security) != 0 {
		t.Fatalf("GET /api/health should explicitly disable auth, got %#v", health.Security)
	}
}

func TestAPIVMCreateMissingSSHMaterialReturnsStructuredError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	body := bytes.NewBufferString(`{"name":"nokey","vcpu_count":1,"mem_mib":512,"dev_user":"dev","git_ref":"HEAD","egress_mode":"allow_all","network_mode":"routed_ptp"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/vms", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "unprocessable" {
		t.Fatalf("code = %q, body = %#v", got.Error.Code, got)
	}
	if got.Error.Fields["ssh_key_id"] == "" || got.Error.Fields["extra_authorized_keys"] == "" {
		t.Fatalf("expected field errors, got %#v", got.Error.Fields)
	}
}

func TestAPITokenAuthenticatesWithoutCSRF(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	createReq := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(`{"name":"agent"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("X-CSRF-Token", sess.CSRFToken)
	createReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	createRR := httptest.NewRecorder()

	a.Router().ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", createRR.Code, createRR.Body.String())
	}
	var created struct {
		Token  model.APIToken `json:"token"`
		Secret string         `json:"secret"`
	}
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Token.Name != "agent" || !strings.HasPrefix(created.Secret, "bap_") {
		t.Fatalf("unexpected token response: %#v", created)
	}

	body := bytes.NewBufferString(`{"name":"agent-net","cidr":"172.31.90.0/30"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/networks", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+created.Secret)
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("bearer request status = %d, body = %s", rr.Code, rr.Body.String())
	}
	sessionReq := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	sessionReq.Header.Set("Authorization", "Bearer "+created.Secret)
	sessionRR := httptest.NewRecorder()
	a.Router().ServeHTTP(sessionRR, sessionReq)
	if sessionRR.Code != http.StatusOK || !strings.Contains(sessionRR.Body.String(), `"user":"admin"`) || !strings.Contains(sessionRR.Body.String(), `"is_admin":false`) {
		t.Fatalf("token session response = %d, body = %s", sessionRR.Code, sessionRR.Body.String())
	}
}

func TestAPITokenOwnershipAndMintingRules(t *testing.T) {
	a, adminSess := newAuthenticatedTestApp(t)
	defer a.Close()
	dev := addTestUser(t, a, "u2", "dev", false)
	devSess := addTestSession(t, a, "sess-dev", dev)

	usersReq := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	usersReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: adminSess.ID})
	usersRR := httptest.NewRecorder()
	a.Router().ServeHTTP(usersRR, usersReq)
	if usersRR.Code != http.StatusOK || !strings.Contains(usersRR.Body.String(), `"username":"dev"`) {
		t.Fatalf("admin user list status = %d, body = %s", usersRR.Code, usersRR.Body.String())
	}
	usersReq = httptest.NewRequest(http.MethodGet, "/api/users", nil)
	usersReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: devSess.ID})
	usersRR = httptest.NewRecorder()
	a.Router().ServeHTTP(usersRR, usersReq)
	if usersRR.Code != http.StatusForbidden {
		t.Fatalf("non-admin user list status = %d, body = %s", usersRR.Code, usersRR.Body.String())
	}

	createWithSession := func(sess model.Session, body string) (model.APIToken, string, int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", sess.CSRFToken)
		req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
		rr := httptest.NewRecorder()
		a.Router().ServeHTTP(rr, req)
		var created struct {
			Token  model.APIToken `json:"token"`
			Secret string         `json:"secret"`
		}
		if rr.Code == http.StatusCreated {
			if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
		}
		return created.Token, created.Secret, rr.Code, rr.Body.String()
	}
	createWithBearer := func(secret, body string) (model.APIToken, string, int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+secret)
		rr := httptest.NewRecorder()
		a.Router().ServeHTTP(rr, req)
		var created struct {
			Token  model.APIToken `json:"token"`
			Secret string         `json:"secret"`
		}
		if rr.Code == http.StatusCreated {
			if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
		}
		return created.Token, created.Secret, rr.Code, rr.Body.String()
	}

	devToken, devSecret, status, body := createWithSession(adminSess, `{"name":"agent","owner_user_id":"u2"}`)
	if status != http.StatusCreated {
		t.Fatalf("admin create for user status = %d, body = %s", status, body)
	}
	if devToken.OwnerUserID != "u2" || devToken.OwnerUsername != "dev" || devToken.IsAdmin || devToken.ExpiresAt == nil {
		t.Fatalf("unexpected dev token: %#v", devToken)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/tokens", nil)
	listReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: devSess.ID})
	listRR := httptest.NewRecorder()
	a.Router().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("dev list status = %d, body = %s", listRR.Code, listRR.Body.String())
	}
	var listed []model.APIToken
	if err := json.Unmarshal(listRR.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != devToken.ID {
		t.Fatalf("expected dev to see own token only, got %#v", listed)
	}

	_, _, status, _ = createWithSession(devSess, `{"name":"bad-owner","owner_user_id":"u1"}`)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin create for another owner status = %d", status)
	}
	_, _, status, _ = createWithSession(devSess, `{"name":"bad-admin","is_admin":true}`)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin create admin token status = %d", status)
	}
	_, _, status, _ = createWithBearer(devSecret, `{"name":"bad-mint"}`)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin bearer mint status = %d", status)
	}

	adminToken, adminSecret, status, body := createWithSession(adminSess, `{"name":"admin-agent","is_admin":true}`)
	if status != http.StatusCreated {
		t.Fatalf("admin token create status = %d, body = %s", status, body)
	}
	if !adminToken.IsAdmin || adminSecret == "" {
		t.Fatalf("unexpected admin token: %#v secret=%q", adminToken, adminSecret)
	}
	bearerToken, _, status, body := createWithBearer(adminSecret, `{"name":"admin-bearer-created","owner_user_id":"u2"}`)
	if status != http.StatusCreated {
		t.Fatalf("admin bearer create status = %d, body = %s", status, body)
	}
	if bearerToken.OwnerUserID != "u2" || bearerToken.IsAdmin {
		t.Fatalf("unexpected admin bearer-created token: %#v", bearerToken)
	}
}

func TestAPITokensPageCreateAndRoleControls(t *testing.T) {
	a, adminSess := newAuthenticatedTestApp(t)
	defer a.Close()
	dev := addTestUser(t, a, "u2", "dev", false)
	devSess := addTestSession(t, a, "sess-dev", dev)

	adminReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	adminReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: adminSess.ID})
	adminRR := httptest.NewRecorder()
	a.Router().ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusOK || !strings.Contains(adminRR.Body.String(), "API Tokens") || !strings.Contains(adminRR.Body.String(), "Admin token") {
		t.Fatalf("admin tokens page = %d, body = %s", adminRR.Code, adminRR.Body.String())
	}

	userReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	userReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: devSess.ID})
	userRR := httptest.NewRecorder()
	a.Router().ServeHTTP(userRR, userReq)
	if userRR.Code != http.StatusOK || strings.Contains(userRR.Body.String(), "Admin token") {
		t.Fatalf("user tokens page = %d, body = %s", userRR.Code, userRR.Body.String())
	}

	form := url.Values{}
	form.Set("csrf", devSess.CSRFToken)
	form.Set("name", "dev-agent")
	form.Set("expires_at", time.Now().UTC().Add(defaultAPITokenTTL).Format(time.RFC3339))
	createReq := httptest.NewRequest(http.MethodPost, "/ui/api-tokens", strings.NewReader(form.Encode()))
	createReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: devSess.ID})
	createRR := httptest.NewRecorder()
	a.Router().ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusOK || !strings.Contains(createRR.Body.String(), "Token Secret") || !strings.Contains(createRR.Body.String(), "bap_") {
		t.Fatalf("user token create page = %d, body = %s", createRR.Code, createRR.Body.String())
	}
}

func TestAPIBaseImageListIncludesDefaultImage(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/base-images", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var images []model.BaseImage
	if err := json.Unmarshal(rr.Body.Bytes(), &images); err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 {
		t.Fatalf("images = %#v", images)
	}
	if images[0].Name != "default-base-rootfs" || images[0].Status != "active" || images[0].VirtualSizeMiB != 2 {
		t.Fatalf("unexpected default image: %#v", images[0])
	}
}

func TestImagesPageBaseImageActionsUseDropdown(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	image, err := a.store.DefaultBaseImage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if image == nil {
		t.Fatal("default base image was not registered")
	}

	req := httptest.NewRequest(http.MethodGet, "/images", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`action="/ui/base-images/` + image.ID + `/action"`,
		`name="action"`,
		`Make active`,
		`Mark deprecated`,
		`Archive`,
		`Delete`,
		`Confirm`,
		`data-confirm-delete="Delete this base image?"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
}

func TestUIBaseImageActionUpdatesStatus(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	image, err := a.store.DefaultBaseImage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if image == nil {
		t.Fatal("default base image was not registered")
	}

	form := url.Values{
		"csrf":   {sess.CSRFToken},
		"action": {"mark_deprecated"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/base-images/"+image.ID+"/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	updated, err := a.store.GetBaseImage(context.Background(), image.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || updated.Status != "deprecated" {
		t.Fatalf("base image status was not updated: %#v", updated)
	}
}

func TestAPIKernelListIncludesDefaultKernel(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/kernels", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var kernels []model.Kernel
	if err := json.Unmarshal(rr.Body.Bytes(), &kernels); err != nil {
		t.Fatal(err)
	}
	if len(kernels) != 1 {
		t.Fatalf("kernels = %#v", kernels)
	}
	if kernels[0].Name != "default-kernel-5-10" || kernels[0].Status != "active" || kernels[0].SourceType != "configured" {
		t.Fatalf("unexpected default kernel: %#v", kernels[0])
	}
}

func TestAPIVMCreateRootFSSizeTooSmallReturnsStructuredError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	image, err := a.store.DefaultBaseImage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if image == nil {
		t.Fatal("default base image was not registered")
	}

	body := bytes.NewBufferString(`{"name":"smallfs","vcpu_count":1,"mem_mib":512,"dev_user":"dev","git_ref":"HEAD","egress_mode":"allow_all","network_mode":"routed_ptp","base_image_id":"` + image.ID + `","rootfs_size_mib":1}`)
	req := httptest.NewRequest(http.MethodPost, "/api/vms", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "invalid" || got.Error.Fields["rootfs_size_mib"] == "" {
		t.Fatalf("expected rootfs_size_mib field error, got %#v", got.Error)
	}
}

func TestAPIImageHookUploadCreatesAndDeletesContent(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	body := bytes.NewBufferString(`{"name":"bootstrap","source_type":"upload","content":"#!/bin/sh\necho ok"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/image-hooks", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var hook model.ImageHook
	if err := json.Unmarshal(rr.Body.Bytes(), &hook); err != nil {
		t.Fatal(err)
	}
	if hook.SourceType != "upload" || hook.ContentPath == "" || hook.Checksum == "" {
		t.Fatalf("unexpected hook response: %#v", hook)
	}
	if _, err := os.Stat(hook.ContentPath); err != nil {
		t.Fatal(err)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/image-hooks/"+hook.ID, nil)
	del.Header.Set("X-CSRF-Token", sess.CSRFToken)
	del.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	delRR := httptest.NewRecorder()
	a.Router().ServeHTTP(delRR, del)
	if delRR.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", delRR.Code, delRR.Body.String())
	}
	if _, err := os.Stat(hook.ContentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hook content was not removed: %v", err)
	}
}

func TestImagesPageIncludesBuildJobLogControls(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestImageBuildJob(t, a, model.ImageBuildJob{
		ID:         "job1",
		Status:     "running",
		Name:       "build-one",
		Filesystem: "ext4",
		SizeMiB:    2048,
		LogPath:    filepath.Join(a.cfg.Paths.LogDir, "job1.log"),
	})

	req := httptest.NewRequest(http.MethodGet, "/images?build_job=job1", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`data-open-build-job="job1"`,
		`id="build-job-job1"`,
		`data-build-log-toggle="job1"`,
		`data-build-log-url="/ui/image-build-jobs/job1/logs?lines=300"`,
		`id="build-log-row-job1"`,
		`View logs`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
}

func TestKernelsPageIncludesManagementControls(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestKernelDiscoveryJob(t, a, model.KernelDiscoveryJob{
		ID:           "disc1",
		Status:       "succeeded",
		SourceURL:    "https://s3.amazonaws.com/spec.ccfc.min",
		CIPrefix:     "firecracker-ci/v1.15/",
		Architecture: "x86_64",
		ItemCount:    1,
	})
	createTestKernelDiscoveryItems(t, a, "disc1", []model.KernelDiscoveryItem{{
		ID:           "artifact1",
		JobID:        "disc1",
		Version:      "6.1.155",
		Variant:      "standard",
		Architecture: "x86_64",
		CIPrefix:     "firecracker-ci/v1.15/",
		KernelKey:    "firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
		KernelURL:    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155",
	}})

	req := httptest.NewRequest(http.MethodGet, "/kernels", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`Registered Kernels`,
		`default-kernel-5-10`,
		`/ui/kernels/import-firecracker-ci`,
		`/ui/kernels/firecracker-ci/scan`,
		`/ui/kernels/upload`,
		`name="kernel"`,
		`Firecracker CI Discovery`,
		`data-discovery-status-panel`,
		`data-poll-discovery-job=""`,
		`data-discovery-panel-message>Complete</dd>`,
		`Refresh Firecracker CI kernels`,
		`https://s3.amazonaws.com/spec.ccfc.min?list-type=2&amp;prefix=firecracker-ci/`,
		`artifact1`,
		`6.1.155`,
		`Kernel Test Jobs`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
	for _, notWant := range []string{
		`firecracker-ci/v1.15/x86_64/vmlinux-6.1.155`,
		`placeholder="fc-6.1.155"`,
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("response should not include %q: %s", notWant, body)
		}
	}
}

func TestKernelsPagePollsOnlyRunningDiscoveryJob(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestKernelDiscoveryJob(t, a, model.KernelDiscoveryJob{
		ID:           "disc-running",
		Status:       "running",
		SourceURL:    "https://s3.amazonaws.com/spec.ccfc.min",
		CIPrefix:     "firecracker-ci/v1.15/",
		Architecture: "x86_64",
	})

	req := httptest.NewRequest(http.MethodGet, "/kernels?discovery_job=disc-running", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`data-poll-discovery-job="disc-running"`,
		`data-discovery-panel-message>Refreshing</dd>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
}

func TestKernelDiscoveryPollingJSForcesReloadForSameURL(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("templates", "kernels.html"))
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	for _, want := range []string{
		`const reloadDiscoveryFindings = id =>`,
		`window.location.reload();`,
		`window.location.replace(target);`,
		`window.setTimeout(() => reloadDiscoveryFindings(discoveryID), 750);`,
	} {
		if !strings.Contains(tpl, want) {
			t.Fatalf("missing %q in kernels template", want)
		}
	}
}

func TestAPIKernelDiscoveryScanAndItems(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Get("prefix") != "firecracker-ci/v1.15/x86_64/" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`<ListBucketResult>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155</Key></Contents>
  <Contents><Key>firecracker-ci/v1.15/x86_64/vmlinux-6.1.155.config</Key></Contents>
</ListBucketResult>`))
	}))
	defer server.Close()
	a.cfg.Kernels.FirecrackerCIBaseURL = server.URL

	req := httptest.NewRequest(http.MethodPost, "/api/kernels/firecracker-ci/scan", bytes.NewBufferString(`{"ci_prefix":"firecracker-ci/v1.15/"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var job model.KernelDiscoveryJob
	if err := json.Unmarshal(rr.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	waitForAppDiscoveryJob(t, a, job.ID)

	itemsReq := httptest.NewRequest(http.MethodGet, "/api/kernels/firecracker-ci/items?job_id="+job.ID, nil)
	itemsReq.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	itemsRR := httptest.NewRecorder()
	a.Router().ServeHTTP(itemsRR, itemsReq)
	if itemsRR.Code != http.StatusOK {
		t.Fatalf("items status = %d, body = %s", itemsRR.Code, itemsRR.Body.String())
	}
	var items []model.KernelDiscoveryItem
	if err := json.Unmarshal(itemsRR.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Version != "6.1.155" || items[0].ConfigKey == "" {
		t.Fatalf("unexpected items: %#v", items)
	}
}

func TestAPIKernelDiscoveryScanInvalidPrefixReturnsStructuredError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/kernels/firecracker-ci/scan", bytes.NewBufferString(`{"ci_prefix":"../bad"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "invalid" || got.Error.Fields["ci_prefix"] == "" {
		t.Fatalf("expected ci_prefix field error, got %#v", got.Error)
	}
}

func TestAPIKernelImportMissingArtifactReturnsNotFound(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/kernels/import-firecracker-ci", bytes.NewBufferString(`{"artifact_id":"missing"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestKernelsPageIncludesTestJobLogControls(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestKernelTestJob(t, a, model.KernelTestJob{
		ID:          "ktjob1",
		KernelID:    "kernel1",
		Status:      "succeeded",
		LogPath:     filepath.Join(a.cfg.Paths.LogDir, "ktjob1.log"),
		UnameResult: "Warning: Permanently added '172.31.0.2' (ED25519) to the list of known hosts. 5.10.245+ gateway-ok",
	})

	req := httptest.NewRequest(http.MethodGet, "/kernels?test_job=ktjob1", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`data-open-kernel-test-job="ktjob1"`,
		`id="kernel-test-job-ktjob1"`,
		`data-kernel-test-log-toggle="ktjob1"`,
		`data-kernel-test-log-url="/ui/kernel-test-jobs/ktjob1/logs?lines=300"`,
		`id="kernel-test-log-row-ktjob1"`,
		`5.10.245`,
		`>ok</span>`,
		`View logs`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
	if strings.Contains(body, "Permanently added") {
		t.Fatalf("kernel test table leaked raw SSH warning: %s", body)
	}
}

func TestAPIKernelTestJobGetIncludesCleanDerivedResult(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestKernelTestJob(t, a, model.KernelTestJob{
		ID:          "kt-clean",
		KernelID:    "kernel1",
		Status:      "succeeded",
		LogPath:     filepath.Join(a.cfg.Paths.LogDir, "kt-clean.log"),
		UnameResult: "Warning: Permanently added '172.31.0.2' (ED25519) to the list of known hosts. 5.10.245+ gateway-ok",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/kernel-test-jobs/kt-clean", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got model.KernelTestJob
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.KernelRelease != "5.10.245+" || got.GatewayOK == nil || !*got.GatewayOK || got.ResultSummary != "5.10.245+, gateway OK" {
		t.Fatalf("unexpected derived result: %#v", got)
	}
	if !strings.Contains(got.UnameResult, "Permanently added") {
		t.Fatalf("raw uname_result should be preserved for compatibility: %#v", got)
	}
}

func TestUIKernelTestJobLogsRenderRunningJobWithPolling(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	logPath := filepath.Join(a.cfg.Paths.LogDir, "kernel-running.log")
	writeTestFileWithContent(t, logPath, "booting\nssh ok\n", 0o600)
	createTestKernelTestJob(t, a, model.KernelTestJob{
		ID:       "kt-running",
		KernelID: "kernel1",
		Status:   "running",
		LogPath:  logPath,
	})

	req := httptest.NewRequest(http.MethodGet, "/ui/kernel-test-jobs/kt-running/logs?lines=10", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`data-poll="true"`, "kt-running", "booting", "ssh ok", "refreshing"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
}

func TestAPIKernelUploadMissingFileReturnsStructuredError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	body := &bytes.Buffer{}
	req := httptest.NewRequest(http.MethodPost, "/api/kernels/upload", body)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=empty")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "invalid" || got.Error.Fields["kernel"] == "" {
		t.Fatalf("expected kernel field error, got %#v", got.Error)
	}
}

func TestUIImageBuildJobLogsRenderRunningJobWithPolling(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	logPath := filepath.Join(a.cfg.Paths.LogDir, "running.log")
	writeTestFileWithContent(t, logPath, "first\nsecond\n", 0o600)
	createTestImageBuildJob(t, a, model.ImageBuildJob{
		ID:         "job-running",
		Status:     "running",
		Name:       "running-build",
		Filesystem: "ext4",
		SizeMiB:    2048,
		LogPath:    logPath,
	})

	req := httptest.NewRequest(http.MethodGet, "/ui/image-build-jobs/job-running/logs?lines=10", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`data-poll="true"`, "running-build", "first", "second", "refreshing"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
}

func TestUIImageBuildJobLogsRenderQueuedMissingLogAsEmpty(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestImageBuildJob(t, a, model.ImageBuildJob{
		ID:         "job-queued",
		Status:     "queued",
		Name:       "queued-build",
		Filesystem: "ext4",
		SizeMiB:    2048,
		LogPath:    filepath.Join(a.cfg.Paths.LogDir, "missing.log"),
	})

	req := httptest.NewRequest(http.MethodGet, "/ui/image-build-jobs/job-queued/logs", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `data-poll="true"`) || !strings.Contains(body, "No log output yet.") {
		t.Fatalf("unexpected response: %s", body)
	}
}

func TestUIImageBuildJobLogsStopPollingForSucceededJob(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	logPath := filepath.Join(a.cfg.Paths.LogDir, "done.log")
	writeTestFileWithContent(t, logPath, "complete\n", 0o600)
	createTestImageBuildJob(t, a, model.ImageBuildJob{
		ID:            "job-done",
		Status:        "succeeded",
		Name:          "done-build",
		Filesystem:    "ext4",
		SizeMiB:       2048,
		LogPath:       logPath,
		ResultImageID: "image1",
	})

	req := httptest.NewRequest(http.MethodGet, "/ui/image-build-jobs/job-done/logs", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `data-poll="false"`) || !strings.Contains(body, "image image1") || !strings.Contains(body, "complete") {
		t.Fatalf("unexpected response: %s", body)
	}
	if strings.Contains(body, "refreshing") {
		t.Fatalf("succeeded job should not show refreshing marker: %s", body)
	}
}

func TestUIImageBuildJobLogsRequiresAdmin(t *testing.T) {
	a, sess := newAuthenticatedTestAppWithRole(t, false)
	defer a.Close()

	req := httptest.NewRequest(http.MethodGet, "/ui/image-build-jobs/job1/logs", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPIImageBuildJobLogsMissingFileReturnsEmptyLines(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestImageBuildJob(t, a, model.ImageBuildJob{
		ID:         "job-api",
		Status:     "running",
		Name:       "api-build",
		Filesystem: "ext4",
		SizeMiB:    2048,
		LogPath:    filepath.Join(a.cfg.Paths.LogDir, "api-missing.log"),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/image-build-jobs/job-api/logs", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Path  string   `json:"path"`
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Path == "" || len(got.Lines) != 0 {
		t.Fatalf("unexpected log response: %#v", got)
	}
}

func TestDashboardUsesSharedPanelGrid(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Count(body, `class="dashboard-grid"`) != 3 {
		t.Fatalf("expected 3 dashboard grid sections, got response: %s", body)
	}
	for _, want := range []string{
		`id="new-vm-panel"`,
		`Create Network`,
		`Create Egress Policy`,
		`data-confirm-delete`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
}

func TestVMsTableUsesDropdownActionForm(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestVM(t, a, model.VM{ID: "vm-stopped", Name: "stoppedvm", State: model.VMStopped})
	createTestVM(t, a, model.VM{ID: "vm-running", Name: "runningvm", State: model.VMRunning})

	req := httptest.NewRequest(http.MethodGet, "/ui/vms-table", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`action="/ui/vms/vm-stopped/action"`,
		`hx-post="/ui/vms/vm-stopped/action"`,
		`action="/ui/vms/vm-running/action"`,
		`name="action"`,
		`value="start">Start</option>`,
		`value="stop">Stop</option>`,
		`value="restart">Restart</option>`,
		`value="delete">Delete</option>`,
		`Confirm`,
		`data-confirm-delete="Delete this VM?"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
	for _, notWant := range []string{
		`/ui/vms/vm-stopped/start`,
		`/ui/vms/vm-running/stop`,
		`/ui/vms/vm-stopped/restart`,
		`/ui/vms/vm-stopped/delete`,
		`>Open</a>`,
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("response should not include %q: %s", notWant, body)
		}
	}
}

func TestUIVMActionInvalidRendersTableError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestVM(t, a, model.VM{ID: "vm-invalid", Name: "invalidvm", State: model.VMStopped})

	form := url.Values{
		"csrf":   {sess.CSRFToken},
		"action": {"bad-action"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/vms/vm-invalid/action", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "VM action is invalid") {
		t.Fatalf("missing invalid action error: %s", rr.Body.String())
	}
}

func TestVMDetailUsesResizableTerminalAndCollapsedLogs(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestVM(t, a, model.VM{ID: "vm-detail", Name: "detailvm", State: model.VMRunning})

	req := httptest.NewRequest(http.MethodGet, "/vms/vm-detail", nil)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`id="terminal-shell" class="terminal-shell"`,
		`id="terminal" class="terminal"`,
		`new Terminal({cursorBlink: true, scrollback: 1000})`,
		`terminalSize`,
		`term.refresh(0, term.rows - 1)`,
		`type: "resize"`,
		`cols=${initialSize.cols}&rows=${initialSize.rows}`,
		`ResizeObserver`,
		`<section id="logs" class="detail-section">`,
		`<div class="settings-list">`,
		`<details class="settings-card log-details">`,
		`<summary>VM logs</summary>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in response: %s", want, body)
		}
	}
	if strings.Contains(body, `convertEol`) {
		t.Fatalf("terminal should not enable convertEol for PTY output, got: %s", body)
	}
	if strings.Contains(body, `<details id="logs" class="detail-section log-details">`) {
		t.Fatalf("logs should use the settings-card expansion layout, got: %s", body)
	}
}

func TestAPIVMExecRejectsStoppedVMWithStructuredError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestVM(t, a, model.VM{ID: "vm-exec-api", Name: "execapi", State: model.VMStopped})

	req := httptest.NewRequest(http.MethodPost, "/api/vms/vm-exec-api/exec", bytes.NewBufferString(`{"command":"id"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "unprocessable" || got.Error.Fields["state"] != string(model.VMStopped) {
		t.Fatalf("unexpected error body: %#v", got)
	}
}

func TestAPIVMExecJobRejectsStoppedVMWithStructuredError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	createTestVM(t, a, model.VM{ID: "vm-exec-job-api", Name: "execjobapi", State: model.VMStopped})

	req := httptest.NewRequest(http.MethodPost, "/api/vms/vm-exec-job-api/exec-jobs", bytes.NewBufferString(`{"command":"id"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "unprocessable" || got.Error.Fields["state"] != string(model.VMStopped) {
		t.Fatalf("unexpected error body: %#v", got)
	}
}

func TestUIVMCreateMissingSSHMaterialRendersInlineError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()

	form := url.Values{
		"csrf":         {sess.CSRFToken},
		"name":         {"nokey"},
		"vcpu_count":   {"1"},
		"mem_mib":      {"512"},
		"dev_user":     {"dev"},
		"git_ref":      {"HEAD"},
		"egress_mode":  {"allow_all"},
		"network_mode": {"routed_ptp"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/vms", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body, _ := io.ReadAll(rr.Result().Body)
	text := string(body)
	if !strings.Contains(text, "Select an SSH key or paste at least one authorized public key.") {
		t.Fatalf("missing inline error in response: %s", text)
	}
	if !strings.Contains(text, `name="name"`) || !strings.Contains(text, `value="nokey"`) {
		t.Fatalf("form values were not preserved: %s", text)
	}
}

func TestAPINetworkCreateOverlapReturnsStructuredConflict(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	if _, err := a.lifecycle.CreateNetwork(context.Background(), "base", "172.31.90.0/25", ""); err != nil {
		t.Fatal(err)
	}

	body := bytes.NewBufferString(`{"name":"overlap","cidr":"172.31.90.0/24"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/networks", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var got apiErrorBody
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error.Code != "conflict" || got.Error.Fields["cidr"] == "" {
		t.Fatalf("expected cidr conflict, got %#v", got.Error)
	}
}

func TestUINetworkCreateOverlapRendersDashboardError(t *testing.T) {
	a, sess := newAuthenticatedTestApp(t)
	defer a.Close()
	if _, err := a.lifecycle.CreateNetwork(context.Background(), "base", "172.31.91.0/25", ""); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"csrf": {sess.CSRFToken},
		"name": {"overlap"},
		"cidr": {"172.31.91.0/24"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sess.ID})
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	body, _ := io.ReadAll(rr.Result().Body)
	if !strings.Contains(string(body), "overlaps network base 172.31.91.0/25") {
		t.Fatalf("missing overlap error in response: %s", string(body))
	}
}

func getPathBody(t *testing.T, a *App, path, sessionID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: "bap_web_session", Value: sessionID})
	}
	rr := httptest.NewRecorder()

	a.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("%s status = %d, body = %s", path, rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

func assertContains(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Fatalf("missing %q in body: %s", want, body)
	}
}

func assertNotContains(t *testing.T, body, want string) {
	t.Helper()
	if strings.Contains(body, want) {
		t.Fatalf("unexpected %q in body: %s", want, body)
	}
}

func newTestApp(t *testing.T) (*App, *config.Config) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.MkdirTemp(wd, ".test-app-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tmp)
	})
	cfg := config.Defaults()
	cfg.Server.Port = freePort(t)
	cfg.Server.MetadataBindAddress = "127.0.0.1"
	cfg.Server.MetadataPort = freePort(t)
	cfg.Server.StaticDir = filepath.Join(tmp, "static")
	cfg.Database.DSN = filepath.Join(tmp, "bap-web.db")
	cfg.Paths.StateDir = filepath.Join(tmp, "state")
	cfg.Paths.LogDir = filepath.Join(tmp, "logs")
	cfg.Paths.KeyDir = filepath.Join(tmp, "keys")
	cfg.Paths.RuntimeDir = filepath.Join(tmp, "runtime")
	cfg.Paths.ImageDir = filepath.Join(tmp, "images")
	cfg.Paths.BaseImageDir = filepath.Join(tmp, "base-images")
	cfg.Paths.KernelDir = filepath.Join(tmp, "kernels")
	cfg.Paths.KernelImage = filepath.Join(cfg.Paths.KernelDir, "vmlinux-5.10.bin")
	cfg.Paths.BaseRootFS = filepath.Join(cfg.Paths.BaseImageDir, "base-rootfs.ext4")
	cfg.Paths.JailerBaseDir = filepath.Join(tmp, "jailer")
	cfg.Paths.FirecrackerBin = filepath.Join(tmp, "firecracker")
	cfg.Paths.JailerBin = filepath.Join(tmp, "jailer-bin")
	cfg.Images.BuildDir = filepath.Join(tmp, "image-builds")
	cfg.Images.HookDir = filepath.Join(tmp, "image-hooks")
	writeTestFile(t, cfg.Paths.KernelImage, 0o644)
	writeSparseTestFile(t, cfg.Paths.BaseRootFS, 2*1024*1024, 0o644)
	writeTestFile(t, cfg.Paths.FirecrackerBin, 0o755)
	writeTestFile(t, cfg.Paths.JailerBin, 0o755)

	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a, cfg
}

func newAuthenticatedTestApp(t *testing.T) (*App, model.Session) {
	t.Helper()
	return newAuthenticatedTestAppWithRole(t, true)
}

func newAuthenticatedTestAppWithRole(t *testing.T, isAdmin bool) (*App, model.Session) {
	t.Helper()
	a, _ := newTestApp(t)
	now := time.Now().UTC()
	username := "user"
	if isAdmin {
		username = "admin"
	}
	u := model.User{ID: "u1", Username: username, PasswordHash: []byte("hash"), IsAdmin: isAdmin, CreatedAt: now}
	if err := a.store.CreateUser(context.Background(), u); err != nil {
		a.Close()
		t.Fatal(err)
	}
	sess := model.Session{
		ID:         "sess1",
		UserID:     u.ID,
		CSRFToken:  "csrf1",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := a.store.CreateSession(context.Background(), sess); err != nil {
		a.Close()
		t.Fatal(err)
	}
	return a, sess
}

func addTestUser(t *testing.T, a *App, id, username string, isAdmin bool) model.User {
	t.Helper()
	u := model.User{ID: id, Username: username, PasswordHash: []byte("hash"), IsAdmin: isAdmin, CreatedAt: time.Now().UTC()}
	if err := a.store.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func addTestSession(t *testing.T, a *App, id string, u model.User) model.Session {
	t.Helper()
	now := time.Now().UTC()
	sess := model.Session{
		ID:         id,
		UserID:     u.ID,
		CSRFToken:  id + "-csrf",
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := a.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func createTestVM(t *testing.T, a *App, vm model.VM) {
	t.Helper()
	now := time.Now().UTC()
	if vm.ID == "" {
		t.Fatal("test vm id is required")
	}
	if vm.Name == "" {
		vm.Name = vm.ID
	}
	if vm.State == "" {
		vm.State = model.VMStopped
	}
	if vm.VCPUCount == 0 {
		vm.VCPUCount = 1
	}
	if vm.MemMiB == 0 {
		vm.MemMiB = 512
	}
	n := 10
	for i, r := range vm.ID {
		n += (i + 1) * int(r)
	}
	n = 10 + (n % 200)
	if vm.SSHPort == 0 {
		vm.SSHPort = 20000 + n
	}
	if vm.TapName == "" {
		vm.TapName = "tap" + strings.ReplaceAll(vm.ID, "-", "")
	}
	if vm.HostIP == "" {
		vm.HostIP = "172.31.250." + strconv.Itoa(n)
	}
	if vm.GuestIP == "" {
		vm.GuestIP = "172.31.251." + strconv.Itoa(n)
	}
	if vm.CIDR == 0 {
		vm.CIDR = 30
	}
	if vm.KernelPath == "" {
		vm.KernelPath = filepath.Join(a.cfg.Paths.KernelDir, vm.ID+"-kernel")
	}
	if vm.RootFSPath == "" {
		vm.RootFSPath = filepath.Join(a.cfg.Paths.ImageDir, vm.ID+".ext4")
	}
	if vm.BaseRootFSPath == "" {
		vm.BaseRootFSPath = a.cfg.Paths.BaseRootFS
	}
	if vm.DevUser == "" {
		vm.DevUser = "dev"
	}
	if vm.GitRef == "" {
		vm.GitRef = "HEAD"
	}
	if vm.NetworkMode == "" {
		vm.NetworkMode = "routed_ptp"
	}
	if vm.EgressMode == "" {
		vm.EgressMode = "allow_all"
	}
	if vm.CreatedAt.IsZero() {
		vm.CreatedAt = now
	}
	if vm.UpdatedAt.IsZero() {
		vm.UpdatedAt = now
	}
	if err := a.store.CreateVM(context.Background(), vm); err != nil {
		t.Fatal(err)
	}
}

func createTestImageBuildJob(t *testing.T, a *App, job model.ImageBuildJob) {
	t.Helper()
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if job.ID == "" {
		t.Fatal("test image build job id is required")
	}
	if err := a.store.CreateImageBuildJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
}

func createTestKernelTestJob(t *testing.T, a *App, job model.KernelTestJob) {
	t.Helper()
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if job.ID == "" {
		t.Fatal("test kernel test job id is required")
	}
	if err := a.store.CreateKernelTestJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
}

func createTestKernelDiscoveryJob(t *testing.T, a *App, job model.KernelDiscoveryJob) {
	t.Helper()
	now := time.Now().UTC()
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	if job.ID == "" {
		t.Fatal("test kernel discovery job id is required")
	}
	if err := a.store.CreateKernelDiscoveryJob(context.Background(), job); err != nil {
		t.Fatal(err)
	}
}

func createTestKernelDiscoveryItems(t *testing.T, a *App, jobID string, items []model.KernelDiscoveryItem) {
	t.Helper()
	now := time.Now().UTC()
	for i := range items {
		if items[i].JobID == "" {
			items[i].JobID = jobID
		}
		if items[i].CreatedAt.IsZero() {
			items[i].CreatedAt = now
		}
	}
	if err := a.store.ReplaceKernelDiscoveryItems(context.Background(), jobID, items); err != nil {
		t.Fatal(err)
	}
}

func waitForAppDiscoveryJob(t *testing.T, a *App, id string) model.KernelDiscoveryJob {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err := a.store.GetKernelDiscoveryJob(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if job != nil && job.Status != "queued" && job.Status != "running" {
			return *job
		}
		time.Sleep(10 * time.Millisecond)
	}
	job, _ := a.store.GetKernelDiscoveryJob(context.Background(), id)
	t.Fatalf("kernel discovery job did not finish: %#v", job)
	return model.KernelDiscoveryJob{}
}

func writeTestFile(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	writeTestFileWithContent(t, path, "test", mode)
}

func writeTestFileWithContent(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func writeSparseTestFile(t *testing.T, path string, size int64, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
