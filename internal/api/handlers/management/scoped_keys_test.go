package management

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func scopedTestHandler(t *testing.T, allowRemote bool) (*Handler, string) {
	t.Helper()
	const key = "scoped-test-key-0123456789abcdef"
	sum := sha256.Sum256([]byte(key))
	cfg := &config.Config{}
	cfg.RemoteManagement.AllowRemote = allowRemote
	cfg.RemoteManagement.ScopedKeys = []config.ManagementScopedKey{{
		Name:      "test",
		KeySHA256: hex.EncodeToString(sum[:]),
		Routes: []string{
			"GET /v8/management/credentials",
			"POST /v8/management/requests/api-call",
			"PATCH /v8/management/credentials/fields",
			// Listed, but forbidden for every scoped key.
			"GET /v8/management/credentials/download",
			"GET /v8/management/config",
		},
		APICallURLs: []string{
			"https://api.anthropic.com/api/oauth/usage",
			"https://api.anthropic.com/api/organizations/*/reset_rate_limits",
		},
	}}
	return &Handler{cfg: cfg, failedAttempts: make(map[string]*attemptInfo), envSecret: "root-secret"}, key
}

func scopedEngine(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	group := engine.Group("/v8/management")
	group.Use(h.Middleware())
	echo := func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.String(http.StatusOK, string(body))
	}
	group.GET("/credentials", echo)
	group.DELETE("/credentials", echo)
	group.GET("/credentials/download", echo)
	group.GET("/config", echo)
	group.POST("/requests/api-call", echo)
	group.PATCH("/credentials/fields", echo)
	return engine
}

func scopedDo(engine *gin.Engine, method, path, key, body, remote string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Header.Set("Authorization", "Bearer "+key)
	engine.ServeHTTP(rec, req)
	return rec
}

func TestScopedKeyRoutes(t *testing.T) {
	h, key := scopedTestHandler(t, true)
	engine := scopedEngine(h)
	local := "127.0.0.1:1234"

	if rec := scopedDo(engine, http.MethodGet, "/v8/management/credentials", key, "", local); rec.Code != http.StatusOK {
		t.Fatalf("listed route: %d %s", rec.Code, rec.Body.String())
	}
	if rec := scopedDo(engine, http.MethodDelete, "/v8/management/credentials", key, "", local); rec.Code != http.StatusForbidden {
		t.Fatalf("unlisted route: %d", rec.Code)
	}
	for _, path := range []string{"/v8/management/credentials/download", "/v8/management/config"} {
		if rec := scopedDo(engine, http.MethodGet, path, key, "", local); rec.Code != http.StatusForbidden {
			t.Fatalf("%s must be forbidden for a scoped key even when listed: %d", path, rec.Code)
		}
	}
	// The root key still reaches everything.
	if rec := scopedDo(engine, http.MethodGet, "/v8/management/credentials/download", "root-secret", "", local); rec.Code != http.StatusOK {
		t.Fatalf("root key: %d", rec.Code)
	}
}

func TestScopedKeyAPICallURLs(t *testing.T) {
	h, key := scopedTestHandler(t, true)
	engine := scopedEngine(h)
	local := "127.0.0.1:1234"
	cases := []struct {
		body string
		want int
	}{
		{`{"authIndex":"a","method":"GET","url":"https://api.anthropic.com/api/oauth/usage"}`, http.StatusOK},
		{`{"authIndex":"a","method":"POST","url":"https://api.anthropic.com/api/organizations/0f0e/reset_rate_limits"}`, http.StatusOK},
		{`{"authIndex":"a","url":"https://api.anthropic.com/api/oauth/usage?x=1"}`, http.StatusForbidden},
		{`{"authIndex":"a","url":"https://evil.example.com/api/oauth/usage"}`, http.StatusForbidden},
		{`{"authIndex":"a","url":"http://api.anthropic.com/api/oauth/usage"}`, http.StatusForbidden},
		{`{"authIndex":"a","url":"https://user@api.anthropic.com/api/oauth/usage"}`, http.StatusForbidden},
		{`{"authIndex":"a","url":"https://api.anthropic.com/api/organizations/../oauth/reset_rate_limits"}`, http.StatusForbidden},
		{`{"authIndex":"a","url":"https://api.anthropic.com/api/organizations/x/y/reset_rate_limits"}`, http.StatusForbidden},
		{`{"authIndex":"a","url":"https://api.anthropic.com/api/oauth/usage","proxy_url":"http://evil.example.com:8080"}`, http.StatusForbidden},
		// Duplicate keys: encoding/json keeps the last, for the check and the handler alike.
		{`{"url":"https://api.anthropic.com/api/oauth/usage","url":"https://evil.example.com/"}`, http.StatusForbidden},
		{`not json`, http.StatusForbidden},
	}
	for _, tc := range cases {
		rec := scopedDo(engine, http.MethodPost, "/v8/management/requests/api-call", key, tc.body, local)
		if rec.Code != tc.want {
			t.Errorf("%s → %d, want %d (%s)", tc.body, rec.Code, tc.want, rec.Body.String())
		}
		if tc.want == http.StatusOK && rec.Body.String() != tc.body {
			t.Errorf("the handler must see the same body: %q", rec.Body.String())
		}
	}
}

func TestScopedKeyFieldsAndRemote(t *testing.T) {
	h, key := scopedTestHandler(t, false)
	engine := scopedEngine(h)
	local := "127.0.0.1:1234"
	if rec := scopedDo(engine, http.MethodPatch, "/v8/management/credentials/fields", key, `{"name":"a.json","priority":2}`, local); rec.Code != http.StatusOK {
		t.Fatalf("plain fields: %d", rec.Code)
	}
	if rec := scopedDo(engine, http.MethodPatch, "/v8/management/credentials/fields", key, `{"name":"a.json","Proxy_URL":"socks5://x"}`, local); rec.Code != http.StatusForbidden {
		t.Fatalf("proxy_url must be refused: %d", rec.Code)
	}
	if rec := scopedDo(engine, http.MethodGet, "/v8/management/credentials", key, "", "100.64.0.9:1234"); rec.Code != http.StatusForbidden {
		t.Fatalf("remote with allow-remote off: %d", rec.Code)
	}
	if rec := scopedDo(engine, http.MethodGet, "/v8/management/credentials", "not-a-key", "", local); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", rec.Code)
	}
}
