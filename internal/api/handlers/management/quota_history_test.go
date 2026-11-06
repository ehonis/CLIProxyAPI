package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/quotahistory"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func newQuotaHistoryHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{ID: "qh-claude", FileName: "qh-claude.json", Provider: "claude"}
	index := auth.EnsureIndex()
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	recorder := quotahistory.New(filepath.Join(t.TempDir(), quotahistory.FileName), manager.List)
	h.SetQuotaHistory(recorder)
	return h, index
}

func callQuotaHistory(h *Handler, method, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	if method == http.MethodGet {
		h.GetQuotaHistory(ctx)
	} else {
		h.PostQuotaHistory(ctx)
	}
	return rec
}

func TestPostQuotaHistoryValidation(t *testing.T) {
	h, index := newQuotaHistoryHandler(t)
	cases := []struct {
		name string
		body string
		want int
	}{
		{"junk", `not json`, http.StatusBadRequest},
		{"missing index", `{"provider":"claude","windows":{"seven_day":{"used":1}}}`, http.StatusBadRequest},
		{"bad provider", `{"auth_index":"` + index + `","provider":"gemini","windows":{"seven_day":{"used":1}}}`, http.StatusBadRequest},
		{"no windows", `{"auth_index":"` + index + `","provider":"claude","windows":{}}`, http.StatusBadRequest},
		{"bad window id", `{"auth_index":"` + index + `","provider":"claude","windows":{"Seven Day":{"used":1}}}`, http.StatusBadRequest},
		{"negative used", `{"auth_index":"` + index + `","provider":"claude","windows":{"seven_day":{"used":-1}}}`, http.StatusBadRequest},
		{"provider mismatch", `{"auth_index":"` + index + `","provider":"codex","windows":{"primary":{"used":1}}}`, http.StatusBadRequest},
		{"unknown auth", `{"auth_index":"nope","provider":"claude","windows":{"seven_day":{"used":1}}}`, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := callQuotaHistory(h, http.MethodPost, "/v8/management/quota/history", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestQuotaHistoryPostThenGet(t *testing.T) {
	h, index := newQuotaHistoryHandler(t)
	body := `{"auth_index":"` + index + `","provider":"claude","windows":{"seven_day":{"used":42.5,"reset_at":1790500000}}}`
	rec := callQuotaHistory(h, http.MethodPost, "/v8/management/quota/history", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("post status = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = callQuotaHistory(h, http.MethodGet, "/v8/management/quota/history?hours=1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Now     int64                 `json:"now"`
		Samples []quotahistory.Sample `json:"samples"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Samples) != 1 {
		t.Fatalf("samples = %+v", payload.Samples)
	}
	s := payload.Samples[0]
	if s.AuthIndex != index || s.Provider != "claude" || s.Source != "active" ||
		s.Windows["seven_day"].Used != 42.5 || s.Windows["seven_day"].ResetAt != 1790500000000 {
		t.Fatalf("unexpected sample %+v", s)
	}
	if payload.Now < s.T || payload.Now-s.T > time.Minute.Milliseconds() {
		t.Fatalf("now %d vs t %d", payload.Now, s.T)
	}

	for _, q := range []string{"hours=abc", "hours=0", "hours=-3"} {
		if rec := callQuotaHistory(h, http.MethodGet, "/v8/management/quota/history?"+q, ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d", q, rec.Code)
		}
	}
	if rec := callQuotaHistory(h, http.MethodGet, "/v8/management/quota/history?hours=9999", ""); rec.Code != http.StatusOK {
		t.Fatalf("clamped hours status = %d", rec.Code)
	}
}

func TestGetQuotaHistoryEmptyAndUnavailable(t *testing.T) {
	h, _ := newQuotaHistoryHandler(t)
	rec := callQuotaHistory(h, http.MethodGet, "/v8/management/quota/history", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"samples":[]`) {
		t.Fatalf("empty history = %d %s", rec.Code, rec.Body.String())
	}
	h.SetQuotaHistory(nil)
	if rec := callQuotaHistory(h, http.MethodGet, "/v8/management/quota/history", ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil recorder status = %d", rec.Code)
	}
}
