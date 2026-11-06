package management

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/quotahistory"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	defaultQuotaHistoryHours = 336
	maxQuotaHistoryHours     = 504
	maxQuotaHistoryWindows   = 16
	maxQuotaHistoryUsed      = 1000
)

// SetQuotaHistory attaches the quota history recorder.
func (h *Handler) SetQuotaHistory(recorder *quotahistory.Recorder) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.quotaHistory = recorder
	h.mu.Unlock()
}

// CurrentAuthManager returns the auth manager currently used by the handler.
func (h *Handler) CurrentAuthManager() *coreauth.Manager {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.authManager
}

func (h *Handler) quotaHistoryRecorder() *quotahistory.Recorder {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.quotaHistory
}

// GetQuotaHistory returns recorded quota samples from the last `hours` hours
// (default 336, max 504), sorted by t ascending.
func (h *Handler) GetQuotaHistory(c *gin.Context) {
	recorder := h.quotaHistoryRecorder()
	if recorder == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota history unavailable"})
		return
	}
	hours := defaultQuotaHistoryHours
	if raw := strings.TrimSpace(c.Query("hours")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "hours must be a positive integer"})
			return
		}
		hours = min(parsed, maxQuotaHistoryHours)
	}
	now := recorder.Now()
	samples, err := recorder.Query(now.Add(-time.Duration(hours) * time.Hour))
	if err != nil {
		log.WithError(err).Warn("quota history: query failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read quota history"})
		return
	}
	if samples == nil {
		samples = []quotahistory.Sample{}
	}
	c.JSON(http.StatusOK, gin.H{"now": now.UnixMilli(), "samples": samples})
}

// PostQuotaHistory records an active sample after the dashboard fetched a
// credential's usage directly from the provider.
func (h *Handler) PostQuotaHistory(c *gin.Context) {
	recorder := h.quotaHistoryRecorder()
	if recorder == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "quota history unavailable"})
		return
	}
	var req struct {
		AuthIndex string                         `json:"auth_index"`
		Provider  string                         `json:"provider"`
		Windows   map[string]quotahistory.Window `json:"windows"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	authIndex := strings.TrimSpace(req.AuthIndex)
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if authIndex == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_index is required"})
		return
	}
	if provider != quotahistory.ProviderClaude && provider != quotahistory.ProviderCodex {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider must be claude or codex"})
		return
	}
	if len(req.Windows) == 0 || len(req.Windows) > maxQuotaHistoryWindows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "windows must contain 1-16 entries"})
		return
	}
	windows := make(map[string]quotahistory.Window, len(req.Windows))
	for id, w := range req.Windows {
		if !quotahistory.ValidWindowID(id) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid window id: " + id})
			return
		}
		if math.IsNaN(w.Used) || w.Used < 0 || w.Used > maxQuotaHistoryUsed || w.ResetAt < 0 || w.WindowMinutes < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid values for window " + id})
			return
		}
		if w.ResetAt > 0 && w.ResetAt < 1e12 {
			w.ResetAt *= 1000 // accept unix seconds
		}
		if provider != quotahistory.ProviderCodex {
			w.WindowMinutes = 0
		}
		windows[id] = w
	}
	auth := h.authByIndex(authIndex)
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), provider) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider does not match auth"})
		return
	}
	sample, err := recorder.RecordActive(authIndex, provider, windows)
	if err != nil {
		log.WithError(err).Warn("quota history: record failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record sample"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "sample": sample})
}
