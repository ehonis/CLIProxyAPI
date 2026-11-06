package api

import (
	"context"
	"path/filepath"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/quotahistory"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// startQuotaHistory attaches the quota history recorder to the management
// handler and starts its passive sampler. The history file lives next to the
// application logs unless QUOTA_HISTORY_PATH overrides it.
func (s *Server) startQuotaHistory(logDir string) {
	if s == nil || s.mgmt == nil {
		return
	}
	path := quotahistory.ResolvePath(logDir)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	mgmt := s.mgmt
	recorder := quotahistory.New(path, func() []*coreauth.Auth {
		if manager := mgmt.CurrentAuthManager(); manager != nil {
			return manager.List()
		}
		return nil
	})
	mgmt.SetQuotaHistory(recorder)
	ctx, cancel := context.WithCancel(context.Background())
	s.quotaHistoryStop = cancel
	go recorder.Run(ctx, quotahistory.DefaultSampleInterval)
	log.Debugf("quota history recording to %s", path)
}
