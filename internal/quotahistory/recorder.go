// Package quotahistory records per-credential quota windows to an append-only
// JSONL file so the management dashboard can chart remaining quota over time
// without a browser having been open to observe it.
package quotahistory

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	ProviderClaude = "claude"
	ProviderCodex  = "codex"

	SourcePassive = "passive"
	SourceActive  = "active"

	// FileName is the history file name used inside the logs directory.
	FileName = "quota-history.jsonl"
	// PathEnv overrides the history file location.
	PathEnv = "QUOTA_HISTORY_PATH"

	DefaultSampleInterval = 2 * time.Minute
	DefaultRetention      = 21 * 24 * time.Hour
	DefaultMaxFileBytes   = 32 << 20

	unchangedHeartbeat = 15 * time.Minute
	compactEvery       = time.Hour
	maxLineBytes       = 64 << 10
)

// Window is one quota window. Used is a percentage (0-100); ResetAt is unix ms.
type Window struct {
	Used          float64 `json:"used"`
	ResetAt       int64   `json:"reset_at,omitempty"`
	WindowMinutes int64   `json:"window_minutes,omitempty"`
}

// Sample is one line of the history file.
type Sample struct {
	T         int64             `json:"t"`
	AuthIndex string            `json:"auth_index"`
	Provider  string            `json:"provider"`
	Source    string            `json:"source"`
	Windows   map[string]Window `json:"windows"`
}

type lastSample struct {
	t          int64
	windows    map[string]Window
	passiveObs int64
}

// Recorder appends quota samples and serves history queries. All methods are
// safe for concurrent use; errors are logged rather than returned to callers
// on the sampling path.
type Recorder struct {
	path      string
	listAuths func() []*coreauth.Auth
	now       func() time.Time
	retention time.Duration
	maxBytes  int64

	mu          sync.Mutex
	loaded      bool
	last        map[string]*lastSample
	size        int64
	lastCompact time.Time
}

// ResolvePath returns QUOTA_HISTORY_PATH when set, else FileName inside logDir.
func ResolvePath(logDir string) string {
	if p := strings.TrimSpace(os.Getenv(PathEnv)); p != "" {
		return filepath.Clean(p)
	}
	return filepath.Join(logDir, FileName)
}

// New creates a recorder writing to path. listAuths supplies the current auths
// for passive sampling and may be nil.
func New(path string, listAuths func() []*coreauth.Auth) *Recorder {
	return &Recorder{
		path:      path,
		listAuths: listAuths,
		now:       time.Now,
		retention: DefaultRetention,
		maxBytes:  DefaultMaxFileBytes,
		last:      make(map[string]*lastSample),
	}
}

// Path returns the history file path.
func (r *Recorder) Path() string { return r.path }

// Run compacts once, then samples passively every interval until ctx ends.
func (r *Recorder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultSampleInterval
	}
	r.mu.Lock()
	r.compactLocked()
	r.mu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.SamplePassive()
		}
	}
}

// SamplePassive records a sample for each enabled claude/codex auth whose
// quota observation advanced since its last passive sample, when used changed
// or the auth's last sample is at least 15 minutes old. It returns the number
// of samples written.
func (r *Recorder) SamplePassive() int {
	if r == nil || r.listAuths == nil {
		return 0
	}
	auths := r.listAuths()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLoadedLocked()
	var batch []Sample
	for _, auth := range auths {
		if sample, ok := r.passiveCandidateLocked(auth); ok {
			batch = append(batch, sample)
		}
	}
	if len(batch) > 0 {
		if err := r.appendLocked(batch); err != nil {
			log.WithError(err).Warn("quota history: append failed")
			return 0
		}
	}
	if r.now().Sub(r.lastCompact) >= compactEvery {
		r.compactLocked()
	}
	return len(batch)
}

func (r *Recorder) passiveCandidateLocked(auth *coreauth.Auth) (Sample, bool) {
	if auth == nil || auth.Disabled {
		return Sample{}, false
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider != ProviderClaude && provider != ProviderCodex {
		return Sample{}, false
	}
	observed := auth.Quota.ObservedAt
	if observed.IsZero() {
		return Sample{}, false
	}
	index := auth.EnsureIndex()
	if index == "" {
		return Sample{}, false
	}
	windows := WindowsFromSignals(provider, auth.Quota.Signals, observed)
	if len(windows) == 0 {
		return Sample{}, false
	}
	t := observed.UnixMilli()
	if prev := r.last[index]; prev != nil {
		if t <= prev.passiveObs {
			return Sample{}, false
		}
		if sameUsage(prev.windows, windows) && t-prev.t < unchangedHeartbeat.Milliseconds() {
			return Sample{}, false
		}
	}
	return Sample{T: t, AuthIndex: index, Provider: provider, Source: SourcePassive, Windows: windows}, true
}

// RecordActive appends an active sample stamped with the current time.
func (r *Recorder) RecordActive(authIndex, provider string, windows map[string]Window) (Sample, error) {
	sample := Sample{
		T:         r.now().UnixMilli(),
		AuthIndex: authIndex,
		Provider:  provider,
		Source:    SourceActive,
		Windows:   windows,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureLoadedLocked()
	if err := r.appendLocked([]Sample{sample}); err != nil {
		return Sample{}, err
	}
	return sample, nil
}

// Query returns samples with t >= since, sorted by t ascending.
func (r *Recorder) Query(since time.Time) ([]Sample, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	samples, err := r.readLocked()
	if err != nil {
		return nil, err
	}
	cutoff := since.UnixMilli()
	out := samples[:0]
	for _, s := range samples {
		if s.T >= cutoff {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out, nil
}

// Now returns the recorder clock's current time.
func (r *Recorder) Now() time.Time { return r.now() }

func (r *Recorder) ensureLoadedLocked() {
	if r.loaded {
		return
	}
	r.compactLocked()
}

func (r *Recorder) appendLocked(batch []Sample) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, s := range batch {
		if err := enc.Encode(s); err != nil {
			return fmt.Errorf("encode sample: %w", err)
		}
	}
	if r.size+int64(buf.Len()) > r.maxBytes {
		r.compactLocked()
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("create history dir: %w", err)
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}
	n, errWrite := f.Write(buf.Bytes())
	errClose := f.Close()
	r.size += int64(n)
	if errWrite != nil {
		return fmt.Errorf("write history file: %w", errWrite)
	}
	if errClose != nil {
		return fmt.Errorf("close history file: %w", errClose)
	}
	for _, s := range batch {
		r.noteLocked(s)
	}
	return nil
}

func (r *Recorder) noteLocked(s Sample) {
	prev := r.last[s.AuthIndex]
	if prev == nil {
		prev = &lastSample{}
		r.last[s.AuthIndex] = prev
	}
	if s.T >= prev.t {
		prev.t = s.T
		prev.windows = s.Windows
	}
	if s.Source == SourcePassive && s.T > prev.passiveObs {
		prev.passiveObs = s.T
	}
}

// readLocked parses the history file, skipping malformed lines.
func (r *Recorder) readLocked() ([]Sample, error) {
	f, err := os.Open(r.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open history file: %w", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.WithError(errClose).Debug("quota history: close failed")
		}
	}()
	var samples []Sample
	reader := bufio.NewReader(f)
	for {
		line, errRead := reader.ReadBytes('\n')
		line = bytes.TrimSpace(line)
		if len(line) > 0 && len(line) <= maxLineBytes {
			var s Sample
			if json.Unmarshal(line, &s) == nil && s.T > 0 && s.AuthIndex != "" && len(s.Windows) > 0 {
				samples = append(samples, s)
			}
		}
		if errRead != nil {
			if errors.Is(errRead, io.EOF) {
				return samples, nil
			}
			return samples, fmt.Errorf("read history file: %w", errRead)
		}
	}
}

// compactLocked drops expired and malformed lines, trims the oldest samples
// when over the size cap, rewrites the file atomically, and rebuilds the
// per-auth dedupe state from what remains.
func (r *Recorder) compactLocked() {
	now := r.now()
	r.lastCompact = now
	r.loaded = true
	samples, err := r.readLocked()
	if err != nil {
		log.WithError(err).Warn("quota history: read failed during compaction")
		return
	}
	cutoff := now.Add(-r.retention).UnixMilli()
	kept := make([]Sample, 0, len(samples))
	for _, s := range samples {
		if s.T >= cutoff {
			kept = append(kept, s)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].T < kept[j].T })

	lines := make([][]byte, len(kept))
	var total int64
	for i, s := range kept {
		line, errMarshal := json.Marshal(s)
		if errMarshal != nil {
			continue
		}
		lines[i] = append(line, '\n')
		total += int64(len(lines[i]))
	}
	// Leave headroom so a full file does not compact on every append.
	limit := r.maxBytes * 3 / 4
	start := 0
	for total > limit && start < len(lines) {
		total -= int64(len(lines[start]))
		start++
	}
	kept, lines = kept[start:], lines[start:]

	r.last = make(map[string]*lastSample)
	for _, s := range kept {
		r.noteLocked(s)
	}
	if len(samples) == 0 && len(kept) == 0 {
		r.size = 0
		return
	}
	if err := r.rewriteLocked(lines); err != nil {
		log.WithError(err).Warn("quota history: compaction rewrite failed")
		return
	}
	r.size = total
}

func (r *Recorder) rewriteLocked(lines [][]byte) error {
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".quota-history-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	w := bufio.NewWriter(tmp)
	for _, line := range lines {
		if _, err = w.Write(line); err != nil {
			break
		}
	}
	if err == nil {
		err = w.Flush()
	}
	if errClose := tmp.Close(); err == nil {
		err = errClose
	}
	if err == nil {
		err = os.Rename(tmpName, r.path)
	}
	if err != nil {
		_ = os.Remove(tmpName)
	}
	return err
}

func sameUsage(a, b map[string]Window) bool {
	if len(a) != len(b) {
		return false
	}
	for id, wa := range a {
		wb, ok := b[id]
		if !ok || wa.Used != wb.Used {
			return false
		}
	}
	return true
}
