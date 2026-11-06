package quotahistory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestWindowsFromSignalsClaude(t *testing.T) {
	signals := map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization":      "0.125",
		"Anthropic-Ratelimit-Unified-5h-Reset":            "1787588999",
		"Anthropic-Ratelimit-Unified-7d-Utilization":      "0.53",
		"Anthropic-Ratelimit-Unified-7d-Reset":            "1787900000",
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization":   "1",
		"Anthropic-Ratelimit-Unified-7d_oi-Status":        "allowed",
		"Anthropic-Ratelimit-Unified-Status":              "allowed",
		"Anthropic-Ratelimit-Unified-Overage-Status":      "rejected",
		"Anthropic-Ratelimit-Unified-7d_Bad!-Utilization": "0.2",
	}
	got := WindowsFromSignals("claude", signals, time.Unix(1787580000, 0))
	want := map[string]Window{
		"five_hour":    {Used: 12.5, ResetAt: 1787588999000},
		"seven_day":    {Used: 53, ResetAt: 1787900000000},
		"seven_day_oi": {Used: 100},
	}
	assertWindows(t, got, want)
}

func TestWindowsFromSignalsCodex(t *testing.T) {
	observed := time.UnixMilli(1787580000000)
	signals := map[string]string{
		"X-Codex-Primary-Used-Percent":           "51",
		"X-Codex-Primary-Window-Minutes":         "300",
		"X-Codex-Primary-Reset-After-Seconds":    "60",
		"X-Codex-Secondary-Used-Percent":         "7.5",
		"X-Codex-Secondary-Window-Minutes":       "10080",
		"X-Codex-Secondary-Reset-At":             "1787588999",
		"X-Codex-Bengalfox-Primary-Used-Percent": "99",
		"X-Codex-Plan-Type":                      "pro",
	}
	got := WindowsFromSignals("codex", signals, observed)
	want := map[string]Window{
		"primary":   {Used: 51, WindowMinutes: 300, ResetAt: 1787580060000},
		"secondary": {Used: 7.5, WindowMinutes: 10080, ResetAt: 1787588999000},
	}
	assertWindows(t, got, want)

	if w := WindowsFromSignals("gemini", signals, observed); w != nil {
		t.Fatalf("unsupported provider returned %v", w)
	}
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func newTestRecorder(t *testing.T, auths *[]*coreauth.Auth) (*Recorder, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.UnixMilli(1_790_000_000_000)}
	r := New(filepath.Join(t.TempDir(), "logs", FileName), func() []*coreauth.Auth { return *auths })
	r.now = clock.Now
	return r, clock
}

func claudeAuth(id string, observed time.Time, util string) *coreauth.Auth {
	return &coreauth.Auth{
		ID:       id,
		FileName: id + ".json",
		Provider: "claude",
		Quota: coreauth.QuotaState{
			ObservedAt: observed,
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Utilization": util,
				"Anthropic-Ratelimit-Unified-7d-Reset":       "1790500000",
			},
		},
	}
}

func TestSamplePassiveDedupe(t *testing.T) {
	var auths []*coreauth.Auth
	r, clock := newTestRecorder(t, &auths)
	base := clock.now

	disabled := claudeAuth("off", base, "0.9")
	disabled.Disabled = true
	noSignals := &coreauth.Auth{ID: "bare", Provider: "claude", Quota: coreauth.QuotaState{ObservedAt: base}}
	gemini := &coreauth.Auth{ID: "g", Provider: "gemini", Quota: coreauth.QuotaState{ObservedAt: base, Signals: map[string]string{"X": "1"}}}
	auths = []*coreauth.Auth{claudeAuth("a", base, "0.10"), disabled, noSignals, gemini}

	if n := r.SamplePassive(); n != 1 {
		t.Fatalf("first sample wrote %d, want 1", n)
	}
	// Same observation: nothing new.
	if n := r.SamplePassive(); n != 0 {
		t.Fatalf("unchanged observation wrote %d, want 0", n)
	}
	// Observation advanced, usage unchanged, under 15 min: skip.
	auths[0] = claudeAuth("a", base.Add(5*time.Minute), "0.10")
	if n := r.SamplePassive(); n != 0 {
		t.Fatalf("unchanged usage within heartbeat wrote %d, want 0", n)
	}
	// Usage changed: record.
	auths[0] = claudeAuth("a", base.Add(6*time.Minute), "0.12")
	if n := r.SamplePassive(); n != 1 {
		t.Fatalf("changed usage wrote %d, want 1", n)
	}
	// Unchanged usage but >= 15 min since last sample: heartbeat.
	auths[0] = claudeAuth("a", base.Add(21*time.Minute), "0.12")
	if n := r.SamplePassive(); n != 1 {
		t.Fatalf("heartbeat wrote %d, want 1", n)
	}

	samples, err := r.Query(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 {
		t.Fatalf("got %d samples, want 3", len(samples))
	}
	s := samples[1]
	if s.T != base.Add(6*time.Minute).UnixMilli() || s.Source != SourcePassive || s.Provider != "claude" || s.Windows["seven_day"].Used != 12 {
		t.Fatalf("unexpected sample %+v", s)
	}

	// A new recorder over the same file restores dedupe state.
	r2 := New(r.path, func() []*coreauth.Auth { return auths })
	r2.now = clock.Now
	if n := r2.SamplePassive(); n != 0 {
		t.Fatalf("restarted recorder re-recorded %d samples", n)
	}
}

func TestRecordActiveAndQueryOrder(t *testing.T) {
	var auths []*coreauth.Auth
	r, clock := newTestRecorder(t, &auths)
	if _, err := r.RecordActive("idx1", "codex", map[string]Window{"secondary": {Used: 40, WindowMinutes: 10080}}); err != nil {
		t.Fatal(err)
	}
	// Passive sample observed earlier than the active one is appended later.
	auths = []*coreauth.Auth{claudeAuth("a", clock.now.Add(-time.Hour), "0.5")}
	r.SamplePassive()

	samples, err := r.Query(clock.now.Add(-2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 || samples[0].Source != SourcePassive || samples[1].Source != SourceActive {
		t.Fatalf("unexpected order %+v", samples)
	}
	samples, _ = r.Query(clock.now.Add(-30 * time.Minute))
	if len(samples) != 1 || samples[0].AuthIndex != "idx1" {
		t.Fatalf("window filter failed: %+v", samples)
	}
}

func TestCompactionRetentionAndCap(t *testing.T) {
	var auths []*coreauth.Auth
	r, clock := newTestRecorder(t, &auths)
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		t.Fatal(err)
	}
	old := Sample{T: clock.now.Add(-22 * 24 * time.Hour).UnixMilli(), AuthIndex: "x", Provider: "claude", Source: SourcePassive, Windows: map[string]Window{"seven_day": {Used: 1}}}
	recent := Sample{T: clock.now.Add(-time.Hour).UnixMilli(), AuthIndex: "x", Provider: "claude", Source: SourcePassive, Windows: map[string]Window{"seven_day": {Used: 2}}}
	var b strings.Builder
	for _, s := range []Sample{recent, old} {
		line, _ := json.Marshal(s)
		b.Write(line)
		b.WriteByte('\n')
	}
	b.WriteString("not json\n")
	b.WriteString(strings.Repeat("x", maxLineBytes+10) + "\n")
	b.WriteString(`{"t":5}` + "\n")
	if err := os.WriteFile(r.path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	r.SamplePassive() // first use compacts
	data, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"used":2`) {
		t.Fatalf("compacted file = %q", data)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(r.path), ".quota-history-*"))
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}

	// Size cap drops oldest samples first.
	r.maxBytes = 2000
	for i := 0; i < 40; i++ {
		clock.now = clock.now.Add(time.Minute)
		if _, err := r.RecordActive("y", "claude", map[string]Window{"seven_day": {Used: float64(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > r.maxBytes {
		t.Fatalf("file size %d exceeds cap %d", info.Size(), r.maxBytes)
	}
	samples, _ := r.Query(time.Time{})
	if len(samples) == 0 || samples[len(samples)-1].Windows["seven_day"].Used != 39 {
		t.Fatalf("newest sample missing after cap: %+v", samples)
	}
}

func TestCompactionNoFileCreatesNothing(t *testing.T) {
	var auths []*coreauth.Auth
	r, _ := newTestRecorder(t, &auths)
	r.SamplePassive()
	if _, err := os.Stat(filepath.Dir(r.path)); !os.IsNotExist(err) {
		t.Fatalf("expected no logs dir to be created, stat err = %v", err)
	}
}

func TestResolvePath(t *testing.T) {
	t.Setenv(PathEnv, "")
	if got := ResolvePath("/CLIProxyAPI/logs"); got != "/CLIProxyAPI/logs/quota-history.jsonl" {
		t.Fatalf("default path = %q", got)
	}
	t.Setenv(PathEnv, "/data/qh.jsonl")
	if got := ResolvePath("/CLIProxyAPI/logs"); got != "/data/qh.jsonl" {
		t.Fatalf("env path = %q", got)
	}
}

func assertWindows(t *testing.T, got, want map[string]Window) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("windows = %+v, want %+v", got, want)
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("window %s = %+v, want %+v", id, got[id], w)
		}
	}
}
