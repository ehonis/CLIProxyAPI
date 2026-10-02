package auth

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SoonestResetSelector burns the credential whose weekly quota window resets
// soonest. Quota that is about to reset is quota that will otherwise be lost,
// so it is spent before quota with days left on its clock.
//
// The reset instant comes from the passive quota signals captured from
// upstream response headers (anthropic-ratelimit-unified-* for Claude,
// x-codex-* for Codex). Credentials without an observation sort after every
// credential with a known reset; ties fall back to ID order, which makes the
// strategy behave like fill-first until signals are available.
//
// Availability (cooldowns, disabled, quota-exceeded) and priority tiers are
// resolved exactly like the built-in strategies before ordering is applied.
// Combine with routing.session-affinity so an established conversation keeps
// its credential (and its prompt cache) rather than jumping on every request.
type SoonestResetSelector struct{}

// weeklyWindow is the window length that marks a "weekly" Codex limit.
const weeklyWindow = 7 * 24 * time.Hour

// Pick implements Selector.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return orderBySoonestReset(available, now)[0], nil
}

// orderBySoonestReset returns a copy of candidates ordered by weekly reset
// instant ascending; unknown resets sort last, ties by ID.
func orderBySoonestReset(candidates []*Auth, now time.Time) []*Auth {
	ordered := make([]*Auth, len(candidates))
	copy(ordered, candidates)
	resets := make(map[*Auth]time.Time, len(ordered))
	for _, candidate := range ordered {
		if reset, ok := weeklyResetAt(candidate, now); ok {
			resets[candidate] = reset
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, iok := resets[ordered[i]]
		rj, jok := resets[ordered[j]]
		switch {
		case iok && jok && !ri.Equal(rj):
			return ri.Before(rj)
		case iok != jok:
			return iok
		default:
			return ordered[i].ID < ordered[j].ID
		}
	})
	return ordered
}

// weeklyResetAt returns the next weekly reset instant observed for auth.
//
// A reset that already passed means the window rolled over since the last
// observation; the account now has a fresh week, so the next reset is
// projected one week later rather than treated as "soonest".
func weeklyResetAt(auth *Auth, now time.Time) (time.Time, bool) {
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return time.Time{}, false
	}
	signals := lowerSignals(auth.Quota.Signals)
	var reset time.Time
	var ok bool
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		reset, ok = claudeWeeklyReset(signals)
	case "codex":
		reset, ok = codexWeeklyReset(signals, auth.Quota.ObservedAt)
	}
	if !ok {
		return time.Time{}, false
	}
	for !reset.After(now) {
		reset = reset.Add(weeklyWindow)
	}
	return reset, true
}

func lowerSignals(signals map[string]string) map[string]string {
	out := make(map[string]string, len(signals))
	for key, value := range signals {
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return out
}

// claudeWeeklyReset takes the earliest of every 7-day unified window reset
// (the all-models window and any model-scoped weekly window).
func claudeWeeklyReset(signals map[string]string) (time.Time, bool) {
	const prefix = "anthropic-ratelimit-unified-"
	var earliest time.Time
	for key, value := range signals {
		if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, "-reset") {
			continue
		}
		window := strings.TrimSuffix(strings.TrimPrefix(key, prefix), "-reset")
		if !strings.HasPrefix(window, "7d") {
			continue
		}
		if at, ok := parseUnixSignal(value); ok && (earliest.IsZero() || at.Before(earliest)) {
			earliest = at
		}
	}
	return earliest, !earliest.IsZero()
}

// codexWeeklyReset prefers the secondary (weekly) window; the primary window
// counts only when it is itself weekly-length (some plans have one window).
func codexWeeklyReset(signals map[string]string, observedAt time.Time) (time.Time, bool) {
	for _, window := range []string{"secondary", "primary"} {
		if window == "primary" {
			minutes, err := strconv.ParseFloat(signals["x-codex-primary-window-minutes"], 64)
			if err != nil || time.Duration(minutes)*time.Minute < weeklyWindow {
				continue
			}
		}
		if at, ok := parseUnixSignal(signals["x-codex-"+window+"-reset-at"]); ok {
			return at, true
		}
		if secs, err := strconv.ParseFloat(signals["x-codex-"+window+"-reset-after-seconds"], 64); err == nil && !observedAt.IsZero() {
			return observedAt.Add(time.Duration(secs * float64(time.Second))), true
		}
	}
	return time.Time{}, false
}

// parseUnixSignal accepts unix seconds (or milliseconds) and RFC 3339.
func parseUnixSignal(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseFloat(value, 64); err == nil && n > 0 {
		if n > 1e12 {
			return time.UnixMilli(int64(n)), true
		}
		return time.Unix(int64(n), 0), true
	}
	if at, err := time.Parse(time.RFC3339, value); err == nil {
		return at, true
	}
	return time.Time{}, false
}
