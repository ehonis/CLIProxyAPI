package quotahistory

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	claudeSignalPrefix = "anthropic-ratelimit-unified-"
	claudeUtilSuffix   = "-utilization"
)

var windowIDPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// ValidWindowID reports whether id is an acceptable window key.
func ValidWindowID(id string) bool { return windowIDPattern.MatchString(id) }

// WindowsFromSignals converts a passive quota snapshot (response headers kept in
// auth.Quota.Signals) into normalized windows. observedAt anchors relative
// reset values such as Codex reset-after-seconds.
func WindowsFromSignals(provider string, signals map[string]string, observedAt time.Time) map[string]Window {
	if len(signals) == 0 {
		return nil
	}
	lower := make(map[string]string, len(signals))
	for key, value := range signals {
		lower[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	var out map[string]Window
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case ProviderClaude:
		out = claudeWindows(lower)
	case ProviderCodex:
		out = codexWindows(lower, observedAt)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// claudeWindows reads anthropic-ratelimit-unified-<window>-utilization (a 0..1
// fraction) and the matching -reset (unix seconds). Window names: 5h, 7d, and
// model-scoped weekly windows such as 7d_oi.
func claudeWindows(signals map[string]string) map[string]Window {
	out := make(map[string]Window)
	for key, value := range signals {
		if !strings.HasPrefix(key, claudeSignalPrefix) || !strings.HasSuffix(key, claudeUtilSuffix) {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(key, claudeSignalPrefix), claudeUtilSuffix)
		id, ok := claudeWindowID(name)
		if !ok {
			continue
		}
		fraction, err := strconv.ParseFloat(value, 64)
		if err != nil || !finite(fraction) || fraction < 0 {
			continue
		}
		window := Window{Used: roundPercent(fraction * 100)}
		if at, ok := parseUnix(signals[claudeSignalPrefix+name+"-reset"]); ok {
			window.ResetAt = at.UnixMilli()
		}
		out[id] = window
	}
	return out
}

func claudeWindowID(name string) (string, bool) {
	switch {
	case name == "5h":
		return "five_hour", true
	case name == "7d":
		return "seven_day", true
	case strings.HasPrefix(name, "7d_"):
		id := "seven_day_" + strings.TrimPrefix(name, "7d_")
		return id, ValidWindowID(id)
	}
	return "", false
}

// codexWindows reads x-codex-{primary,secondary}-{used-percent,window-minutes,
// reset-at,reset-after-seconds}. Additional named limits are ignored.
func codexWindows(signals map[string]string, observedAt time.Time) map[string]Window {
	out := make(map[string]Window)
	for _, id := range []string{"primary", "secondary"} {
		prefix := "x-codex-" + id + "-"
		used, err := strconv.ParseFloat(signals[prefix+"used-percent"], 64)
		if err != nil || !finite(used) || used < 0 {
			continue
		}
		window := Window{Used: roundPercent(used)}
		if minutes, err := strconv.ParseFloat(signals[prefix+"window-minutes"], 64); err == nil && finite(minutes) && minutes > 0 {
			window.WindowMinutes = int64(minutes)
		}
		if at, ok := parseUnix(signals[prefix+"reset-at"]); ok {
			window.ResetAt = at.UnixMilli()
		} else if secs, err := strconv.ParseFloat(signals[prefix+"reset-after-seconds"], 64); err == nil && finite(secs) && secs >= 0 && !observedAt.IsZero() {
			window.ResetAt = observedAt.Add(time.Duration(secs * float64(time.Second))).UnixMilli()
		}
		out[id] = window
	}
	return out
}

// parseUnix accepts unix seconds, unix milliseconds, or RFC 3339.
func parseUnix(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseFloat(value, 64); err == nil {
		if !finite(n) || n <= 0 {
			return time.Time{}, false
		}
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

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

func roundPercent(f float64) float64 { return math.Round(f*100) / 100 }
