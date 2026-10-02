package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func claudeAuthWithReset(id string, reset time.Time) *Auth {
	a := &Auth{ID: id, Provider: "claude", Status: StatusActive}
	if !reset.IsZero() {
		a.Quota.Signals = map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(reset.Unix(), 10),
			"Anthropic-Ratelimit-Unified-5h-Reset": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
		}
	}
	return a
}

func TestSoonestResetSelectorPicksEarliestWeeklyReset(t *testing.T) {
	now := time.Now()
	auths := []*Auth{
		claudeAuthWithReset("a", now.Add(4*24*time.Hour)),
		claudeAuthWithReset("b", now.Add(20*time.Hour)),
		claudeAuthWithReset("c", time.Time{}),
	}
	got, err := (&SoonestResetSelector{}).Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if got.ID != "b" {
		t.Fatalf("picked %q, want b (resets soonest)", got.ID)
	}
}

func TestSoonestResetSelectorUnknownSortsLast(t *testing.T) {
	now := time.Now()
	ordered := orderBySoonestReset([]*Auth{
		claudeAuthWithReset("a", time.Time{}),
		claudeAuthWithReset("z", now.Add(6*24*time.Hour)),
	}, now)
	if ordered[0].ID != "z" || ordered[1].ID != "a" {
		t.Fatalf("order = %s,%s; want z,a", ordered[0].ID, ordered[1].ID)
	}
}

func TestSoonestResetSelectorProjectsElapsedReset(t *testing.T) {
	now := time.Now()
	ordered := orderBySoonestReset([]*Auth{
		// Reset passed an hour ago: fresh week, next reset ~7d out.
		claudeAuthWithReset("rolled", now.Add(-time.Hour)),
		claudeAuthWithReset("soon", now.Add(2*24*time.Hour)),
	}, now)
	if ordered[0].ID != "soon" {
		t.Fatalf("first = %s; want soon", ordered[0].ID)
	}
}

func TestSoonestResetSelectorCodexSecondaryWindow(t *testing.T) {
	now := time.Now()
	later := &Auth{ID: "a", Provider: "codex", Status: StatusActive}
	later.Quota.Signals = map[string]string{
		"X-Codex-Secondary-Reset-At": strconv.FormatInt(now.Add(5*24*time.Hour).Unix(), 10),
	}
	sooner := &Auth{ID: "b", Provider: "codex", Status: StatusActive}
	sooner.Quota.ObservedAt = now
	sooner.Quota.Signals = map[string]string{
		"X-Codex-Secondary-Reset-After-Seconds": "3600",
	}
	ordered := orderBySoonestReset([]*Auth{later, sooner}, now)
	if ordered[0].ID != "b" {
		t.Fatalf("first = %s; want b", ordered[0].ID)
	}
}

func TestSoonestResetSelectorSkipsUnavailable(t *testing.T) {
	now := time.Now()
	soonest := claudeAuthWithReset("soonest", now.Add(time.Hour))
	soonest.Disabled = true
	auths := []*Auth{soonest, claudeAuthWithReset("next", now.Add(3*24*time.Hour))}
	got, err := (&SoonestResetSelector{}).Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick: %v", err)
	}
	if got.ID != "next" {
		t.Fatalf("picked %q, want next", got.ID)
	}
}
