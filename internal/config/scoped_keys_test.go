package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopedKeysLoadAndSurviveSecretHashing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "management:\n  secret-key: test-secret\n  scoped-keys:\n    - name: totem\n      key-sha256: \"" + strings.Repeat("ab", 32) + "\"\n      routes: [\"GET /v8/management/credentials\"]\n      api-call-urls: [\"https://api.anthropic.com/api/oauth/usage\"]\n"
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	keys := cfg.RemoteManagement.ScopedKeys
	if len(keys) != 1 || keys[0].Name != "totem" || len(keys[0].Routes) != 1 || len(keys[0].APICallURLs) != 1 {
		t.Fatalf("scoped keys not loaded: %+v", keys)
	}
	// Loading rewrites the file to hash the secret; the scoped keys must stay.
	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "test-secret") || !strings.Contains(string(saved), "scoped-keys") || !strings.Contains(string(saved), strings.Repeat("ab", 32)) {
		t.Fatalf("file after load:\n%s", saved)
	}
	again, err := LoadConfig(path)
	if err != nil || len(again.RemoteManagement.ScopedKeys) != 1 {
		t.Fatalf("reload: %v %+v", err, again)
	}
}
