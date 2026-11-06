package management

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Scoped management keys (management.scoped-keys) let another program manage
// credentials without the root management key. The root key can download every
// credential file and send any credential's token to any URL through api-call; a
// scoped key reaches only the routes it lists, and its api-call may only target
// the URLs it lists. Whatever a scoped key lists, it can never read or change the
// config, download a credential, touch plugins or read logs, so it cannot widen
// its own scope or read a refresh token.
//
// The key is stored as the hex SHA-256 of its value (key-sha256). Keys are meant
// to be long random strings, so a slow hash adds nothing; the value never sits in
// the config.

const scopedKeyContextKey = "managementScopedKey"

const maxScopedAPICallBody = 1 << 20

// Never reachable with a scoped key, whatever its route list says.
var scopedKeyForbiddenPrefixes = []string{
	"/v0/management/config",
	"/v8/management/config",
	"/v0/management/auth-files/download",
	"/v8/management/credentials/download",
	"/v0/management/plugins",
	"/v8/management/plugins",
	"/v0/management/logs",
	"/v8/management/observability",
	"/v0/management/api-keys",
}

// matchScopedKey returns the scoped key whose hash matches provided, or nil.
func matchScopedKey(cfg *config.Config, provided string) *config.ManagementScopedKey {
	if cfg == nil || provided == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(provided))
	given := hex.EncodeToString(sum[:])
	var found *config.ManagementScopedKey
	for i := range cfg.RemoteManagement.ScopedKeys {
		key := &cfg.RemoteManagement.ScopedKeys[i]
		want := strings.ToLower(strings.TrimSpace(key.KeySHA256))
		if len(want) != sha256.Size*2 {
			continue
		}
		// Compare every key so timing does not say which one matched.
		if subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1 && found == nil {
			found = key
		}
	}
	return found
}

func scopedRouteForbidden(path string) bool {
	for _, prefix := range scopedKeyForbiddenPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") || strings.HasPrefix(path, prefix+".") {
			return true
		}
	}
	return false
}

// scopedRouteAllowed matches "METHOD /full/route/pattern" entries against the
// request's method and gin route pattern (c.FullPath()), so path parameters are
// written as in the router, e.g. "GET /v8/management/routing/model-definitions/:channel".
func scopedRouteAllowed(key *config.ManagementScopedKey, method, fullPath string) bool {
	if fullPath == "" || scopedRouteForbidden(fullPath) {
		return false
	}
	for _, entry := range key.Routes {
		parts := strings.Fields(entry)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], method) && parts[1] == fullPath {
			return true
		}
	}
	return false
}

// scopedAPICallURLAllowed matches an upstream URL against the key's patterns.
// Scheme and host must be equal, the path must have the same segments with "*"
// matching exactly one non-empty segment, and the query must be equal (a pattern
// without a query allows none). No user info, fragment, or non-https scheme.
func scopedAPICallURLAllowed(key *config.ManagementScopedKey, raw string) bool {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || target.Scheme != "https" || target.User != nil || target.Fragment != "" || target.Opaque != "" {
		return false
	}
	if target.RawPath != "" && target.RawPath != target.EscapedPath() {
		return false
	}
	for _, pattern := range key.APICallURLs {
		allowed, errParse := url.Parse(strings.TrimSpace(pattern))
		if errParse != nil || allowed.Scheme != "https" {
			continue
		}
		if !strings.EqualFold(allowed.Host, target.Host) {
			continue
		}
		if allowed.RawQuery != target.RawQuery {
			continue
		}
		if pathMatches(allowed.Path, target.Path) {
			return true
		}
	}
	return false
}

func pathMatches(pattern, path string) bool {
	if strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") || strings.Contains(path, "/./") || strings.Contains(path, "//") {
		return false
	}
	want := strings.Split(pattern, "/")
	got := strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] == "*" {
			if got[i] == "" || got[i] == "." || got[i] == ".." {
				return false
			}
			continue
		}
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// checkScopedAPICall reads the api-call body, refuses a URL the key does not
// allow or any proxy override, and puts the body back for the handler. It decodes
// into the handler's own request type, so both read the same url.
func checkScopedAPICall(c *gin.Context, key *config.ManagementScopedKey) (bool, string) {
	if c.Request.Body == nil {
		return false, "scoped key: api-call needs a body"
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, maxScopedAPICallBody+1))
	_ = c.Request.Body.Close()
	if err != nil || len(raw) > maxScopedAPICallBody {
		return false, "scoped key: api-call body too large"
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	var body apiCallRequest
	if errDecode := json.Unmarshal(raw, &body); errDecode != nil {
		return false, "scoped key: api-call body is not JSON"
	}
	if strings.TrimSpace(body.ProxyURL) != "" {
		return false, "scoped key: api-call may not set proxy_url"
	}
	if !scopedAPICallURLAllowed(key, body.URL) {
		return false, "scoped key: api-call URL not allowed"
	}
	return true, ""
}

// Credential fields a scoped key may not set: where a login's traffic goes and
// what is sent with it.
var scopedForbiddenFields = []string{"proxy_url", "proxy-url", "headers", "base_url", "base-url"}

func checkScopedFieldsPatch(c *gin.Context) (bool, string) {
	if c.Request.Body == nil {
		return true, ""
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, maxScopedAPICallBody+1))
	_ = c.Request.Body.Close()
	if err != nil || len(raw) > maxScopedAPICallBody {
		return false, "scoped key: body too large"
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	var body map[string]json.RawMessage
	if errDecode := json.Unmarshal(raw, &body); errDecode != nil {
		return false, "scoped key: body is not a JSON object"
	}
	for name := range body {
		for _, forbidden := range scopedForbiddenFields {
			if strings.EqualFold(name, forbidden) {
				return false, "scoped key: may not set " + forbidden
			}
		}
	}
	return true, ""
}

func (h *Handler) clientBanned(clientIP string) bool {
	h.attemptsMu.Lock()
	defer h.attemptsMu.Unlock()
	ai := h.failedAttempts[clientIP]
	return ai != nil && !ai.blockedUntil.IsZero() && time.Now().Before(ai.blockedUntil)
}

// authorizeScopedKey runs for a request carrying a scoped key. It applies the
// same remote rule as the root key and then the key's own scope.
func (h *Handler) authorizeScopedKey(c *gin.Context, key *config.ManagementScopedKey, localClient bool) bool {
	if h.clientBanned(c.ClientIP()) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "IP banned due to too many failed attempts"})
		return false
	}
	allowRemote := h.allowRemoteOverride || (h.cfg != nil && h.cfg.RemoteManagement.AllowRemote)
	if !localClient && !allowRemote {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "remote management disabled"})
		return false
	}
	fullPath := c.FullPath()
	if !scopedRouteAllowed(key, c.Request.Method, fullPath) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "scoped key: route not allowed"})
		return false
	}
	if strings.HasSuffix(fullPath, "/credentials/fields") || strings.HasSuffix(fullPath, "/auth-files/fields") {
		if ok, msg := checkScopedFieldsPatch(c); !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msg})
			return false
		}
	}
	if strings.HasSuffix(fullPath, "/requests/api-call") || strings.HasSuffix(fullPath, "/api-call") {
		if ok, msg := checkScopedAPICall(c, key); !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": msg})
			return false
		}
	}
	c.Set(scopedKeyContextKey, key.Name)
	return true
}
