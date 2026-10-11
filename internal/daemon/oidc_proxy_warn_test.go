package daemon

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/auth"
)

// TestWarnOIDCBehindProxy (re-review 2, M4): the startup warning fires for an
// OIDC realm on a loopback UI with no trusted_proxies, and not when a proxy is
// listed, the UI is not on loopback, or no OIDC realm is configured.
func TestWarnOIDCBehindProxy(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	oidc := []auth.RealmConfig{{Name: "kanidm", Kind: "oidc"}}
	ldap := []auth.RealmConfig{{Name: "corp", Kind: "ldap"}}
	for name, tc := range map[string]struct {
		bind    string
		proxies []string
		realms  []auth.RealmConfig
		warn    bool
	}{
		"loopback, oidc, no proxies": {"127.0.0.1", nil, oidc, true},
		"localhost, oidc":            {"localhost", nil, oidc, true},
		"a proxy listed":             {"127.0.0.1", []string{"127.0.0.1"}, oidc, false},
		"not loopback":               {"0.0.0.0", nil, oidc, false},
		"no oidc realm":              {"127.0.0.1", nil, ldap, false},
	} {
		logs.Reset()
		cfg := &Config{UIBind: tc.bind, TrustedProxies: tc.proxies}
		cfg.Auth.Realms = tc.realms
		warnOIDCBehindProxy(cfg)
		if got := strings.Contains(logs.String(), "trusted_proxies is empty"); got != tc.warn {
			t.Errorf("%s: warned=%v, want %v", name, got, tc.warn)
		}
	}
}
