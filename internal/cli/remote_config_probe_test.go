package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestClassifyRemoteConfig is the "a failed read is not an absence" invariant
// applied to the one preflight that stops `lv host init` destroying a member.
//
// The probe used `cat <path> 2>/dev/null || true`, so an UNREADABLE config and
// an ABSENT one both arrived as empty output. refuseIfAlreadyAMember then saw
// "no config" — exactly the node init is for — and allowed the run, which
// rewrites config.yaml with join_peers: []. The node loses its peer list and
// the signal that stops it minting an admin credential.
func TestClassifyRemoteConfig(t *testing.T) {
	t.Run("sentinel means genuinely absent", func(t *testing.T) {
		got, absent, err := classifyRemoteConfig(noConfigSentinel, nil)
		if err != nil || !absent || got != "" {
			t.Fatalf("classifyRemoteConfig(sentinel) = (%q, %v, %v), want empty/absent/nil", got, absent, err)
		}
	})

	t.Run("contents are returned as-is", func(t *testing.T) {
		cfg := "host_name: node-1\njoin_peers: [10.0.0.2]\n"
		got, absent, err := classifyRemoteConfig(cfg, nil)
		if err != nil || absent || got != cfg {
			t.Fatalf("classifyRemoteConfig(cfg) = (%q, %v, %v), want the config back", got, absent, err)
		}
	})

	t.Run("a failed read REFUSES", func(t *testing.T) {
		_, _, err := classifyRemoteConfig("", errors.New("exit status 1"))
		if err == nil {
			t.Fatal("a failed read was treated as an absent config; that is the conflation " +
				"this guard exists to prevent, and it ends in an overwritten member")
		}
	})

	t.Run("empty output without the sentinel REFUSES", func(t *testing.T) {
		_, _, err := classifyRemoteConfig("", nil)
		if err == nil {
			t.Fatal("empty output with no sentinel means the probe did not run as expected; " +
				"it must not be read as 'there is no config there'")
		}
		if !strings.Contains(err.Error(), "--force") {
			t.Errorf("the refusal should name the escape hatch, got %q", err)
		}
	})
}
