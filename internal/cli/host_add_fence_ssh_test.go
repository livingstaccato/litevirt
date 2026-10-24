package cli

import (
	"strings"
	"testing"
)

// `lv host add` copies the cluster's enforcement block onto the new host
// verbatim. A block that still says enforcement.fence_ssh: legacy, a value
// this binary refuses at start, would give the new host a daemon that does
// not start, so addSetupEnforcement, which HostAdd asks before anything is
// minted or pushed, refuses it, naming where the value was read and the fix.
// Read from this node's own config and from a join peer's, in any case.
//
// Mutation: pass the block on unchecked (refuseRemovedFenceSSH returns it) —
// the add goes ahead, red.
func TestHostAdd_RefusesToCopyALegacyFenceSSH(t *testing.T) {
	t.Run("this node's config", func(t *testing.T) {
		useConfig(t, "advertise_address: 10.0.0.1\nenforcement:\n  audit_signature: true\n  fence_ssh: Legacy\n")
		asked := stubPeerConfig(t, func(string) (string, bool, error) { return "", false, nil })
		block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946"})
		if err == nil || !strings.Contains(err.Error(), "enforcement.fence_ssh: Legacy") ||
			!strings.Contains(err.Error(), "this machine's") ||
			!strings.Contains(err.Error(), "set enforcement.fence_ssh to auto or managed") {
			t.Fatalf("addSetupEnforcement = (%q, %v), want refused naming this machine's config and the fix", block, err)
		}
		if len(*asked) != 0 {
			t.Fatalf("read a peer's config (%v) although this node has its own", *asked)
		}
	})
	t.Run("a join peer's config", func(t *testing.T) {
		useConfig(t, "")
		stubPeerConfig(t, func(string) (string, bool, error) {
			return "host_name: node-1\nenforcement:\n  fence_ssh: legacy\n", true, nil
		})
		block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946"})
		if err == nil || !strings.Contains(err.Error(), "root@10.0.0.1:") ||
			!strings.Contains(err.Error(), "set enforcement.fence_ssh to auto or managed") {
			t.Fatalf("addSetupEnforcement = (%q, %v), want refused naming root@10.0.0.1 and the fix", block, err)
		}
	})
	t.Run("auto is copied", func(t *testing.T) {
		useConfig(t, "")
		stubPeerConfig(t, func(string) (string, bool, error) {
			return "enforcement:\n  fence_ssh: auto\n", true, nil
		})
		if block, err := addSetupEnforcement("root", []string{"10.0.0.1:7946"}); err != nil ||
			block != "enforcement:\n  fence_ssh: auto\n" {
			t.Fatalf("addSetupEnforcement = (%q, %v), want the block copied", block, err)
		}
	})
}
